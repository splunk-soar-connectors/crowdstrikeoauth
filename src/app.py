# Copyright (c) 2019-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import time
from collections.abc import Iterator

from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.logging import getLogger
from soar_sdk.models.artifact import Artifact
from soar_sdk.models.container import Container
from soar_sdk.params import OnPollParams

from . import parse_cs_events as events_parser
from .consts import (
    CROWDSTRIKE_BLANK_LINES_COUNT_MESSAGE,
    CROWDSTRIKE_EVENT_TYPES,
    CROWDSTRIKE_GET_DEVICE_ID_ENDPOINT,
    CROWDSTRIKE_GETTING_EVENTS_MESSAGE,
    CROWDSTRIKE_GOT_EVENTS_MESSAGE,
    CROWDSTRIKE_NO_DATA_MESSAGE,
    CROWDSTRIKE_PULLED_EVENTS_MESSAGE,
    CROWDSTRIKE_REACHED_CR_LF_COUNT_MESSAGE,
    CROWDSTRIKE_RECEIVED_CR_LF_MESSAGE,
    CROWDSTRIKE_REFRESH_TOKEN_ERROR,
    DEFAULT_EVENTS_COUNT,
    DEFAULT_POLLNOW_EVENTS_COUNT,
)
from .helper import (
    CrowdStrikeClient,
    get_subtenants,
    migrate_legacy_ingest_state,
    validate_integer,
)


logger = getLogger()


class Asset(BaseAsset):
    url: str = AssetField(
        description="Base URL",
        default="https://api.crowdstrike.com",
        category=FieldCategory.CONNECTIVITY,
    )
    client_id: str = AssetField(
        description="Client ID",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    client_secret: str = AssetField(
        description="Client Secret",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    subtenants: str | None = AssetField(
        description="Comma-separated list of subtenant CIDs. Example: 123,456,789",
        category=FieldCategory.CONNECTIVITY,
    )
    app_id: str | None = AssetField(
        description="App ID", category=FieldCategory.CONNECTIVITY
    )
    max_events: int | None = AssetField(
        description="Maximum events to get for scheduled and interval polling",
        default=10000,
        category=FieldCategory.INGEST,
    )
    max_events_poll_now: int | None = AssetField(
        description="Maximum events to get while POLL NOW",
        default=2000,
        category=FieldCategory.INGEST,
    )
    collate: bool | None = AssetField(
        description="Merge containers for hostname and eventname",
        default=True,
        category=FieldCategory.INGEST,
    )
    max_crlf: int | None = AssetField(
        description="Maximum allowed continuous blank lines",
        default=50,
        category=FieldCategory.INGEST,
    )
    detonate_timeout: int | None = AssetField(
        description="Timeout for detonation result in minutes (Default: 15 minutes)",
        default=15,
        category=FieldCategory.ACTION,
    )


def get_client(asset: Asset) -> CrowdStrikeClient:
    """Build a CrowdStrike OAuth client for the given asset."""
    return CrowdStrikeClient(asset)


app = App(
    name="CrowdStrike OAuth API",
    app_type="endpoint",
    logo="logo_crowdstrikeoauthapi.svg",
    logo_dark="logo_crowdstrikeoauthapi_dark.svg",
    product_vendor="CrowdStrike",
    product_name="CrowdStrike",
    publisher="Splunk",
    appid="ae971ba5-3117-444a-8ac5-6ce779f3a232",
    fips_compliant=True,
    asset_cls=Asset,
    min_phantom_version="8.6.0",
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    client = get_client(asset)
    logger.progress("Fetching devices")
    client.make_rest_call(CROWDSTRIKE_GET_DEVICE_ID_ENDPOINT, params={"limit": 1})
    soar.set_message("Test connectivity passed")
    logger.info("Test connectivity passed")


@app.on_poll()
def on_poll(
    params: OnPollParams, soar: SOARClient, asset: Asset
) -> Iterator[Container | Artifact]:
    client = get_client(asset)
    is_poll_now = params.is_manual_poll()

    if not is_poll_now:
        migrate_legacy_ingest_state(asset)

    max_crlf = validate_integer(asset.max_crlf, "max_crlf") if asset.max_crlf else None

    if is_poll_now:
        max_events = validate_integer(
            asset.max_events_poll_now or DEFAULT_POLLNOW_EVENTS_COUNT,
            "max_events_poll_now",
        )
    else:
        max_events = validate_integer(
            asset.max_events or DEFAULT_EVENTS_COUNT, "max_events"
        )

    tenants = [None, *get_subtenants(asset)]

    for tenant in tenants:
        yield from _poll_detection_events(
            client, asset, is_poll_now, max_crlf, max_events, subtenant=tenant
        )


def _poll_detection_events(
    client: CrowdStrikeClient,
    asset: Asset,
    is_poll_now: bool,
    max_crlf: int | None,
    max_events: int,
    subtenant: str | None = None,
) -> Iterator[Container | Artifact]:
    offset_key = f"last_offset_id_{subtenant}" if subtenant else "last_offset_id"

    lower_id = 0
    if not is_poll_now:
        try:
            lower_id = int(asset.ingest_state.get(offset_key, 0))
        except (TypeError, ValueError):
            lower_id = 0
    if lower_id < 0:
        lower_id = 0

    logger.progress(
        CROWDSTRIKE_GETTING_EVENTS_MESSAGE.format(
            lower_id=lower_id, max_events=max_events
        )
    )

    tenant = subtenant or "main"
    stage = "feed discovery"
    events: list = []
    skipped_records = 0
    stop_reason = "stream exhausted"
    try:
        logger.info(f"Poll stage={stage}, tenant={tenant}, checkpoint={lower_id}")
        feed = client.get_datafeed(
            asset.app_id or str(app.app_meta_info["appid"]), subtenant=subtenant
        )
        stage = "stream opening"
        logger.info(f"Poll stage={stage}, tenant={tenant}")
        response = client.stream_datafeed(
            feed["data_feed_url"], feed["token"], lower_id
        )
        try:
            if response.status_code != 200:
                raise RuntimeError(
                    f"Error opening CrowdStrike datafeed stream: HTTP {response.status_code}"
                )

            stage = "stream reading"
            logger.info(f"Poll stage={stage}, tenant={tenant}")
            counter = 0
            total_blank_lines_count = 0
            start_time = time.time()
            for stream_data in response.iter_lines(chunk_size=None):
                if int(time.time() - start_time) > (feed["refresh_interval"] - 60):
                    try:
                        client.refresh_datafeed_session(feed["refresh_url"], subtenant)
                        start_time = time.time()
                    except Exception:
                        if not events:
                            raise
                        stop_reason = "session refresh failed"
                        logger.warning(
                            f"{CROWDSTRIKE_REFRESH_TOKEN_ERROR}; tenant={tenant}, "
                            f"processing {len(events)} valid events already received"
                        )
                        break

                if stream_data is None:
                    stop_reason = "no data"
                    logger.debug(CROWDSTRIKE_NO_DATA_MESSAGE)
                    break
                if not stream_data.strip():
                    counter += 1
                    total_blank_lines_count += 1
                    if max_crlf and counter > max_crlf:
                        stop_reason = "blank-line limit"
                        logger.debug(
                            CROWDSTRIKE_REACHED_CR_LF_COUNT_MESSAGE.format(counter)
                        )
                        break
                    logger.debug(CROWDSTRIKE_RECEIVED_CR_LF_MESSAGE.format(counter))
                    continue

                ok, event = client.parse_stream_event(stream_data)
                if (
                    not ok
                    or not isinstance(event, dict)
                    or not isinstance(event.get("metadata"), dict)
                ):
                    skipped_records += 1
                    logger.warning(
                        f"Skipping malformed CrowdStrike stream record; tenant={tenant}"
                    )
                    continue
                metadata = event["metadata"]
                event_type = metadata.get("eventType")
                if event_type not in CROWDSTRIKE_EVENT_TYPES:
                    continue
                details = event.get("event")
                offset = metadata.get("offset")
                name_key = (
                    "DetectName" if event_type == "DetectionSummaryEvent" else "Name"
                )
                if (
                    not isinstance(details, dict)
                    or type(offset) is not int
                    or offset < 0
                    or (
                        asset.collate
                        and (
                            not isinstance(details.get(name_key), str)
                            or not details[name_key].strip()
                        )
                    )
                ):
                    skipped_records += 1
                    logger.warning(
                        f"Skipping malformed CrowdStrike detection; tenant={tenant}"
                    )
                    continue
                events.append(event)
                counter = 0
                if max_events and len(events) >= max_events:
                    stop_reason = "event limit"
                    break
                logger.progress(CROWDSTRIKE_PULLED_EVENTS_MESSAGE.format(len(events)))
            logger.debug(
                CROWDSTRIKE_BLANK_LINES_COUNT_MESSAGE.format(total_blank_lines_count)
            )
        finally:
            response.close()

        logger.info(
            f"Poll stream complete: tenant={tenant}, events={len(events)}, "
            f"skipped={skipped_records}, stop_reason={stop_reason}"
        )
        logger.info(CROWDSTRIKE_GOT_EVENTS_MESSAGE.format(len(events)))
        if skipped_records:
            logger.warning(
                f"Skipped {skipped_records} malformed records; tenant={tenant}. "
                "Saving valid events may permanently skip malformed records before the next checkpoint."
            )
        if events:
            stage = "event parsing"
            logger.info(f"Poll stage={stage}, tenant={tenant}, events={len(events)}")
            results = events_parser.parse_events(events, asset.collate)
            if not results:
                raise ValueError("CrowdStrike parser produced no ingestion results")
            stage = "yielding results"
            logger.info(f"Poll stage={stage}, tenant={tenant}")
            yield from _yield_results(results)

            if not is_poll_now:
                stage = "checkpoint staging"
                next_offset = max(
                    lower_id, max(event["metadata"]["offset"] for event in events) + 1
                )
                asset.ingest_state[offset_key] = next_offset
                logger.info(
                    f"Checkpoint staged: tenant={tenant}, previous={lower_id}, next={next_offset}; "
                    "commit pending SDK artifact saves"
                )
    except Exception:
        logger.error(
            f"Poll failed: stage={stage}, tenant={tenant}, events={len(events)}, "
            f"skipped={skipped_records}, checkpoint_start={lower_id}"
        )
        raise


def _yield_results(results: list) -> Iterator[Container | Artifact]:
    for result in results:
        container = result.get("container")
        artifacts = result.get("artifacts")
        if not container or not artifacts:
            raise ValueError(
                "CrowdStrike parser produced an incomplete ingestion result"
            )
        yield Container(**container)
        for artifact in artifacts:
            yield Artifact(**artifact)


# Register simple actions (plain @app.action() in their own modules).
# Imports are placed at the bottom so the `app` instance exists first.
# Custom-view actions are registered explicitly via app.register_action(...).
from .actions import assign_hosts  # noqa: F401
from .actions import check_detonate_status  # noqa: F401
from .actions import create_ioa_rule  # noqa: F401
from .actions import create_ioa_rule_group  # noqa: F401
from .actions import create_session  # noqa: F401
from .actions import delete_iocs  # noqa: F401
from .actions import delete_ioa_rule  # noqa: F401
from .actions import delete_ioa_rule_group  # noqa: F401
from .actions import delete_session  # noqa: F401
from .actions import detonate_file  # noqa: F401
from .actions import detonate_url  # noqa: F401
from .actions import download_report  # noqa: F401
from .actions import file_reputation  # noqa: F401
from .actions import get_command_details  # noqa: F401
from .actions import get_device_detail  # noqa: F401
from .actions import get_device_scroll  # noqa: F401
from .actions import get_epp_alerts_details  # noqa: F401
from .actions import get_indicator  # noqa: F401
from .actions import get_process_detail  # noqa: F401
from .actions import get_role  # noqa: F401
from .actions import get_session_file  # noqa: F401
from .actions import get_user_roles  # noqa: F401
from .actions import get_zta_data  # noqa: F401
from .actions import hunt_domain  # noqa: F401
from .actions import hunt_file  # noqa: F401
from .actions import hunt_ip  # noqa: F401
from .actions import list_alerts  # noqa: F401
from .actions import list_custom_indicators  # noqa: F401
from .actions import list_epp_alerts  # noqa: F401
from .actions import list_groups  # noqa: F401
from .actions import list_ioa_platforms  # noqa: F401
from .actions import list_ioa_rule_groups  # noqa: F401
from .actions import list_ioa_severities  # noqa: F401
from .actions import list_ioa_types  # noqa: F401
from .actions import list_processes  # noqa: F401
from .actions import list_put_files  # noqa: F401
from .actions import list_roles  # noqa: F401
from .actions import list_session_files  # noqa: F401
from .actions import list_sessions  # noqa: F401
from .actions import make_request  # noqa: F401
from .actions import list_users  # noqa: F401
from .actions import query_device  # noqa: F401
from .actions import quarantine_device  # noqa: F401
from .actions import remove_hosts  # noqa: F401
from .actions import resolve_epp_alerts  # noqa: F401
from .actions import run_admin_command  # noqa: F401
from .actions import run_command  # noqa: F401
from .actions import run_query  # noqa: F401
from .actions import unquarantine_device  # noqa: F401
from .actions import url_reputation  # noqa: F401
from .actions import update_epp_alerts  # noqa: F401
from .actions import update_iocs  # noqa: F401
from .actions import update_ioa_rule  # noqa: F401
from .actions import update_ioa_rule_group  # noqa: F401
from .actions import upload_iocs  # noqa: F401
from .actions import upload_put_file  # noqa: F401
