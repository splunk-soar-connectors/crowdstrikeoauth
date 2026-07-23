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

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import (
    CROWDSTRIKE_GET_INDICATOR_ENDPOINT,
    CROWDSTRIKE_SUCC_POST_ALERT,
    CROWDSTRIKE_TIME_FORMAT,
)
from ..helper import get_ioc_type, validate_integer
from datetime import UTC, datetime, timedelta


class UploadIocsParams(Params):
    ioc: str = Param(
        description="The IOC to upload",
        required=True,
        primary=True,
        cef_types=["sha256", "md5", "domain", "ip", "ipv6"],
    )
    action: str = Param(
        description="Action to take when a host observes the IOC",
        required=True,
        value_list=["no_action", "allow", "prevent_no_ui", "prevent", "detect"],
        cef_types=["crowdstrike indicator action"],
    )
    platforms: str = Param(
        description="Comma-separated list of platforms the IOC applies to",
        required=True,
        cef_types=["crowdstrike indicator platforms"],
    )
    expiration: int = Param(
        description="Number of days after which the IOC expires",
        required=False,
    )
    source: str = Param(
        description="The source of the IOC",
        required=False,
        default="IOC uploaded via Splunk SOAR",
    )
    description: str = Param(description="Description of the IOC", required=False)
    tags: str = Param(
        description="Comma-separated list of tags to apply to the IOC",
        required=False,
    )
    severity: str = Param(
        description="The severity of the IOC",
        required=False,
        value_list=["informational", "low", "medium", "high", "critical"],
        cef_types=["severity"],
    )
    host_groups: str = Param(
        description="Comma-separated list of host group IDs the IOC applies to",
        required=False,
        cef_types=["crowdstrike host group id"],
    )
    filename: str = Param(
        description="The filename metadata of the IOC", required=False
    )


class UploadIocsMetadata(PermissiveActionOutput):
    av_hits: int | None = None
    filename: str | None = None
    signed: bool | None = None


class UploadIocsOutput(PermissiveActionOutput):
    action: str | None = OutputField(cef_types=["crowdstrike indicator action"])
    applied_globally: bool | None = None
    created_by: str | None = None
    created_on: str | None = OutputField(cef_types=["date"])
    created_timestamp: str | None = OutputField(cef_types=["date"])
    deleted: bool | None = None
    description: str | None = None
    expiration: str | None = OutputField(cef_types=["date"])
    expiration_timestamp: str | None = OutputField(cef_types=["date"])
    expired: bool | None = None
    from_parent: bool | None = None
    host_groups: list[str] | None = OutputField(cef_types=["crowdstrike host group id"])
    id: str | None = OutputField(cef_types=["crowdstrike indicator id"])
    metadata: UploadIocsMetadata | None = None
    modified_by: str | None = None
    modified_on: str | None = None
    modified_timestamp: str | None = OutputField(cef_types=["date"])
    platforms: list[str] | None = OutputField(
        cef_types=["crowdstrike indicator platforms"]
    )
    severity: str | None = OutputField(cef_types=["severity"])
    source: str | None = None
    tags: list[str] | None = None
    type: str | None = OutputField(cef_types=["crowdstrike indicator type"])
    value: str | None = OutputField(cef_types=["ip", "ipv6", "md5", "sha256", "domain"])


@app.view_handler(template="crowdstrike_get_indicator.html")
def upload_iocs_view(outputs: list[UploadIocsOutput]) -> dict:
    return {"results": [{"data": [o.model_dump() for o in outputs]}]}


def _get_time_string(days: int) -> str:
    expiry_date = datetime.now(UTC) + timedelta(days=days)
    time_str = expiry_date.strftime(CROWDSTRIKE_TIME_FORMAT)
    return f"{time_str[:-2]}:{time_str[-2:]}"


@app.action(
    name="upload indicator",
    description="Upload an IOC",
    action_type="contain",
    read_only=False,
    view_handler=upload_iocs_view,
)
def upload_iocs(
    params: UploadIocsParams, soar: SOARClient, asset: Asset
) -> list[UploadIocsOutput]:
    client = get_client(asset)

    ioc_type = get_ioc_type(params.ioc)

    platforms = [x.strip() for x in params.platforms.split(",") if x.strip()]

    indicator: dict = {
        "action": params.action,
        "platforms": platforms,
        "type": ioc_type,
        "value": params.ioc,
    }

    if params.expiration is not None:
        days = validate_integer(params.expiration, "expiration")
        indicator["expiration"] = _get_time_string(days)

    if params.severity:
        indicator["severity"] = params.severity

    if params.source:
        indicator["source"] = params.source

    if params.description:
        indicator["description"] = params.description

    if params.tags:
        indicator["tags"] = [x.strip() for x in params.tags.split(",") if x.strip()]

    if params.host_groups:
        indicator["host_groups"] = [
            x.strip() for x in params.host_groups.split(",") if x.strip()
        ]
    else:
        indicator["applied_globally"] = True

    if params.filename:
        indicator["metadata"] = {"filename": params.filename}

    resp_json = client.make_rest_call(
        CROWDSTRIKE_GET_INDICATOR_ENDPOINT,
        json_data={"indicators": [indicator]},
        method="post",
    )

    outputs = [
        UploadIocsOutput(**resource) for resource in resp_json.get("resources", [])
    ]

    soar.set_message(CROWDSTRIKE_SUCC_POST_ALERT)
    return outputs
