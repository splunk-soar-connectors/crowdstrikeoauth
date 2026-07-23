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
from soar_sdk.action_results import PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import (
    CROWDSTRIKE_FILTER_GET_IOC,
    CROWDSTRIKE_GET_INDICATOR_ENDPOINT,
    CROWDSTRIKE_SUCC_UPDATE_ALERT,
    CROWDSTRIKE_TIME_FORMAT,
)
from ..helper import get_ioc_type, validate_integer
from datetime import UTC, datetime, timedelta


class UpdateIocsParams(Params):
    ioc: str = Param(
        description="The IOC to update",
        required=True,
        primary=True,
        cef_types=["ip", "md5", "sha256", "domain"],
    )
    action: str = Param(
        description="Action to take when a host observes the IOC",
        required=False,
        value_list=["no_action", "allow", "prevent_no_ui", "prevent", "detect"],
        cef_types=["crowdstrike indicator action"],
    )
    platforms: str = Param(
        description="Comma-separated list of platforms the IOC applies to",
        required=False,
        cef_types=["crowdstrike indicator platforms"],
    )
    expiration: int = Param(
        description="Number of days after which the IOC expires",
        required=False,
    )
    source: str = Param(
        description="The source of the IOC",
        required=False,
        default="IOC updated via Splunk SOAR",
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
        description="Comma-separated list of host group IDs the IOC applies to. "
        "Use 'all' to apply globally",
        required=False,
        cef_types=["crowdstrike host group id"],
    )
    filename: str = Param(
        description="The filename metadata of the IOC", required=False
    )


class UpdateIocsOutput(PermissiveActionOutput):
    ioc: str | None = None
    ioc_type: str | None = None
    action: str | None = None
    source: str | None = None
    description: str | None = None


@app.view_handler(template="crowdstrike_update_indicator.html")
def update_iocs_view(outputs: list[UpdateIocsOutput]) -> dict:
    results = []
    for output in outputs:
        results.append({"param": output.model_dump()})
    return {"results": results}


def _get_time_string(days: int) -> str:
    expiry_date = datetime.now(UTC) + timedelta(days=days)
    time_str = expiry_date.strftime(CROWDSTRIKE_TIME_FORMAT)
    return f"{time_str[:-2]}:{time_str[-2:]}"


@app.action(
    name="update indicator",
    description="Update an IOC",
    action_type="generic",
    read_only=False,
    view_handler=update_iocs_view,
)
def update_iocs(
    params: UpdateIocsParams, soar: SOARClient, asset: Asset
) -> list[UpdateIocsOutput]:
    client = get_client(asset)

    ioc_type = get_ioc_type(params.ioc)

    update_data: dict = {
        "filter": CROWDSTRIKE_FILTER_GET_IOC.format(ioc_type, params.ioc)
    }

    if params.action:
        update_data["action"] = params.action

    if params.expiration is not None:
        days = validate_integer(params.expiration, "expiration")
        update_data["expiration"] = _get_time_string(days)

    if params.source:
        update_data["source"] = params.source

    if params.severity:
        update_data["severity"] = params.severity

    if params.platforms:
        update_data["platforms"] = [
            x.strip() for x in params.platforms.split(",") if x.strip()
        ]

    if params.description:
        update_data["description"] = params.description

    if params.tags:
        update_data["tags"] = [x.strip() for x in params.tags.split(",") if x.strip()]

    if params.host_groups:
        if params.host_groups == "all":
            update_data["applied_globally"] = True
        else:
            update_data["host_groups"] = [
                x.strip() for x in params.host_groups.split(",") if x.strip()
            ]

    if params.filename:
        update_data["metadata"] = {"filename": params.filename}

    client.make_rest_call(
        CROWDSTRIKE_GET_INDICATOR_ENDPOINT,
        json_data={"bulk_update": update_data},
        method="patch",
    )

    soar.set_message(CROWDSTRIKE_SUCC_UPDATE_ALERT)
    return [
        UpdateIocsOutput(
            ioc=params.ioc,
            ioc_type=ioc_type,
            action=params.action,
            source=params.source,
            description=params.description,
        )
    ]
