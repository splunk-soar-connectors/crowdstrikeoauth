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
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import (
    CROWDSTRIKE_GET_DEVICE_DETAILS_ENDPOINT,
    CROWDSTRIKE_NO_DATA_MESSAGE,
    CROWDSTRIKE_STATUS_CODE_CHECK_MESSAGE,
)


class GetDeviceDetailParams(Params):
    id: str = Param(
        description="ID of the device to get the details of",
        required=True,
        primary=True,
        cef_types=["crowdstrike device id"],
    )


class GetDeviceDetailOutput(PermissiveActionOutput):
    device_id: str | None = OutputField(
        cef_types=["crowdstrike device id"], column_name="Crowdstrike Device ID"
    )
    hostname: str | None = OutputField(cef_types=["host name"], column_name="Hostname")
    last_seen: str | None = OutputField(column_name="Last Seen")
    os_version: str | None = OutputField(column_name="OS Version")
    platform_name: str | None = OutputField(column_name="Platform")


class GetDeviceDetailSummary(ActionOutput):
    hostname: str | None = OutputField(cef_types=["host name"])


@app.action(
    name="get system info",
    description="Queries CrowdStrike for the details of a device",
    action_type="investigate",
    read_only=True,
    render_as="table",
    summary_type=GetDeviceDetailSummary,
)
def get_device_detail(
    params: GetDeviceDetailParams, soar: SOARClient, asset: Asset
) -> list[GetDeviceDetailOutput]:
    client = get_client(asset)

    try:
        response = client.make_rest_call(
            CROWDSTRIKE_GET_DEVICE_DETAILS_ENDPOINT, params={"ids": params.id}
        )
    except Exception as e:
        if CROWDSTRIKE_STATUS_CODE_CHECK_MESSAGE in str(e):
            soar.set_message(CROWDSTRIKE_NO_DATA_MESSAGE)
            return []
        raise

    data = response["resources"][0]

    soar.set_summary(GetDeviceDetailSummary(hostname=data.get("hostname")))
    soar.set_message("Device details fetched successfully")
    return [GetDeviceDetailOutput(**data)]
