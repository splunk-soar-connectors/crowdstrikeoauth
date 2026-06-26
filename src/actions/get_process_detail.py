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
from ..consts import CROWDSTRIKE_GET_PROCESS_DETAIL_APIPATH


class GetProcessDetailParams(Params):
    falcon_process_id: str = Param(
        description="ID of the process to get the details of",
        required=True,
        primary=True,
        cef_types=["falcon process id"],
        column_name="Falcon Process ID",
    )


class GetProcessDetailOutput(PermissiveActionOutput):
    command_line: str | None = OutputField(column_name="Command Line")
    file_name: str | None = OutputField(column_name="File Name")
    start_timestamp: str | None = OutputField(column_name="Start Timestamp")
    stop_timestamp: str | None = OutputField(column_name="Stop Timestamp")
    device_id: str | None = OutputField(
        cef_types=["crowdstrike device id"], column_name="Crowdstrike Device ID"
    )
    start_timestamp_raw: str | None = OutputField(column_name="Start Timestamp Raw")
    stop_timestamp_raw: str | None = OutputField(column_name="Stop Timestamp Raw")


@app.action(
    description="Queries CrowdStrike for the details of a process",
    action_type="investigate",
    read_only=True,
    render_as="table",
)
def get_process_detail(
    params: GetProcessDetailParams, soar: SOARClient, asset: Asset
) -> list[GetProcessDetailOutput]:
    client = get_client(asset)

    response = client.make_rest_call(
        CROWDSTRIKE_GET_PROCESS_DETAIL_APIPATH,
        params={"ids": params.falcon_process_id},
    )

    data = response["resources"][0]

    soar.set_message("Process details fetched successfully")
    return [GetProcessDetailOutput(**data)]
