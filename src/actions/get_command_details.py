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
from ..helper import validate_integer


class GetCommandDetailsParams(Params):
    cloud_request_id: str = Param(
        description="Cloud Request ID for Command",
        required=True,
        primary=True,
        cef_types=["crowdstrike cloud request id"],
        column_name="Cloud Request ID",
    )
    timeout_seconds: int = Param(
        description="Time (in seconds; default is 60) to wait before timing out poll for results",
        default=60,
    )


class GetCommandDetailsResource(PermissiveActionOutput):
    base_command: str | None = OutputField(column_name="Command")
    stdout: str | None = OutputField(column_name="Stdout")
    stderr: str | None = OutputField(column_name="Stderr")
    complete: bool | None = None
    session_id: str | None = OutputField(cef_types=["crowdstrike rtr session id"])
    task_id: str | None = None


class GetCommandDetailsOutput(PermissiveActionOutput):
    resources: list[GetCommandDetailsResource] | None = None


class GetCommandDetailsSummary(ActionOutput):
    results: str | None = None


@app.action(
    description="Retrieve results of an active responder command executed on a single host",
    action_type="investigate",
    read_only=True,
    render_as="table",
    summary_type=GetCommandDetailsSummary,
)
def get_command_details(
    params: GetCommandDetailsParams, soar: SOARClient, asset: Asset
) -> list[GetCommandDetailsOutput]:
    client = get_client(asset)

    timeout = validate_integer(params.timeout_seconds, "timeout_seconds")

    soar.set_summary(GetCommandDetailsSummary(results="Successfully executed command"))

    results = client.poll_command_results(params.cloud_request_id, timeout=timeout)

    return [GetCommandDetailsOutput(**data) for data in results]
