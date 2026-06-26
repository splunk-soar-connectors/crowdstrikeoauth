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
from ..consts import CROWDSTRIKE_ADMIN_COMMAND_ENDPOINT


RUN_ADMIN_COMMAND_VALUE_LIST = [
    "cat",
    "cd",
    "cp",
    "encrypt",
    "env",
    "eventlog",
    "filehash",
    "get",
    "getsid",
    "ipconfig",
    "kill",
    "ls",
    "map",
    "memdump",
    "mkdir",
    "mount",
    "mv",
    "netstat",
    "ps",
    "put",
    "reg query",
    "reg set",
    "reg delete",
    "reg load",
    "reg unload",
    "restart",
    "rm",
    "run",
    "runscript",
    "shutdown",
    "unmap",
    "xmemdump",
    "zip",
]


class RunAdminCommandParams(Params):
    device_id: str = Param(
        description="Device ID to run command on",
        required=True,
        primary=True,
        cef_types=["crowdstrike device id"],
    )
    session_id: str = Param(
        description="RTR Session ID",
        required=True,
        primary=True,
        cef_types=["crowdstrike rtr session id"],
    )
    command: str = Param(
        description="RTR admin command to run",
        required=True,
        value_list=RUN_ADMIN_COMMAND_VALUE_LIST,
    )
    data: str = Param(
        description="Additional data/parameters for the command",
        required=False,
    )


class RunAdminCommandResource(PermissiveActionOutput):
    base_command: str | None = None
    complete: bool | None = None
    session_id: str | None = OutputField(cef_types=["crowdstrike rtr session id"])
    stderr: str | None = None
    stdout: str | None = None
    task_id: str | None = None


class RunAdminCommandOutput(PermissiveActionOutput):
    resources: list[RunAdminCommandResource] | None = None


class RunAdminCommandSummary(ActionOutput):
    cloud_request_id: str | None = OutputField(
        cef_types=["crowdstrike cloud request id"]
    )


@app.view_handler(template="crowdstrike_command_output.html")
def run_admin_command_view(outputs: list[RunAdminCommandOutput]) -> dict:
    return {"results": [{"data": [o.model_dump() for o in outputs]}]}


@app.action(
    description="Execute an RTR administrator command on a single host",
    action_type="generic",
    read_only=False,
    view_handler=run_admin_command_view,
    summary_type=RunAdminCommandSummary,
)
def run_admin_command(
    params: RunAdminCommandParams, soar: SOARClient, asset: Asset
) -> list[RunAdminCommandOutput]:
    client = get_client(asset)

    request_data = {
        "session_id": params.session_id,
        "device_id": params.device_id,
        "base_command": params.command,
        "command_string": params.command + " " + (params.data or ""),
    }

    resp_json = client.make_rest_call(
        CROWDSTRIKE_ADMIN_COMMAND_ENDPOINT,
        json_data=request_data,
        method="post",
    )

    try:
        cloud_request_id = resp_json["resources"][0]["cloud_request_id"]
    except (KeyError, IndexError, TypeError) as e:
        raise ValueError(
            "Error occurred while fetching the cloud_request_id from the response. "
            "Unexpected response retrieved"
        ) from e

    soar.set_summary(RunAdminCommandSummary(cloud_request_id=cloud_request_id))

    results = client.poll_command_results(
        cloud_request_id, endpoint=CROWDSTRIKE_ADMIN_COMMAND_ENDPOINT
    )

    return [RunAdminCommandOutput(**data) for data in results]
