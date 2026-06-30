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
from ..consts import CROWDSTRIKE_GET_RTR_FILES_ENDPOINT


class ListSessionFilesParams(Params):
    session_id: str = Param(
        description="RTR Session ID",
        required=True,
        primary=True,
        cef_types=["crowdstrike rtr session id"],
    )


class ListSessionFilesResource(PermissiveActionOutput):
    name: str | None = OutputField(cef_types=["file name"], column_name="Name")
    sha256: str | None = OutputField(cef_types=["sha256"], column_name="SHA256")
    session_id: str | None = OutputField(
        cef_types=["crowdstrike rtr session id"], column_name="Session ID"
    )


class ListSessionFilesOutput(PermissiveActionOutput):
    resources: list[ListSessionFilesResource] | None = None


class ListSessionFilesSummary(ActionOutput):
    total_files: int | None = None


@app.action(
    description="Get a list of files for the specified RTR session",
    action_type="investigate",
    read_only=True,
    render_as="table",
    summary_type=ListSessionFilesSummary,
)
def list_session_files(
    params: ListSessionFilesParams, soar: SOARClient, asset: Asset
) -> list[ListSessionFilesOutput]:
    client = get_client(asset)

    resp_json = client.make_rest_call(
        CROWDSTRIKE_GET_RTR_FILES_ENDPOINT, params={"session_id": params.session_id}
    )

    resources = resp_json.get("resources", [])
    if not resources:
        soar.set_message(f"No session files present for session ID {params.session_id}")
        return [ListSessionFilesOutput(**resp_json)]

    soar.set_summary(ListSessionFilesSummary(total_files=len(resources)))
    soar.set_message("Session files listed successfully")

    return [ListSessionFilesOutput(**resp_json)]
