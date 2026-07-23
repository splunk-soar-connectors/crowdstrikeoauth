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
from soar_sdk.action_results import ActionOutput, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import CROWDSTRIKE_RTR_SESSION_ENDPOINT


class DeleteSessionParams(Params):
    session_id: str = Param(
        description="RTR Session ID",
        required=True,
        primary=True,
        cef_types=["crowdstrike rtr session id"],
    )


class DeleteSessionOutput(PermissiveActionOutput):
    pass


class DeleteSessionSummary(ActionOutput):
    results: str


@app.action(
    description="Deletes a Real Time Response session",
    action_type="generic",
    read_only=False,
)
def delete_session(
    params: DeleteSessionParams, soar: SOARClient, asset: Asset
) -> DeleteSessionOutput:
    client = get_client(asset)

    resp_json = client.make_rest_call(
        CROWDSTRIKE_RTR_SESSION_ENDPOINT,
        params={"session_id": params.session_id},
        method="delete",
    )

    soar.set_summary(
        DeleteSessionSummary(
            results=f"Successfully removed session: {params.session_id}"
        )
    )
    soar.set_message("Session ended successfully")
    return DeleteSessionOutput(**resp_json)
