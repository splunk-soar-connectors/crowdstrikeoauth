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
from ..consts import CROWDSTRIKE_RTR_SESSION_ENDPOINT


class CreateSessionParams(Params):
    device_id: str = Param(
        description="Device ID for session to be created",
        required=True,
        primary=True,
        cef_types=["crowdstrike device id"],
    )
    queue_offline: bool = Param(
        description=(
            "Queue commands for offline devices, will execute when system comes "
            "back online"
        ),
        required=False,
        default=False,
    )


class CreateSessionResource(PermissiveActionOutput):
    session_id: str | None = OutputField(cef_types=["crowdstrike rtr session id"])
    created_at: str | None = None
    existing_aid_sessions: int | None = None
    offline_queued: bool | None = None
    pwd: str | None = OutputField(cef_types=["file path"])


class CreateSessionOutput(PermissiveActionOutput):
    device_id: str | None = OutputField(cef_types=["crowdstrike device id"])
    resources: list[CreateSessionResource] | None = None


class CreateSessionSummary(ActionOutput):
    session_id: str | None = OutputField(cef_types=["crowdstrike rtr session id"])


@app.view_handler(template="crowdstrike_create_session.html")
def create_session_view(outputs: list[CreateSessionOutput]) -> dict:
    results = []
    for output in outputs:
        results.append({"data": [output.model_dump()]})
    return {"results": results}


@app.action(
    description="Initialize a new session with the Real Time Response cloud",
    action_type="generic",
    read_only=False,
    view_handler=create_session_view,
    summary_type=CreateSessionSummary,
)
def create_session(
    params: CreateSessionParams, soar: SOARClient, asset: Asset
) -> CreateSessionOutput:
    client = get_client(asset)

    resp_json = client.make_rest_call(
        CROWDSTRIKE_RTR_SESSION_ENDPOINT,
        json_data={
            "device_id": params.device_id,
            "origin": "phantom",
            "queue_offline": params.queue_offline,
        },
        method="post",
    )

    output = CreateSessionOutput(device_id=params.device_id, **resp_json)

    try:
        session_id = resp_json["resources"][0]["session_id"]
        soar.set_summary(CreateSessionSummary(session_id=session_id))
        soar.set_message("Session created successfully")
    except (KeyError, IndexError, TypeError):
        soar.set_message(
            "Session created successfully, but unable to find session_id from the "
            "response. Unexpected response retrieved"
        )

    return output
