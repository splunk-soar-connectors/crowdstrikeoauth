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
from ..consts import CROWDSTRIKE_DETONATE_RESOURCE_ENDPOINT


class CheckDetonateStatusParams(Params):
    resource_id: str = Param(
        description="Resource ID of the submitted detonation",
        required=True,
        primary=True,
        cef_types=["crowdstrike resource id"],
        column_name="Resource ID",
    )


class CheckDetonateStatusSandbox(PermissiveActionOutput):
    action_script: str | None = None
    command_line: str | None = None
    enable_tor: bool | None = None
    environment_id: int | None = None
    network_settings: str | None = None
    sha256: str | None = OutputField(cef_types=["sha256"])
    submit_name: str | None = None
    url: str | None = OutputField(cef_types=["url"])


class CheckDetonateStatusOutput(PermissiveActionOutput):
    cid: str | None = None
    created_timestamp: str | None = OutputField(cef_types=["date"])
    id: str | None = OutputField(cef_types=["crowdstrike resource id"])
    origin: str | None = None
    state: str | None = None
    user_id: str | None = None
    user_name: str | None = None
    user_uuid: str | None = None
    sandbox: list[CheckDetonateStatusSandbox] | None = None


class CheckDetonateStatusSummary(ActionOutput):
    state: str | None = None


@app.action(
    name="check status",
    description="Check detonation status using the resource ID",
    action_type="investigate",
    read_only=True,
    render_as="table",
    summary_type=CheckDetonateStatusSummary,
)
def check_detonate_status(
    params: CheckDetonateStatusParams, soar: SOARClient, asset: Asset
) -> list[CheckDetonateStatusOutput]:
    client = get_client(asset)

    resp_json = client.make_rest_call(
        CROWDSTRIKE_DETONATE_RESOURCE_ENDPOINT,
        params={"ids": params.resource_id},
        headers={"accept": "application/json"},
    )

    resources = resp_json.get("resources")
    if not resources:
        soar.set_message("No data found")
        return []

    resource = resources[0]
    state = resource.get("state", "No state found")

    soar.set_summary(CheckDetonateStatusSummary(state=state))

    return [CheckDetonateStatusOutput(**resource)]
