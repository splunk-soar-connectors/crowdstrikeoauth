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


class RemoveHostsParams(Params):
    device_id: str = Param(
        description="Comma-separated list of device IDs",
        required=False,
        primary=True,
        cef_types=["crowdstrike device id"],
    )
    hostname: str = Param(
        description="Comma-separated list of hostnames",
        required=False,
        primary=True,
        cef_types=["host name"],
    )
    host_group_id: str = Param(
        description="Static host group ID",
        required=True,
        primary=True,
        cef_types=["crowdstrike host group id"],
    )


class RemoveHostsOutput(PermissiveActionOutput):
    id: str | None = OutputField(cef_types=["crowdstrike host group id"])
    name: str | None = None
    description: str | None = None
    group_type: str | None = None
    assignment_rule: str | None = None
    created_by: str | None = None
    created_timestamp: str | None = None
    modified_by: str | None = None
    modified_timestamp: str | None = None


class RemoveHostsSummary(ActionOutput):
    total_removed_device: int


@app.view_handler(template="crowdstrike_host_group.html")
def remove_hosts_view(outputs: list[RemoveHostsOutput]) -> dict:
    return {"results": [{"data": [o.model_dump() for o in outputs]}]}


@app.action(
    description="Remove one or more hosts from an existing static host group",
    action_type="contain",
    read_only=False,
    view_handler=remove_hosts_view,
    summary_type=RemoveHostsSummary,
)
def remove_hosts(
    params: RemoveHostsParams, soar: SOARClient, asset: Asset
) -> list[RemoveHostsOutput]:
    client = get_client(asset)

    device_params = {
        k: v
        for k, v in {
            "device_id": params.device_id,
            "hostname": params.hostname,
            "host_group_id": params.host_group_id,
        }.items()
        if v
    }
    device_params["action_name"] = "remove-hosts"

    results = client.perform_device_action(device_params)
    outputs = [RemoveHostsOutput(**g) for g in results]

    soar.set_summary(RemoveHostsSummary(total_removed_device=len(outputs)))
    soar.set_message("Host removed successfully")
    return outputs
