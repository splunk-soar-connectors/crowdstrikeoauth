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
    CROWDSTRIKE_IOA_CREATE_RULE_GROUP_ENDPOINT,
    CROWDSTRIKE_UPDATE_PREVENTION_ACTIONS_ENDPOINT,
)


class UpdateIoaRuleGroupParams(Params):
    id: str = Param(
        description="ID of the rule group to update",
        required=True,
        primary=True,
        cef_types=["crowdstrike ioa rule group id"],
    )
    version: int = Param(description="Version of the rule group", required=True)
    name: str = Param(description="Name of the rule group", required=True)
    description: str = Param(description="Description of the rule group", required=True)
    enabled: bool = Param(
        description="Whether the rule group is enabled",
        required=False,
        default=False,
    )
    comment: str = Param(description="Comment for the update", required=True)
    assign_policy_id: str = Param(
        description="Comma-separated list of prevention policy IDs to attach",
        required=False,
        cef_types=["crowdstrike prevention policy id"],
    )
    remove_policy_id: str = Param(
        description="Comma-separated list of prevention policy IDs to remove",
        required=False,
        cef_types=["crowdstrike prevention policy id"],
    )


class UpdateIoaRuleGroupResource(PermissiveActionOutput):
    id: str | None = OutputField(cef_types=["crowdstrike ioa rule group id"])
    customer_id: str | None = OutputField(cef_types=["crowdstrike customer id"])
    enabled: bool | None = None
    name: str | None = None
    description: str | None = None
    platform: str | None = None
    deleted: bool | None = None
    rule_ids: list[str] | None = OutputField(cef_types=["crowdstrike ioa rule id"])
    comment: str | None = None
    version: int | None = None
    created_by: str | None = OutputField(cef_types=["crowdstrike user id"])
    created_on: str | None = None
    modified_by: str | None = OutputField(cef_types=["crowdstrike user id"])
    modified_on: str | None = None
    committed_on: str | None = None
    assigned_policy_ids: list[str] | None = OutputField(
        cef_types=["crowdstrike prevention policy id"]
    )
    removed_policy_ids: list[str] | None = OutputField(
        cef_types=["crowdstrike prevention policy id"]
    )


class UpdateIoaRuleGroupOutput(PermissiveActionOutput):
    resources: list[UpdateIoaRuleGroupResource] | None = None


class UpdateIoaRuleGroupSummary(ActionOutput):
    rule_group_id: str | None = None


@app.view_handler(template="crowdstrike_update_ioa_rule_group.html")
def update_ioa_rule_group_view(outputs: list[UpdateIoaRuleGroupOutput]) -> dict:
    results = []
    for output in outputs:
        results.append({"data": [output.model_dump()]})
    return {"results": results}


@app.action(
    name="update ioa rule group",
    description="Update an existing IOA rule group",
    action_type="contain",
    read_only=False,
    view_handler=update_ioa_rule_group_view,
    summary_type=UpdateIoaRuleGroupSummary,
)
def update_ioa_rule_group(
    params: UpdateIoaRuleGroupParams, soar: SOARClient, asset: Asset
) -> UpdateIoaRuleGroupOutput:
    client = get_client(asset)

    update_params = {
        "id": params.id,
        "rulegroup_version": params.version,
        "name": params.name,
        "description": params.description,
        "enabled": params.enabled,
        "comment": params.comment,
    }
    resp_json = client.make_rest_call(
        CROWDSTRIKE_IOA_CREATE_RULE_GROUP_ENDPOINT,
        json_data=update_params,
        method="patch",
    )

    rulegroup_id = resp_json["resources"][0]["id"]

    assign_policy_ids_list = [
        x.strip() for x in (params.assign_policy_id or "").split(",") if x.strip()
    ]
    for policy_id in assign_policy_ids_list:
        assign_params = {
            "action_parameters": [{"name": "rule_group_id", "value": rulegroup_id}],
            "ids": [policy_id],
        }
        client.make_rest_call(
            CROWDSTRIKE_UPDATE_PREVENTION_ACTIONS_ENDPOINT,
            params={"action_name": "add-rule-group"},
            json_data=assign_params,
            method="post",
        )

    remove_policy_ids_list = [
        x.strip() for x in (params.remove_policy_id or "").split(",") if x.strip()
    ]
    for policy_id in remove_policy_ids_list:
        remove_params = {
            "action_parameters": [{"name": "rule_group_id", "value": rulegroup_id}],
            "ids": [policy_id],
        }
        client.make_rest_call(
            CROWDSTRIKE_UPDATE_PREVENTION_ACTIONS_ENDPOINT,
            params={"action_name": "remove-rule-group"},
            json_data=remove_params,
            method="post",
        )

    resp_json["resources"][0]["assigned_policy_ids"] = assign_policy_ids_list
    resp_json["resources"][0]["removed_policy_ids"] = remove_policy_ids_list

    soar.set_summary(UpdateIoaRuleGroupSummary(rule_group_id=rulegroup_id))
    soar.set_message("Rule group updated successfully")

    return UpdateIoaRuleGroupOutput(**resp_json)
