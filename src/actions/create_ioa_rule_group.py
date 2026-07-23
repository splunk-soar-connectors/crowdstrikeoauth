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


class CreateIoaRuleGroupParams(Params):
    name: str = Param(description="Name of the rule group", required=True, primary=True)
    description: str = Param(description="Description of the rule group", required=True)
    platform: str = Param(description="Platform for the rule group", required=True)
    enabled: bool = Param(
        description="Whether the rule group is enabled",
        required=False,
        default=False,
    )
    policy_id: str = Param(
        description="Comma-separated list of prevention policy IDs to attach",
        required=False,
        allow_list=True,
        cef_types=["crowdstrike prevention policy id"],
    )


class CreateIoaRuleGroupResource(PermissiveActionOutput):
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


class CreateIoaRuleGroupOutput(PermissiveActionOutput):
    resources: list[CreateIoaRuleGroupResource] | None = None


class CreateIoaRuleGroupSummary(ActionOutput):
    rule_group_id: str | None = None


@app.view_handler(template="crowdstrike_create_ioa_rule_group.html")
def create_ioa_rule_group_view(outputs: list[CreateIoaRuleGroupOutput]) -> dict:
    results = []
    for output in outputs:
        results.append({"data": [output.model_dump()]})
    return {"results": results}


@app.action(
    name="create ioa rule group",
    description="Create an empty IOA rule group",
    action_type="contain",
    read_only=False,
    view_handler=create_ioa_rule_group_view,
    summary_type=CreateIoaRuleGroupSummary,
)
def create_ioa_rule_group(
    params: CreateIoaRuleGroupParams, soar: SOARClient, asset: Asset
) -> CreateIoaRuleGroupOutput:
    client = get_client(asset)

    create_params = {
        "name": params.name,
        "description": params.description,
        "platform": params.platform,
    }
    resp_json = client.make_rest_call(
        CROWDSTRIKE_IOA_CREATE_RULE_GROUP_ENDPOINT,
        json_data=create_params,
        method="post",
    )

    rulegroup_id = resp_json["resources"][0].get("id")
    rulegroup_version = resp_json["resources"][0].get("version")
    if rulegroup_id is None or rulegroup_version is None:
        raise ValueError("CrowdStrike failed to return a Rule Group ID and Version")

    if params.enabled:
        update_params = {
            "id": rulegroup_id,
            "rulegroup_version": rulegroup_version,
            "name": params.name,
            "description": params.description,
            "enabled": True,
            "comment": "Rule Group enabled via Splunk SOAR",
        }
        resp_json = client.make_rest_call(
            CROWDSTRIKE_IOA_CREATE_RULE_GROUP_ENDPOINT,
            json_data=update_params,
            method="patch",
        )

    policy_ids_list = [
        x.strip() for x in (params.policy_id or "").split(",") if x.strip()
    ]
    for policy_id in policy_ids_list:
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

    resp_json["resources"][0]["assigned_policy_ids"] = policy_ids_list

    soar.set_summary(CreateIoaRuleGroupSummary(rule_group_id=rulegroup_id))
    soar.set_message("Rule group created successfully")

    return CreateIoaRuleGroupOutput(**resp_json)
