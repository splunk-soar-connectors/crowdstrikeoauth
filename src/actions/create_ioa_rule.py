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

import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import CROWDSTRIKE_IOA_CREATE_RULE_ENDPOINT


class CreateIoaRuleParams(Params):
    rule_group_id: str = Param(
        description="ID of the rule group to add the rule to",
        required=True,
        primary=True,
        cef_types=["crowdstrike ioa rule group id"],
    )
    name: str = Param(description="Name of the rule", required=True)
    description: str = Param(description="Description of the rule", required=True)
    severity: str = Param(description="Severity of the rule", required=True)
    rule_type_id: int = Param(description="Rule type ID", required=True)
    disposition_id: int = Param(description="Disposition ID", required=True)
    field_values: str = Param(
        description="JSON list of field values for the rule", required=True
    )
    comment: str = Param(description="Comment for the rule", required=False)
    enabled: bool = Param(
        description="Whether the rule is enabled", required=False, default=False
    )


class CreateIoaRuleFieldValueOption(PermissiveActionOutput):
    label: str | None = None
    value: str | None = None


class CreateIoaRuleFieldValue(PermissiveActionOutput):
    name: str | None = None
    value: str | None = None
    label: str | None = None
    type: str | None = None
    values: list[CreateIoaRuleFieldValueOption] | None = None
    final_value: str | None = None


class CreateIoaRuleResource(PermissiveActionOutput):
    instance_id: str | None = OutputField(cef_types=["crowdstrike ioa rule id"])
    customer_id: str | None = OutputField(cef_types=["crowdstrike customer id"])
    ruletype_id: str | None = None
    ruletype_name: str | None = None
    comment: str | None = None
    enabled: bool | None = None
    deleted: bool | None = None
    magic_cookie: int | None = None
    rulegroup_id: str | None = OutputField(cef_types=["crowdstrike ioa rule group id"])
    version_ids: list[str] | None = None
    instance_version: int | None = None
    name: str | None = None
    description: str | None = None
    pattern_id: str | None = None
    pattern_severity: str | None = None
    action_label: str | None = None
    disposition_id: int | None = None
    field_values: list[CreateIoaRuleFieldValue] | None = None


class CreateIoaRuleOutput(PermissiveActionOutput):
    resources: list[CreateIoaRuleResource] | None = None


class CreateIoaRuleSummary(ActionOutput):
    rule_group_id: str | None = OutputField(cef_types=["crowdstrike ioa rule group id"])
    rule_id: str | None = OutputField(cef_types=["crowdstrike ioa rule id"])


@app.view_handler(template="crowdstrike_create_ioa_rule.html")
def create_ioa_rule_view(outputs: list[CreateIoaRuleOutput]) -> dict:
    results = []
    for output in outputs:
        results.append({"data": [output.model_dump()]})
    return {"results": results}


@app.action(
    name="create ioa rule",
    description="Create a new IOA rule within a rule group",
    action_type="contain",
    read_only=False,
    view_handler=create_ioa_rule_view,
    summary_type=CreateIoaRuleSummary,
)
def create_ioa_rule(
    params: CreateIoaRuleParams, soar: SOARClient, asset: Asset
) -> CreateIoaRuleOutput:
    client = get_client(asset)

    try:
        field_values = json.loads(params.field_values)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse field_values: {e}") from e

    create_params = {
        "rulegroup_id": params.rule_group_id,
        "name": params.name,
        "description": params.description,
        "pattern_severity": params.severity,
        "ruletype_id": str(params.rule_type_id),
        "disposition_id": params.disposition_id,
        "field_values": field_values,
    }
    if params.comment:
        create_params["comment"] = params.comment

    resp_json = client.make_rest_call(
        CROWDSTRIKE_IOA_CREATE_RULE_ENDPOINT,
        json_data=create_params,
        method="post",
    )

    rulegroup_id = resp_json["resources"][0].get("rulegroup_id")
    rulegroup_version = resp_json["resources"][0].get("magic_cookie")
    rule_id = resp_json["resources"][0].get("instance_id")
    rule_version = resp_json["resources"][0].get("instance_version")
    if not (rulegroup_id and rulegroup_version and rule_id and rule_version):
        raise ValueError(
            "CrowdStrike failed to return a Rule Group ID/Version and Rule ID/Version"
        )

    if params.enabled:
        update_params = {
            "rulegroup_id": rulegroup_id,
            "rulegroup_version": rulegroup_version,
            "instance_version": rule_version,
            "comment": "Rule enabled via Splunk SOAR",
            "rule_updates": [
                {
                    "instance_id": rule_id,
                    "name": params.name,
                    "description": params.description,
                    "enabled": True,
                    "pattern_severity": params.severity,
                    "disposition_id": params.disposition_id,
                    "field_values": field_values,
                }
            ],
        }
        update_resp_json = client.make_rest_call(
            CROWDSTRIKE_IOA_CREATE_RULE_ENDPOINT,
            json_data=update_params,
            method="patch",
        )

        for resource in update_resp_json["resources"]:
            for rule in resource["rules"]:
                if rule["instance_id"] == rule_id:
                    rule["rulegroup_id"] = rulegroup_id
                    resp_json["resources"] = [rule]

    soar.set_summary(CreateIoaRuleSummary(rule_group_id=rulegroup_id, rule_id=rule_id))
    soar.set_message("Rule created successfully")

    return CreateIoaRuleOutput(**resp_json)
