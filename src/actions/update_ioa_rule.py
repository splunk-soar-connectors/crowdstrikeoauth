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


class UpdateIoaRuleParams(Params):
    rule_group_id: str = Param(
        description="ID of the rule group",
        required=True,
        primary=True,
        cef_types=["crowdstrike ioa rule group id"],
    )
    rule_group_version: int = Param(
        description="Version of the rule group", required=True
    )
    rule_id: str = Param(
        description="ID of the rule to update",
        required=True,
        cef_types=["crowdstrike ioa rule id"],
    )
    rule_version: int = Param(description="Version of the rule", required=True)
    name: str = Param(description="Name of the rule", required=True)
    description: str = Param(description="Description of the rule", required=True)
    severity: str = Param(description="Severity of the rule", required=True)
    disposition_id: int = Param(description="Disposition ID", required=True)
    field_values: str = Param(
        description="JSON list of field values for the rule", required=True
    )
    comment: str = Param(description="Comment for the rule", required=False)
    enabled: bool = Param(
        description="Whether the rule is enabled", required=False, default=False
    )


class UpdateIoaRuleFieldValueOption(PermissiveActionOutput):
    label: str | None = None
    value: str | None = None


class UpdateIoaRuleFieldValue(PermissiveActionOutput):
    name: str | None = None
    value: str | None = None
    label: str | None = None
    type: str | None = None
    values: list[UpdateIoaRuleFieldValueOption] | None = None
    final_value: str | None = None


class UpdateIoaRuleRule(PermissiveActionOutput):
    name: str | None = None
    comment: str | None = None
    deleted: bool | None = None
    enabled: bool | None = None
    created_by: str | None = OutputField(cef_types=["crowdstrike unique user id"])
    created_on: str | None = OutputField(cef_types=["date"])
    pattern_id: str | None = None
    customer_id: str | None = OutputField(cef_types=["crowdstrike customer id"])
    description: str | None = None
    modified_by: str | None = OutputField(cef_types=["crowdstrike unique user id"])
    modified_on: str | None = OutputField(cef_types=["date"])
    ruletype_id: str | None = None
    committed_on: str | None = OutputField(cef_types=["date"])
    field_values: list[UpdateIoaRuleFieldValue] | None = None
    magic_cookie: int | None = None
    rulegroup_id: str | None = OutputField(cef_types=["crowdstrike ioa rule group id"])
    ruletype_name: str | None = None
    disposition_id: int | None = None
    instance_id: str | None = OutputField(cef_types=["crowdstrike ioa rule id"])
    instance_version: int | None = None
    pattern_severity: str | None = None
    action_label: str | None = None


class UpdateIoaRuleResource(PermissiveActionOutput):
    id: str | None = OutputField(cef_types=["crowdstrike ioa rule group id"])
    name: str | None = None
    rules: list[UpdateIoaRuleRule] | None = None
    comment: str | None = None
    enabled: bool | None = None
    deleted: bool | None = None
    version: int | None = None
    platform: str | None = None
    rule_ids: list[str] | None = OutputField(cef_types=["crowdstrike ioa rule id"])
    created_by: str | None = OutputField(cef_types=["crowdstrike unique user id"])
    created_on: str | None = OutputField(cef_types=["date"])
    customer_id: str | None = OutputField(cef_types=["crowdstrike customer id"])
    description: str | None = None
    modified_by: str | None = OutputField(cef_types=["crowdstrike unique user id"])
    modified_on: str | None = OutputField(cef_types=["date"])
    committed_on: str | None = OutputField(cef_types=["date"])


class UpdateIoaRuleOutput(PermissiveActionOutput):
    resources: list[UpdateIoaRuleResource] | None = None


class UpdateIoaRuleSummary(ActionOutput):
    rule_group_id: str | None = OutputField(cef_types=["crowdstrike ioa rule group id"])
    rule_group_version: int | None = None
    rule_id: str | None = OutputField(cef_types=["crowdstrike ioa rule id"])
    rule_version: int | None = None


@app.view_handler(template="crowdstrike_update_ioa_rule.html")
def update_ioa_rule_view(outputs: list[UpdateIoaRuleOutput]) -> dict:
    results = []
    for output in outputs:
        results.append({"data": [output.model_dump()]})
    return {"results": results}


@app.action(
    name="update ioa rule",
    description="Update an existing IOA rule",
    action_type="contain",
    read_only=False,
    view_handler=update_ioa_rule_view,
    summary_type=UpdateIoaRuleSummary,
)
def update_ioa_rule(
    params: UpdateIoaRuleParams, soar: SOARClient, asset: Asset
) -> UpdateIoaRuleOutput:
    client = get_client(asset)

    try:
        field_values = json.loads(params.field_values)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse field_values: {e}") from e

    update_params = {
        "rulegroup_id": params.rule_group_id,
        "rulegroup_version": params.rule_group_version,
        "instance_version": params.rule_version,
        "rule_updates": [
            {
                "instance_id": params.rule_id,
                "pattern_severity": params.severity,
                "enabled": params.enabled,
                "name": params.name,
                "description": params.description,
                "disposition_id": params.disposition_id,
                "field_values": field_values,
            }
        ],
    }
    if params.comment:
        update_params["comment"] = params.comment

    resp_json = client.make_rest_call(
        CROWDSTRIKE_IOA_CREATE_RULE_ENDPOINT,
        json_data=update_params,
        method="patch",
    )

    rulegroup_id = resp_json["resources"][0]["id"]
    rulegroup_version = 0
    rule_version = 0

    for rule in resp_json["resources"][0]["rules"]:
        if rule["instance_id"] == params.rule_id:
            rulegroup_version = rule["magic_cookie"]
            rule_version = rule["instance_version"]

    soar.set_summary(
        UpdateIoaRuleSummary(
            rule_group_id=rulegroup_id,
            rule_group_version=rulegroup_version,
            rule_id=params.rule_id,
            rule_version=rule_version,
        )
    )
    soar.set_message("Rule updated successfully")

    return UpdateIoaRuleOutput(**resp_json)
