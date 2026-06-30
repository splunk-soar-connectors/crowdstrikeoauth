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
from ..consts import CROWDSTRIKE_IOA_CREATE_RULE_ENDPOINT


class DeleteIoaRuleParams(Params):
    rule_group_id: str = Param(
        description="ID of the rule group",
        required=True,
        primary=True,
        cef_types=["crowdstrike ioa rule group id"],
    )
    rule_id: str = Param(
        description="Comma-separated list of rule IDs to delete",
        required=True,
        cef_types=["crowdstrike ioa rule id"],
    )


class DeleteIoaRuleOutput(PermissiveActionOutput):
    pass


class DeleteIoaRuleSummary(ActionOutput):
    resources_affected: str | None = None


@app.view_handler(template="crowdstrike_delete_ioa_rule.html")
def delete_ioa_rule_view(outputs: list[DeleteIoaRuleOutput]) -> dict:
    results = []
    for output in outputs:
        results.append({"data": [output.model_dump()]})
    return {"results": results}


@app.action(
    name="delete ioa rule",
    description="Delete IOA rules from a rule group",
    action_type="contain",
    read_only=False,
    view_handler=delete_ioa_rule_view,
    summary_type=DeleteIoaRuleSummary,
)
def delete_ioa_rule(
    params: DeleteIoaRuleParams, soar: SOARClient, asset: Asset
) -> DeleteIoaRuleOutput:
    client = get_client(asset)

    ids_list = [x.strip() for x in params.rule_id.split(",") if x.strip()]
    rest_params = {"rule_group_id": params.rule_group_id, "ids": ",".join(ids_list)}
    resp_json = client.make_rest_call(
        CROWDSTRIKE_IOA_CREATE_RULE_ENDPOINT,
        params=rest_params,
        method="delete",
    )

    resources_affected = resp_json["meta"]["writes"]["resources_affected"]
    soar.set_summary(DeleteIoaRuleSummary(resources_affected=str(resources_affected)))
    soar.set_message(f"Deleted {resources_affected} rules")

    return DeleteIoaRuleOutput(**resp_json)
