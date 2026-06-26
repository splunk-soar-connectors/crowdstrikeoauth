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
from ..consts import CROWDSTRIKE_IOA_QUERY_RULE_GROUPS_ENDPOINT


class ListIoaRuleGroupsParams(Params):
    fql_query: str = Param(
        description="FQL query to filter rule groups",
        required=False,
    )


class ListIoaRuleGroupsResource(PermissiveActionOutput):
    id: str | None = OutputField(cef_types=["crowdstrike ioa rule group id"])
    version: int | None = None
    enabled: bool | None = None
    name: str | None = None
    description: str | None = None
    platform: str | None = None
    comment: str | None = None


class ListIoaRuleGroupsOutput(ActionOutput):
    resources: list[ListIoaRuleGroupsResource]


class ListIoaRuleGroupsSummary(ActionOutput):
    result_count: int


@app.view_handler(template="crowdstrike_list_ioa_rule_groups.html")
def list_ioa_rule_groups_view(outputs: list[ListIoaRuleGroupsOutput]) -> dict:
    return {"results": [{"data": [o.model_dump() for o in outputs]}]}


@app.action(
    description="Get the configured IOA rule groups",
    action_type="investigate",
    read_only=True,
    view_handler=list_ioa_rule_groups_view,
    summary_type=ListIoaRuleGroupsSummary,
)
def list_ioa_rule_groups(
    params: ListIoaRuleGroupsParams, soar: SOARClient, asset: Asset
) -> list[ListIoaRuleGroupsOutput]:
    client = get_client(asset)

    query_params: dict = {}
    if params.fql_query:
        query_params["filter"] = params.fql_query.replace(" ", "")

    resources = client.paginator(
        CROWDSTRIKE_IOA_QUERY_RULE_GROUPS_ENDPOINT, query_params
    )

    output = ListIoaRuleGroupsOutput(
        resources=[ListIoaRuleGroupsResource(**r) for r in resources]
    )

    soar.set_summary(ListIoaRuleGroupsSummary(result_count=len(resources)))
    soar.set_message(f"Result count: {len(resources)}")
    return [output]
