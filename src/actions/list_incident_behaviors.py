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
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import CROWDSTRIKE_LIST_BEHAVIORS_ENDPOINT
from ..helper import validate_integer


class ListIncidentBehaviorsParams(Params):
    filter: str = Param(
        description="Optional filter and sort criteria in the form of an FQL query",
        required=False,
    )
    sort: str = Param(
        description="Sort the results by a specific field and direction. (Example: assigned_to.asc)",
        required=False,
        value_list=["--", "timestamp.asc", "timestamp.desc"],
    )
    offset: int = Param(
        description="Starting index of overall result set from which to return ids. (Defaults to 0)",
        required=False,
        default=0,
    )
    limit: int = Param(
        description="Limit the number of results to return. (Defaults to 50, Max 500)",
        required=False,
        default=50,
    )


class ListIncidentBehaviorsOutput(ActionOutput):
    resources: list[str]


class ListIncidentBehaviorsSummary(ActionOutput):
    total_incident_behaviors: int


@app.view_handler(template="crowdstrike_list_incident_behaviors.html")
def list_incident_behaviors_view(
    outputs: list[ListIncidentBehaviorsOutput],
) -> dict:
    data = [item for o in outputs for item in o.resources]
    return {"results": [{"data": data}]}


@app.action(
    description="Queries CrowdStrike for the behaviors of an incident",
    action_type="investigate",
    read_only=True,
    view_handler=list_incident_behaviors_view,
    summary_type=ListIncidentBehaviorsSummary,
)
def list_incident_behaviors(
    params: ListIncidentBehaviorsParams, soar: SOARClient, asset: Asset
) -> list[ListIncidentBehaviorsOutput]:
    client = get_client(asset)

    limit = validate_integer(params.limit, "limit")

    sort = params.sort
    if sort == "--":
        sort = None

    query_params: dict = {"limit": limit, "offset": params.offset}
    if params.filter:
        query_params["filter"] = params.filter
    if sort:
        query_params["sort"] = sort

    id_list = client.paginator(CROWDSTRIKE_LIST_BEHAVIORS_ENDPOINT, query_params)
    resources = [str(behavior_id) for behavior_id in id_list]

    output = ListIncidentBehaviorsOutput(resources=resources)

    soar.set_summary(
        ListIncidentBehaviorsSummary(total_incident_behaviors=len(resources))
    )
    soar.set_message(f"Total incident behaviors: {len(resources)}")
    return [output]
