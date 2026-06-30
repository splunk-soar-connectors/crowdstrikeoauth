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
from ..consts import CROWDSTRIKE_LIST_INCIDENTS_ENDPOINT
from ..helper import validate_integer


CROWDSTRIKE_LIST_INCIDENTS_SORT_VALUES = [
    "--",
    "assigned_to.asc",
    "assigned_to.desc",
    "assigned_to_name.asc",
    "assigned_to_name.desc",
    "end.asc",
    "end.desc",
    "modified_timestamp.asc",
    "modified_timestamp.desc",
    "name.asc",
    "name.desc",
    "sort_score.asc",
    "sort_score.desc",
    "start.asc",
    "start.desc",
    "state.asc",
    "state.desc",
    "status.asc",
    "status.desc",
]


class ListIncidentsParams(Params):
    filter: str = Param(
        description="Optional filter and sort criteria in the form of an FQL query",
        required=False,
    )
    sort: str = Param(
        description="Sort the results by a specific field and direction. (Example: assigned_to.asc)",
        required=False,
        value_list=CROWDSTRIKE_LIST_INCIDENTS_SORT_VALUES,
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


class ListIncidentsOutput(ActionOutput):
    resources: list[str]


class ListIncidentsSummary(ActionOutput):
    total_incidents: int


@app.view_handler(template="crowdstrike_list_incidents.html")
def list_incidents_view(outputs: list[ListIncidentsOutput]) -> dict:
    data = [item for o in outputs for item in o.resources]
    return {"results": [{"data": data}]}


@app.action(
    description="Queries CrowdStrike for the list of incidents",
    action_type="investigate",
    read_only=True,
    view_handler=list_incidents_view,
    summary_type=ListIncidentsSummary,
)
def list_incidents(
    params: ListIncidentsParams, soar: SOARClient, asset: Asset
) -> list[ListIncidentsOutput]:
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

    id_list = client.paginator(CROWDSTRIKE_LIST_INCIDENTS_ENDPOINT, query_params)
    resources = [str(incident_id) for incident_id in id_list]

    output = ListIncidentsOutput(resources=resources)

    soar.set_summary(ListIncidentsSummary(total_incidents=len(resources)))
    soar.set_message(f"Total incidents: {len(resources)}")
    return [output]
