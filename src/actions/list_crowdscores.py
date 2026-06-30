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
from ..consts import CROWDSTRIKE_LIST_CROWDSCORES_ENDPOINT
from ..helper import validate_integer


class ListCrowdscoresParams(Params):
    filter: str = Param(
        description="Optional filter and sort criteria in the form of an FQL query",
        required=False,
    )
    sort: str = Param(
        description="Sort the results by a specific field and direction. (Example: assigned_to.asc)",
        required=False,
        value_list=["--", "score.asc", "score.desc", "timestamp.asc", "timestamp.desc"],
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


class ListCrowdscoresOutput(PermissiveActionOutput):
    id: str | None = OutputField(
        cef_types=["crowdstrike crowdscore id"], column_name="Incident ID"
    )
    score: int | None = OutputField(column_name="Score")
    timestamp: str | None = OutputField(column_name="Timestamp")


class ListCrowdscoresSummary(ActionOutput):
    total_crowdscores: int


@app.action(
    description="Queries CrowdStrike for the CrowdScores of incidents",
    action_type="investigate",
    read_only=True,
    render_as="table",
    summary_type=ListCrowdscoresSummary,
)
def list_crowdscores(
    params: ListCrowdscoresParams, soar: SOARClient, asset: Asset
) -> list[ListCrowdscoresOutput]:
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

    crowdscores = client.paginator(CROWDSTRIKE_LIST_CROWDSCORES_ENDPOINT, query_params)

    outputs = [ListCrowdscoresOutput(**data) for data in crowdscores]

    soar.set_summary(ListCrowdscoresSummary(total_crowdscores=len(outputs)))
    soar.set_message(f"Total crowdscores: {len(outputs)}")
    return outputs
