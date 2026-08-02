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

import re
from urllib.parse import urlsplit

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import CROWDSTRIKE_INVALID_QUERY_ENDPOINT_MESSAGE_ERROR


_QUERY_ENDPOINT_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")


def _validate_query_endpoint(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    segments = parsed.path.split("/")
    valid_segments = (
        len(segments) == 5
        and segments[0] == ""
        and segments[2].lower() == "queries"
        and all(
            segment not in {".", ".."} and _QUERY_ENDPOINT_SEGMENT.fullmatch(segment)
            for segment in (segments[1], segments[3], segments[4])
        )
    )
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or not valid_segments
    ):
        raise ValueError(CROWDSTRIKE_INVALID_QUERY_ENDPOINT_MESSAGE_ERROR)
    return endpoint


class RunQueryParams(Params):
    endpoint: str = Param(
        description=(
            "API endpoint path in the format: /<service>/queries/<resource>/<version> "
            "(ex: /devices/queries/devices/v1)"
        ),
        required=True,
    )
    limit: int = Param(
        description="Maximum number of results to return",
        required=False,
        default=50,
    )
    filter: str = Param(
        description="Filter expression (FQL Syntax) (ex: last_seen: >'2020-01-01')",
        required=False,
    )
    sort: str = Param(
        description="Property to sort by",
        required=False,
    )
    offset: int = Param(
        description="Starting index for results",
        required=False,
        default=0,
    )


class RunQueryOutput(ActionOutput):
    resource_id: str = OutputField(column_name="Resource ID")


class RunQuerySummary(ActionOutput):
    total_objects: int
    total_count: int
    query_time: float
    powered_by: str
    trace_id: str


@app.action(
    description="Run a generic query against a CrowdStrike API query endpoint",
    action_type="investigate",
    read_only=True,
    render_as="table",
    summary_type=RunQuerySummary,
)
def run_query(
    params: RunQueryParams, soar: SOARClient, asset: Asset
) -> list[RunQueryOutput]:
    client = get_client(asset)

    endpoint = params.endpoint
    if not endpoint:
        raise ValueError("Please provide endpoint path")

    endpoint = _validate_query_endpoint(endpoint)

    query_params: dict = {"limit": params.limit, "offset": params.offset}
    if params.filter:
        query_params["filter"] = params.filter
    if params.sort:
        query_params["sort"] = params.sort

    response = client.make_rest_call(endpoint, params=query_params)

    resources = response.get("resources", [])
    outputs = [RunQueryOutput(resource_id=resource) for resource in resources]

    meta = response.get("meta", {})
    pagination = meta.get("pagination", {})

    soar.set_summary(
        RunQuerySummary(
            total_objects=len(resources),
            total_count=pagination.get("total", 0),
            query_time=meta.get("query_time", 0),
            powered_by=meta.get("powered_by", ""),
            trace_id=meta.get("trace_id", ""),
        )
    )
    soar.set_message("Query completed successfully")
    return outputs
