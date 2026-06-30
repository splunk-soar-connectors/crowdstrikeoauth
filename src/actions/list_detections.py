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
    CROWDSTRIKE_LIST_DETECTIONS_DETAILS_ENDPOINT,
    CROWDSTRIKE_LIST_DETECTIONS_ENDPOINT,
)
from ..helper import validate_integer


class ListDetectionsParams(Params):
    limit: int = Param(
        description="Maximum detections to be fetched",
        required=False,
        default=100,
    )
    filter: str = Param(
        description="Filter expression used to limit the fetched detections (FQL Syntax)",
        required=False,
    )
    sort: str = Param(
        description="Property to sort by",
        required=False,
    )


class ListDetectionsOutput(PermissiveActionOutput):
    detection_id: str | None = OutputField(cef_types=["crowdstrike detection id"])
    status: str | None = None
    created_timestamp: str | None = None


class ListDetectionsSummary(ActionOutput):
    total_detections: int


@app.view_handler(template="crowdstrike_list_detections.html")
def list_detections_view(outputs: list[ListDetectionsOutput]) -> dict:
    return {"results": [{"data": [o.model_dump() for o in outputs]}]}


@app.action(
    description="Fetch the list of detections",
    action_type="investigate",
    read_only=True,
    view_handler=list_detections_view,
    summary_type=ListDetectionsSummary,
)
def list_detections(
    params: ListDetectionsParams, soar: SOARClient, asset: Asset
) -> list[ListDetectionsOutput]:
    client = get_client(asset)

    limit = validate_integer(params.limit, "limit")

    sort = params.sort
    if sort == "--":
        sort = None

    query_params: dict = {"limit": limit}
    if params.filter:
        query_params["filter"] = params.filter
    if sort:
        query_params["sort"] = sort

    id_list = client.paginator(CROWDSTRIKE_LIST_DETECTIONS_ENDPOINT, query_params)
    id_list = [str(detection_id) for detection_id in id_list]

    details: list = []
    ids = list(id_list)
    while ids:
        batch = ids[: min(100, len(ids))]
        response = client.make_rest_call(
            CROWDSTRIKE_LIST_DETECTIONS_DETAILS_ENDPOINT,
            json_data={"ids": batch},
            method="post",
        )
        if response.get("resources"):
            details.extend(response["resources"])
        del ids[: min(100, len(ids))]

    details_by_id = {data["detection_id"]: data for data in details}
    sorted_details: list = []
    for detection_id in id_list:
        data = details_by_id.get(detection_id)
        if data is not None and data not in sorted_details:
            sorted_details.append(data)

    outputs = [ListDetectionsOutput(**data) for data in sorted_details]

    soar.set_summary(ListDetectionsSummary(total_detections=len(outputs)))
    soar.set_message(f"Total detections: {len(outputs)}")
    return outputs
