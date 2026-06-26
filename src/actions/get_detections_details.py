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
    CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM,
    CROWDSTRIKE_LIST_DETECTIONS_DETAILS_ENDPOINT,
)
from ..helper import validate_comma_separated_values


class GetDetectionsDetailsParams(Params):
    detection_ids: str = Param(
        description="Comma-separated list of detection IDs",
        required=True,
        primary=True,
        cef_types=["crowdstrike detection id"],
    )


class GetDetectionsDetailsOutput(PermissiveActionOutput):
    detection_id: str | None = OutputField(cef_types=["crowdstrike detection id"])
    status: str | None = None
    created_timestamp: str | None = None


class GetDetectionsDetailsSummary(ActionOutput):
    total_detections: int


@app.view_handler(template="crowdstrike_get_detections_details.html")
def get_detections_details_view(outputs: list[GetDetectionsDetailsOutput]) -> dict:
    return {"results": [{"data": [o.model_dump() for o in outputs]}]}


@app.action(
    description="Get details for the given detections",
    action_type="investigate",
    read_only=True,
    view_handler=get_detections_details_view,
    summary_type=GetDetectionsDetailsSummary,
)
def get_detections_details(
    params: GetDetectionsDetailsParams, soar: SOARClient, asset: Asset
) -> list[GetDetectionsDetailsOutput]:
    client = get_client(asset)

    ids = validate_comma_separated_values(params.detection_ids)
    if not ids:
        raise ValueError(
            CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM.format(key="detection_ids")
        )

    details: list = []
    list_ids = list(ids)
    while list_ids:
        batch = list_ids[: min(100, len(list_ids))]
        response = client.make_rest_call(
            CROWDSTRIKE_LIST_DETECTIONS_DETAILS_ENDPOINT,
            json_data={"ids": batch},
            method="post",
        )
        if response.get("resources"):
            details.extend(response["resources"])
        del list_ids[: min(100, len(list_ids))]

    outputs = [GetDetectionsDetailsOutput(**data) for data in details]

    soar.set_summary(GetDetectionsDetailsSummary(total_detections=len(outputs)))
    soar.set_message(f"Total detections: {len(outputs)}")
    return outputs
