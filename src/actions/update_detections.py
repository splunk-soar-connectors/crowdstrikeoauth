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
    CROWDSTRIKE_DETECTION_STATUSES,
    CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM,
    CROWDSTRIKE_RESOLVE_DETECTION_APIPATH,
)
from ..helper import validate_comma_separated_values


class UpdateDetectionsParams(Params):
    detection_ids: str = Param(
        description="Comma-separated list of detection IDs",
        required=True,
        primary=True,
        cef_types=["crowdstrike detection id"],
    )
    comment: str = Param(
        description="Comment to add to the detections",
        required=False,
    )
    assigned_to_user: str = Param(
        description="UUID of the user to assign the detections to",
        required=False,
    )
    show_in_ui: bool = Param(
        description="Whether the detections should be displayed in the UI",
        required=False,
        default=True,
    )
    status: str = Param(
        description="Status to set the detections to",
        required=False,
        value_list=CROWDSTRIKE_DETECTION_STATUSES,
    )


class UpdateDetectionsWrites(PermissiveActionOutput):
    resources_affected: int | None = OutputField(column_name="Detections Affected")


class UpdateDetectionsMeta(PermissiveActionOutput):
    writes: UpdateDetectionsWrites


class UpdateDetectionsOutput(PermissiveActionOutput):
    meta: UpdateDetectionsMeta


class UpdateDetectionsSummary(ActionOutput):
    detections_affected: int


@app.action(
    description="Update the given detections",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=UpdateDetectionsSummary,
)
def update_detections(
    params: UpdateDetectionsParams, soar: SOARClient, asset: Asset
) -> list[UpdateDetectionsOutput]:
    client = get_client(asset)

    ids = validate_comma_separated_values(params.detection_ids)
    if not ids:
        raise ValueError(
            CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM.format(key="detection_ids")
        )

    data: dict = {"ids": ids, "show_in_ui": params.show_in_ui}

    if params.assigned_to_user:
        data["assigned_to_uuid"] = params.assigned_to_user

    if params.comment:
        data["comment"] = params.comment

    if params.status:
        if params.status not in CROWDSTRIKE_DETECTION_STATUSES:
            raise ValueError(
                CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM.format(key="status")
            )
        data["status"] = params.status

    response = client.make_rest_call(
        CROWDSTRIKE_RESOLVE_DETECTION_APIPATH,
        json_data=data,
        method="patch",
    )

    resources_affected = (
        response.get("meta", {}).get("writes", {}).get("resources_affected", 0)
    )
    if resources_affected != len(ids):
        errors = [error.get("message") for error in response.get("errors", [])]
        raise ValueError(
            "Errors occurred while updating detections: {}".format("\r\n".join(errors))
        )

    soar.set_summary(UpdateDetectionsSummary(detections_affected=len(ids)))
    soar.set_message(f"Detections affected: {len(ids)}")
    return [UpdateDetectionsOutput(**response)]
