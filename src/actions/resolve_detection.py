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
from soar_sdk.action_results import PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import CROWDSTRIKE_RESOLVE_DETECTION_APIPATH


class ResolveDetectionParams(Params):
    id: str = Param(
        description="Comma-separated list of detection IDs",
        required=True,
        primary=True,
        cef_types=["crowdstrike detection id"],
    )
    state: str = Param(
        description="State to set the detection(s) to",
        required=True,
        value_list=[
            "new",
            "in_progress",
            "true_positive",
            "false_positive",
            "ignored",
        ],
    )


class ResolveDetectionOutput(PermissiveActionOutput):
    pass


@app.view_handler(template="crowdstrike_set_status_view.html")
def resolve_detection_view(outputs: list[ResolveDetectionOutput]) -> dict:
    results = []
    for output in outputs:
        data = output.model_dump()
        param = {"id": data.pop("id", None)}
        message = data.pop("message", None)
        results.append({"data": [data], "param": param, "message": message})
    return {"results": results}


@app.action(
    name="set status",
    description="Set the state of detections to a new, in_progress, true_positive, false_positive, or ignored",
    action_type="generic",
    read_only=False,
    view_handler=resolve_detection_view,
)
def resolve_detection(
    params: ResolveDetectionParams, soar: SOARClient, asset: Asset
) -> ResolveDetectionOutput:
    client = get_client(asset)

    detection_id = [x.strip() for x in params.id.split(",") if x.strip()]

    api_data = {"ids": detection_id, "status": params.state}

    client.make_rest_call(
        CROWDSTRIKE_RESOLVE_DETECTION_APIPATH,
        json_data=api_data,
        method="patch",
    )

    soar.set_message("Status set successfully")

    return ResolveDetectionOutput(id=params.id, message="Status set successfully")
