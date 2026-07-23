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
    CROWDSTRIKE_GET_ALERT_DETAILS_ENDPOINT,
)
from ..helper import validate_comma_separated_values


class GetEppAlertsDetailsParams(Params):
    alert_ids: str = Param(
        description="Comma-separated list of alert IDs (composite IDs)",
        required=True,
        primary=True,
        cef_types=["crowdstrike alert id"],
    )


class GetEppAlertsDetailsOutput(PermissiveActionOutput):
    composite_id: str | None = OutputField(cef_types=["crowdstrike alert id"])
    status: str | None = None
    severity: str | None = None
    created_timestamp: str | None = None


class GetEppAlertsDetailsSummary(ActionOutput):
    total_alerts: int


@app.view_handler(template="crowdstrike_get_alerts_details.html")
def get_epp_alerts_details_view(outputs: list[GetEppAlertsDetailsOutput]) -> dict:
    return {"results": [{"data": [o.model_dump() for o in outputs]}]}


@app.action(
    name="get epp details",
    description="Get details for the given EPP alerts",
    action_type="investigate",
    read_only=True,
    view_handler=get_epp_alerts_details_view,
    summary_type=GetEppAlertsDetailsSummary,
)
def get_epp_alerts_details(
    params: GetEppAlertsDetailsParams, soar: SOARClient, asset: Asset
) -> list[GetEppAlertsDetailsOutput]:
    client = get_client(asset)

    composite_ids = validate_comma_separated_values(params.alert_ids)
    if not composite_ids:
        raise ValueError(CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM.format(key="alert_ids"))

    response = client.make_rest_call(
        CROWDSTRIKE_GET_ALERT_DETAILS_ENDPOINT,
        json_data={"composite_ids": composite_ids},
        method="post",
    )

    alert_details_list = response.get("resources", [])
    outputs = [GetEppAlertsDetailsOutput(**data) for data in alert_details_list]

    soar.set_summary(GetEppAlertsDetailsSummary(total_alerts=len(outputs)))
    soar.set_message(f"Total alerts: {len(outputs)}")
    return outputs
