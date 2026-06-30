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
    CROWDSTRIKE_GET_ALERT_DETAILS_ENDPOINT,
    CROWDSTRIKE_LIST_ALERTS_ENDPOINT,
)
from ..helper import validate_integer


class ListEppAlertsParams(Params):
    limit: int = Param(
        description="Maximum alerts to be fetched",
        required=False,
        default=50,
    )
    filter: str = Param(
        description="Filter expression used to limit the fetched alerts (FQL Syntax)",
        required=False,
    )
    sort: str = Param(
        description="Property to sort by",
        required=False,
    )


class ListEppAlertsOutput(PermissiveActionOutput):
    composite_id: str | None = OutputField(cef_types=["crowdstrike alert id"])
    status: str | None = None
    created_timestamp: str | None = None


class ListEppAlertsSummary(ActionOutput):
    total_alerts: int


@app.view_handler(template="crowdstrike_list_epp_alerts.html")
def list_epp_alerts_view(outputs: list[ListEppAlertsOutput]) -> dict:
    return {"results": [{"data": [o.model_dump() for o in outputs]}]}


@app.action(
    description="Fetch the list of EPP alerts",
    action_type="investigate",
    read_only=True,
    view_handler=list_epp_alerts_view,
    summary_type=ListEppAlertsSummary,
)
def list_epp_alerts(
    params: ListEppAlertsParams, soar: SOARClient, asset: Asset
) -> list[ListEppAlertsOutput]:
    client = get_client(asset)

    limit = validate_integer(params.limit, "limit")

    sort = params.sort
    if sort == "--":
        sort = None

    base_filter = "product:'epp'"
    query_filter = f"{base_filter}+{params.filter}" if params.filter else base_filter

    query_params: dict = {"limit": limit, "filter": query_filter}
    if sort:
        query_params["sort"] = sort

    composite_ids = client.paginator(CROWDSTRIKE_LIST_ALERTS_ENDPOINT, query_params)

    if not composite_ids:
        soar.set_summary(ListEppAlertsSummary(total_alerts=0))
        soar.set_message("No alerts found")
        return []

    all_alerts: list = []
    for i in range(0, len(composite_ids), 5000):
        batch = composite_ids[i : i + 5000]
        response = client.make_rest_call(
            CROWDSTRIKE_GET_ALERT_DETAILS_ENDPOINT,
            json_data={"composite_ids": batch},
            method="post",
        )
        all_alerts.extend(response.get("resources", []))

    outputs = [ListEppAlertsOutput(**data) for data in all_alerts]

    soar.set_summary(ListEppAlertsSummary(total_alerts=len(outputs)))
    return outputs
