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
    CROWDSTRIKE_LIST_ALERT_DETAILS_ENDPOINT,
    CROWDSTRIKE_LIST_ALERTS_ENDPOINT,
)
from ..helper import validate_integer


class ListAlertsParams(Params):
    limit: int = Param(
        description="Maximum alerts to be fetched",
        required=False,
        default=100,
    )
    filter: str = Param(
        description="Filter expression used to limit the fetched alerts (FQL Syntax)",
        required=False,
    )
    sort: str = Param(
        description="Property to sort by",
        required=False,
    )
    include_hidden: bool = Param(
        description="Include hidden alerts",
        required=False,
        default=False,
    )


class ListAlertsOutput(PermissiveActionOutput):
    composite_id: str | None = OutputField(cef_types=["crowdstrike alert id"])
    name: str | None = OutputField(column_name="Name")
    status: str | None = OutputField(column_name="Status")
    created_timestamp: str | None = OutputField(column_name="Timestamp")


class ListAlertsSummary(ActionOutput):
    total_alerts: int


@app.action(
    description="Fetch the list of alerts",
    action_type="investigate",
    read_only=True,
    render_as="table",
    summary_type=ListAlertsSummary,
)
def list_alerts(
    params: ListAlertsParams, soar: SOARClient, asset: Asset
) -> list[ListAlertsOutput]:
    client = get_client(asset)

    limit = validate_integer(params.limit, "limit")

    sort = params.sort
    if sort == "--":
        sort = None

    query_params: dict = {"limit": limit, "include_hidden": params.include_hidden}
    if params.filter:
        query_params["filter"] = params.filter
    if sort:
        query_params["sort"] = sort

    id_list = client.paginator(CROWDSTRIKE_LIST_ALERTS_ENDPOINT, query_params)
    id_list = [str(alert_id) for alert_id in id_list]

    details: list = []
    ids = list(id_list)
    while ids:
        batch = ids[: min(100, len(ids))]
        response = client.make_rest_call(
            CROWDSTRIKE_LIST_ALERT_DETAILS_ENDPOINT,
            json_data={"composite_ids": batch},
            method="post",
        )
        if response.get("resources"):
            details.extend(response["resources"])
        del ids[: min(100, len(ids))]

    details_by_id = {data["composite_id"]: data for data in details}
    sorted_details: list = []
    for alert_id in id_list:
        data = details_by_id.get(alert_id)
        if data is not None and data not in sorted_details:
            sorted_details.append(data)

    outputs = [ListAlertsOutput(**data) for data in sorted_details]

    soar.set_summary(ListAlertsSummary(total_alerts=len(outputs)))
    soar.set_message(f"Total alerts: {len(outputs)}")
    return outputs
