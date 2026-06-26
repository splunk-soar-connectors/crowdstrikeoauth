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
    CROWDSTRIKE_GET_RTR_SESSION_DETAILS_ENDPOINT,
    CROWDSTRIKE_GET_RTR_SESSION_ID_ENDPOINT,
)
from ..helper import validate_integer


class ListSessionsParams(Params):
    limit: int = Param(
        description="Maximum sessions to be fetched",
        required=False,
        default=50,
    )
    filter: str = Param(
        description="Filter expression used to limit the fetched sessions (FQL Syntax)",
        required=False,
    )
    sort: str = Param(
        description="Property to sort by",
        required=False,
    )


class ListSessionsOutput(PermissiveActionOutput):
    id: str | None = OutputField(
        column_name="Session ID", cef_types=["crowdstrike rtr session id"]
    )
    hostname: str | None = OutputField(column_name="Hostname")
    created_at: str | None = OutputField(column_name="Created At")
    device_id: str | None = OutputField(
        column_name="Device ID", cef_types=["crowdstrike device id"]
    )


class ListSessionsSummary(ActionOutput):
    total_sessions: int


@app.action(
    description="Lists the active RTR sessions",
    action_type="investigate",
    read_only=True,
    render_as="table",
    summary_type=ListSessionsSummary,
)
def list_sessions(
    params: ListSessionsParams, soar: SOARClient, asset: Asset
) -> list[ListSessionsOutput]:
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

    id_list = client.paginator(CROWDSTRIKE_GET_RTR_SESSION_ID_ENDPOINT, query_params)
    id_list = [str(session_id) for session_id in id_list]

    details: list = []
    ids = list(id_list)
    while ids:
        batch = ids[: min(100, len(ids))]
        response = client.make_rest_call(
            CROWDSTRIKE_GET_RTR_SESSION_DETAILS_ENDPOINT,
            json_data={"ids": batch},
            method="post",
        )
        if response.get("resources"):
            details.extend(response["resources"])
        del ids[: min(100, len(ids))]

    details_by_id = {data["id"]: data for data in details if data.get("id")}
    sorted_details: list = []
    for session_id in id_list:
        data = details_by_id.get(session_id)
        if data is not None and data not in sorted_details:
            sorted_details.append(data)

    outputs = [ListSessionsOutput(**data) for data in sorted_details]

    soar.set_summary(ListSessionsSummary(total_sessions=len(outputs)))
    soar.set_message(f"Total sessions: {len(outputs)}")
    return outputs
