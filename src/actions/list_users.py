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
from soar_sdk.params import Params

from ..app import Asset, app, get_client
from ..consts import (
    CROWDSTRIKE_GET_USER_INFO_ENDPOINT,
    CROWDSTRIKE_LIST_USERS_UIDS_ENDPOINT,
)


class ListUsersParams(Params):
    pass


class ListUsersResource(PermissiveActionOutput):
    first_name: str | None = OutputField(column_name="First Name")
    last_name: str | None = OutputField(column_name="Last Name")
    uid: str | None = OutputField(
        cef_types=["crowdstrike user id"], column_name="User ID"
    )
    uuid: str | None = OutputField(
        cef_types=["crowdstrike unique user id"], column_name="Unique User ID"
    )
    cid: str | None = OutputField(
        cef_types=["crowdstrike customer id"], column_name="Customer ID"
    )


class ListUsersOutput(ActionOutput):
    resources: list[ListUsersResource]


class ListUsersSummary(ActionOutput):
    total_users: int


@app.view_handler(template="crowdstrike_list_users.html")
def list_users_view(outputs: list[ListUsersOutput]) -> dict:
    return {"results": [{"data": [o.model_dump() for o in outputs]}]}


@app.action(
    description="Gets the list of users",
    action_type="investigate",
    read_only=True,
    view_handler=list_users_view,
    summary_type=ListUsersSummary,
)
def list_users(
    params: ListUsersParams, soar: SOARClient, asset: Asset
) -> list[ListUsersOutput]:
    client = get_client(asset)

    ids = client.paginator(CROWDSTRIKE_LIST_USERS_UIDS_ENDPOINT)
    if not ids:
        soar.set_message("No data found for user resources")
        return []

    response = client.make_rest_call(
        CROWDSTRIKE_GET_USER_INFO_ENDPOINT,
        json_data={"ids": ids},
        method="post",
    )
    resources = response.get("resources", [])

    output = ListUsersOutput(
        resources=[ListUsersResource(**user) for user in resources]
    )

    soar.set_summary(ListUsersSummary(total_users=len(resources)))
    soar.set_message("Users listed successfully")
    return [output]
