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
    CROWDSTRIKE_GET_ROLE_ENDPOINT,
    CROWDSTRIKE_LIST_USER_ROLES_ENDPOINT,
)


class ListRolesParams(Params):
    pass


class ListRolesResource(PermissiveActionOutput):
    id: str | None = OutputField(column_name="ID")
    display_name: str | None = OutputField(column_name="Display Name")
    description: str | None = OutputField(column_name="Description")


class ListRolesOutput(ActionOutput):
    resources: list[ListRolesResource]


@app.action(
    description="Get the list of roles",
    action_type="investigate",
    read_only=True,
    render_as="table",
)
def list_roles(
    params: ListRolesParams, soar: SOARClient, asset: Asset
) -> list[ListRolesOutput]:
    client = get_client(asset)

    response = client.make_rest_call(CROWDSTRIKE_LIST_USER_ROLES_ENDPOINT)
    role_ids = response.get("resources", [])

    detail_response = client.make_rest_call(
        CROWDSTRIKE_GET_ROLE_ENDPOINT, params={"ids": role_ids}
    )

    resources = detail_response.get("resources", [])
    output = ListRolesOutput(
        resources=[ListRolesResource(**role) for role in resources]
    )

    soar.set_message("Roles listed successfully")
    return [output]
