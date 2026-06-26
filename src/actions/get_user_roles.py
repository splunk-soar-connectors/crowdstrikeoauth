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
from soar_sdk.action_results import OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import CROWDSTRIKE_GET_USER_ROLES_ENDPOINT


class GetUserRolesParams(Params):
    user_uuid: str = Param(
        description="Users Unqiue ID to get the roles for",
        required=True,
        primary=True,
        cef_types=["crowdstrike unique user id"],
    )


class GetUserRolesOutput(PermissiveActionOutput):
    cid: str | None = None
    grant_type: str | None = None
    role_id: str | None = OutputField(cef_types=["crowdstrike user role id"])
    role_name: str | None = None
    uuid: str | None = OutputField(cef_types=["crowdstrike unique user id"])


@app.view_handler(template="crowdstrike_get_user_roles.html")
def get_user_roles_view(outputs: list[GetUserRolesOutput]) -> dict:
    return {"results": [{"data": [o.model_dump() for o in outputs]}]}


@app.action(
    description="Get user roles",
    action_type="investigate",
    read_only=True,
    view_handler=get_user_roles_view,
)
def get_user_roles(
    params: GetUserRolesParams, soar: SOARClient, asset: Asset
) -> list[GetUserRolesOutput]:
    client = get_client(asset)

    user_role_list = client.paginator(
        CROWDSTRIKE_GET_USER_ROLES_ENDPOINT, {"user_uuid": params.user_uuid}
    )

    outputs = [GetUserRolesOutput(**role) for role in user_role_list]

    soar.set_message("User roles fetched successfully")
    return outputs
