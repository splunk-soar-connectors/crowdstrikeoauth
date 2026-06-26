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
from ..consts import (
    CROWDSTRIKE_GET_ROLE_ENDPOINT,
    CROWDSTRIKE_STATUS_CODE_MESSAGE,
)


class GetRoleParams(Params):
    role_id: str = Param(
        description="Role ID to get information about. Comma separated list allowed",
        required=True,
        primary=True,
        cef_types=["crowdstrike user role id"],
    )


class GetRoleOutput(PermissiveActionOutput):
    id: str | None = OutputField(column_name="ID")
    display_name: str | None = OutputField(column_name="Display Name")
    description: str | None = OutputField(column_name="Description")


@app.action(
    description="Get information about a specific role",
    action_type="investigate",
    read_only=True,
    render_as="table",
)
def get_role(
    params: GetRoleParams, soar: SOARClient, asset: Asset
) -> list[GetRoleOutput]:
    client = get_client(asset)

    role_ids = [x.strip() for x in params.role_id.split(",") if x.strip()]

    resources = client.paginate_get_endpoint(
        role_ids, CROWDSTRIKE_GET_ROLE_ENDPOINT, CROWDSTRIKE_STATUS_CODE_MESSAGE
    )

    outputs = [GetRoleOutput(**role) for role in resources]

    if not outputs:
        soar.set_message("No data found")
    else:
        soar.set_message("Role fetched successfully")
    return outputs
