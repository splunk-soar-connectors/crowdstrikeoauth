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
    CROWDSTRIKE_GET_DEVICE_DETAILS_ENDPOINT,
    CROWDSTRIKE_GET_DEVICE_ID_ENDPOINT,
)
from ..helper import validate_integer


QUERY_DEVICE_MAX_LIMIT = 5000


class QueryDeviceParams(Params):
    limit: int = Param(
        description="Maximum devices to be fetched",
        required=False,
        default=50,
    )
    offset: int = Param(
        description="Starting index of overall result set from which to return ids. (Defaults to 0)",
        required=False,
        default=0,
    )
    filter: str = Param(
        description="Filter expression used to limit the fetched devices (FQL Syntax)",
        required=False,
    )
    sort: str = Param(
        description="Property to sort by",
        required=False,
    )
    cid: str = Param(
        description=(
            "A single, specific tenant id to search. By default, will search asset main tenant "
            "and all listed subtenants; to search only main tenant (even if you have subtenants) use 'main'"
        ),
        required=False,
    )


class QueryDeviceOutput(PermissiveActionOutput):
    hostname: str | None = OutputField(cef_types=["host name"], column_name="Hostname")
    device_id: str | None = OutputField(
        cef_types=["crowdstrike device id"], column_name="Device ID"
    )
    status: str | None = OutputField(column_name="Status")


class QueryDeviceSummary(ActionOutput):
    total_devices: int


@app.action(
    description="Fetch the list of devices",
    action_type="investigate",
    read_only=True,
    render_as="table",
    summary_type=QueryDeviceSummary,
)
def query_device(
    params: QueryDeviceParams, soar: SOARClient, asset: Asset
) -> list[QueryDeviceOutput]:
    client = get_client(asset)

    limit = validate_integer(params.limit, "limit")
    if limit is not None and limit > QUERY_DEVICE_MAX_LIMIT:
        limit = QUERY_DEVICE_MAX_LIMIT

    sort = params.sort
    if sort == "--":
        sort = None

    query_params: dict = {"limit": limit, "offset": params.offset}
    if params.filter:
        query_params["filter"] = params.filter
    if sort:
        query_params["sort"] = sort

    subtenant = params.cid or None

    id_tenant_map = client.get_ids_with_subtenants(
        CROWDSTRIKE_GET_DEVICE_ID_ENDPOINT, query_params, subtenant=subtenant
    )

    if isinstance(id_tenant_map, dict):
        tenant_id_groups: dict = {}
        for device_id, tenant in id_tenant_map.items():
            tenant_id_groups.setdefault(tenant, []).append(device_id)
    else:
        tenant_id_groups = {subtenant: list(id_tenant_map)}

    devices: list = []
    for tenant, device_ids in tenant_id_groups.items():
        ids = list(device_ids)
        while ids:
            batch = ids[: min(100, len(ids))]
            response = client.make_rest_call(
                CROWDSTRIKE_GET_DEVICE_DETAILS_ENDPOINT,
                json_data={"ids": batch},
                subtenant=tenant,
            )
            if response.get("resources"):
                devices.extend(response["resources"])
            del ids[: min(100, len(ids))]

    outputs = [QueryDeviceOutput(**device) for device in devices]

    soar.set_summary(QueryDeviceSummary(total_devices=len(outputs)))
    soar.set_message(f"Total devices: {len(outputs)}")
    return outputs
