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
    CROWDSTRIKE_GET_HOST_GROUP_DETAILS_ENDPOINT,
    CROWDSTRIKE_GET_HOST_GROUP_ID_ENDPOINT,
)
from ..helper import validate_integer


GROUP_SORT_VALUES = [
    "--",
    "created_by.asc",
    "created_by.desc",
    "created_timestamp.asc",
    "created_timestamp.desc",
    "group_type.asc",
    "group_type.desc",
    "modified_by.asc",
    "modified_by.desc",
    "modified_timestamp.asc",
    "modified_timestamp.desc",
    "name.asc",
    "name.desc",
]


class ListGroupsParams(Params):
    limit: int = Param(
        description="Maximum host groups to be fetched",
        required=False,
        default=50,
    )
    filter: str = Param(
        description="Filter expression used to limit the fetched host groups (FQL Syntax)",
        required=False,
    )
    sort: str = Param(
        description="Property to sort by",
        required=False,
        value_list=GROUP_SORT_VALUES,
    )


class ListGroupsOutput(PermissiveActionOutput):
    name: str | None = OutputField(column_name="Hostgroup Name")
    id: str | None = OutputField(
        cef_types=["crowdstrike host group id"],
        column_name="Hostgroup ID",
    )
    description: str | None = OutputField(column_name="Description")
    assignment_rule: str | None = None
    created_by: str | None = OutputField(cef_types=["email"])
    created_timestamp: str | None = None
    group_type: str | None = None
    modified_by: str | None = OutputField(cef_types=["email"])
    modified_timestamp: str | None = None


class ListGroupsSummary(ActionOutput):
    total_host_groups: int


@app.action(
    description="Fetch the details of the host groups",
    action_type="investigate",
    read_only=True,
    render_as="table",
    summary_type=ListGroupsSummary,
)
def list_groups(
    params: ListGroupsParams, soar: SOARClient, asset: Asset
) -> list[ListGroupsOutput]:
    client = get_client(asset)

    limit = validate_integer(params.limit, "limit")

    sort = params.sort
    if sort == "--":
        sort = None
    if sort and sort not in GROUP_SORT_VALUES:
        raise ValueError(CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM.format(key="sort"))

    query_params: dict = {"limit": limit}
    if params.filter:
        query_params["filter"] = params.filter
    if sort:
        query_params["sort"] = sort

    id_list = client.paginator(CROWDSTRIKE_GET_HOST_GROUP_ID_ENDPOINT, query_params)
    id_list = [str(group_id) for group_id in id_list]

    host_groups: list = []
    while id_list:
        batch = id_list[: min(100, len(id_list))]
        endpoint_param = "&".join(f"ids={group_id}" for group_id in batch)
        endpoint = f"{CROWDSTRIKE_GET_HOST_GROUP_DETAILS_ENDPOINT}?{endpoint_param}"

        response = client.make_rest_call(endpoint)
        if response.get("resources"):
            host_groups.extend(response["resources"])

        del id_list[: min(100, len(id_list))]

    outputs = [ListGroupsOutput(**group) for group in host_groups]

    soar.set_summary(ListGroupsSummary(total_host_groups=len(outputs)))
    soar.set_message(f"Total host groups: {len(outputs)}")
    return outputs
