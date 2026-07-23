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
    CROWDSTRIKE_RTR_ADMIN_GET_PUT_FILES,
    CROWDSTRIKE_RTR_ADMIN_PUT_FILES,
)
from ..helper import validate_integer


class ListPutFilesParams(Params):
    filter: str = Param(
        description="FQL query to filter results",
        required=False,
    )
    sort: str = Param(
        description="Sort results",
        required=False,
    )
    offset: str = Param(
        description="Starting index of overall result set",
        required=False,
    )
    limit: int = Param(
        description="Number of files to return",
        required=False,
        default=50,
    )


class ListPutFilesOutput(PermissiveActionOutput):
    name: str | None = OutputField(column_name="File Name")
    description: str | None = OutputField(column_name="Description")
    file_type: str | None = OutputField(column_name="Type")
    size: int | None = OutputField(column_name="File Size")


class ListPutFilesSummary(ActionOutput):
    total_files: int


@app.action(
    description=(
        "Queries for files uploaded to Crowdstrike for use with the RTR `put` command"
    ),
    action_type="investigate",
    read_only=True,
    render_as="table",
    summary_type=ListPutFilesSummary,
)
def list_put_files(
    params: ListPutFilesParams, soar: SOARClient, asset: Asset
) -> list[ListPutFilesOutput]:
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
    if params.offset:
        query_params["offset"] = params.offset

    id_list = client.paginator(CROWDSTRIKE_RTR_ADMIN_GET_PUT_FILES, query_params)
    id_list = [str(put_file_id) for put_file_id in id_list]

    details: list = []
    ids = list(id_list)
    while ids:
        batch = ids[: min(100, len(ids))]
        response = client.make_rest_call(
            CROWDSTRIKE_RTR_ADMIN_PUT_FILES,
            json_data={"ids": batch},
            method="get",
        )
        if response.get("resources"):
            details.extend(response["resources"])
        del ids[: min(100, len(ids))]

    details_by_id = {data["id"]: data for data in details if data.get("id")}
    sorted_details: list = []
    for put_file_id in id_list:
        data = details_by_id.get(put_file_id)
        if data is not None and data not in sorted_details:
            sorted_details.append(data)

    outputs = [ListPutFilesOutput(**data) for data in sorted_details]

    soar.set_summary(ListPutFilesSummary(total_files=len(outputs)))
    soar.set_message(f"Total files: {len(outputs)}")
    return outputs
