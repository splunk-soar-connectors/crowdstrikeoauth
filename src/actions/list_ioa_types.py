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

import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import (
    CROWDSTRIKE_IOA_GET_TYPE_ENDPOINT,
    CROWDSTRIKE_IOA_LIST_TYPES_ENDPOINT,
)


class ListIoaTypesParams(Params):
    platform: str = Param(
        description="Show only IOA types supported by the given platform",
        required=False,
    )


class ListIoaTypesResource(PermissiveActionOutput):
    id: str | None = None
    name: str | None = None
    platform: str | None = None
    long_desc: str | None = None
    fields_pretty: str | None = None


class ListIoaTypesOutput(ActionOutput):
    resources: list[ListIoaTypesResource]


class ListIoaTypesSummary(ActionOutput):
    result_count: int


@app.view_handler(template="crowdstrike_list_ioa_types.html")
def list_ioa_types_view(outputs: list[ListIoaTypesOutput]) -> dict:
    return {"results": [{"data": [o.model_dump() for o in outputs]}]}


@app.action(
    description="Get the IOA types and their parameters",
    action_type="investigate",
    read_only=True,
    view_handler=list_ioa_types_view,
    summary_type=ListIoaTypesSummary,
)
def list_ioa_types(
    params: ListIoaTypesParams, soar: SOARClient, asset: Asset
) -> list[ListIoaTypesOutput]:
    client = get_client(asset)

    type_ids = client.paginator(CROWDSTRIKE_IOA_LIST_TYPES_ENDPOINT)

    resources: list = []
    if type_ids:
        response = client.make_rest_call(
            CROWDSTRIKE_IOA_GET_TYPE_ENDPOINT, params={"ids": type_ids}
        )
        for resource in response.get("resources", []):
            resource["fields_pretty"] = json.dumps(resource.get("fields"), indent=2)
            if params.platform and resource.get("platform") != params.platform:
                continue
            resources.append(resource)

    output = ListIoaTypesOutput(
        resources=[ListIoaTypesResource(**r) for r in resources]
    )

    soar.set_summary(ListIoaTypesSummary(result_count=len(resources)))
    soar.set_message(f"Result count: {len(resources)}")
    return [output]
