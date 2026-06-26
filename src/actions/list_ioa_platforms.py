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
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Params

from ..app import Asset, app, get_client
from ..consts import CROWDSTRIKE_IOA_LIST_PLATFORMS_ENDPOINT


class ListIoaPlatformsParams(Params):
    pass


class ListIoaPlatformsOutput(ActionOutput):
    resources: list[str]


class ListIoaPlatformsSummary(ActionOutput):
    result_count: int


@app.view_handler(template="crowdstrike_list_ioa_platforms.html")
def list_ioa_platforms_view(outputs: list[ListIoaPlatformsOutput]) -> dict:
    return {"results": [{"data": [o.model_dump() for o in outputs]}]}


@app.action(
    description="Get the platforms that support IOA rules",
    action_type="investigate",
    read_only=True,
    view_handler=list_ioa_platforms_view,
    summary_type=ListIoaPlatformsSummary,
)
def list_ioa_platforms(
    params: ListIoaPlatformsParams, soar: SOARClient, asset: Asset
) -> list[ListIoaPlatformsOutput]:
    client = get_client(asset)

    resources = client.paginator(CROWDSTRIKE_IOA_LIST_PLATFORMS_ENDPOINT)

    output = ListIoaPlatformsOutput(resources=resources)

    soar.set_summary(ListIoaPlatformsSummary(result_count=len(resources)))
    soar.set_message(f"Result count: {len(resources)}")
    return [output]
