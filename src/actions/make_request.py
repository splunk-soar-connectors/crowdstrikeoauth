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

import requests
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import MakeRequestParams, Param

from ..app import Asset, app
from ..consts import CROWDSTRIKE_DEFAULT_TIMEOUT
from ..helper import CrowdStrikeClient


logger = getLogger()


class CrowdStrikeMakeRequestParams(MakeRequestParams):
    endpoint: str = Param(
        description=(
            "CrowdStrike API endpoint to call, appended to the asset base URL. "
            "Example: '/devices/queries/devices/v1'"
        ),
        required=True,
    )
    verify_ssl: bool = Param(
        description="Whether to verify the SSL certificate.",
        required=False,
        default=True,
    )


class CrowdStrikeMakeRequestOutput(ActionOutput):
    status_code: int = OutputField(example_values=[200])
    response_body: str = OutputField(example_values=['{"resources": [], "errors": []}'])

    @classmethod
    def from_response(
        cls, response: requests.Response
    ) -> "CrowdStrikeMakeRequestOutput":
        return cls(status_code=response.status_code, response_body=response.text)


@app.make_request()
def http_action(
    params: CrowdStrikeMakeRequestParams, asset: Asset
) -> CrowdStrikeMakeRequestOutput:
    if params.endpoint.startswith(("http://", "https://")):
        raise ActionFailure(
            f"Invalid endpoint: {params.endpoint}. Do not include the base URL — "
            "it is derived from the asset configuration."
        )

    client = CrowdStrikeClient(asset)

    endpoint = (
        params.endpoint if params.endpoint.startswith("/") else f"/{params.endpoint}"
    )
    url = f"{client._base_url}{endpoint}"

    access_token = client.access_token()
    headers: dict = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    if params.headers:
        try:
            headers.update(json.loads(params.headers))
        except (json.JSONDecodeError, TypeError) as e:
            raise ActionFailure(f"Invalid JSON headers: {params.headers}") from e

    query_params = None
    if params.query_parameters:
        try:
            query_params = json.loads(params.query_parameters)
        except (json.JSONDecodeError, TypeError):
            query_string = params.query_parameters.lstrip("?")
            url = f"{url}?{query_string}" if "?" not in url else f"{url}&{query_string}"

    body = None
    json_body = None
    if params.body:
        content_type = headers.get("Content-Type", "").lower()
        if "json" in content_type:
            try:
                json_body = json.loads(params.body)
            except (json.JSONDecodeError, TypeError) as e:
                raise ActionFailure(f"Invalid JSON body: {params.body}") from e
        else:
            body = params.body

    timeout = params.timeout or CROWDSTRIKE_DEFAULT_TIMEOUT

    try:
        response = requests.request(
            method=params.http_method,
            url=url,
            headers=headers,
            params=query_params,
            data=body,
            json=json_body,
            timeout=timeout,
            verify=params.verify_ssl,
        )
    except Exception as e:
        raise ActionFailure(f"Request failed: {e}") from e

    return CrowdStrikeMakeRequestOutput.from_response(response)
