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
from soar_sdk.action_results import PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import CROWDSTRIKE_UPDATE_INCIDENT_ENDPOINT


CROWDSTRIKE_UPDATE_INCIDENT_STATUSES = {
    "new": 20,
    "reopened": 25,
    "in progress": 30,
    "closed": 40,
}


class UpdateIncidentParams(Params):
    ids: str = Param(
        description="List of incident IDs. Comma separated list allowed",
        required=True,
        primary=True,
        cef_types=["crowdstrike incident id"],
        column_name="Ids",
    )
    add_tag: str = Param(
        description="Adds the associated tag to all the incident(s) of the ids list. See example values for the defined list",
        required=False,
    )
    delete_tag: str = Param(
        description="Deletes the matching tag from all the incident(s) in the ids list. See example values for the defined list",
        required=False,
    )
    update_name: str = Param(
        description="Updates the name of all the incident(s) in the ids list",
        required=False,
    )
    update_description: str = Param(
        description="Updates the description of all the incident(s) listed in the ids",
        required=False,
    )
    update_status: str = Param(
        description="Updates the status of all the incident(s) in the ids list",
        required=False,
        value_list=["New", "Reopened", "In Progress", "Closed"],
    )
    add_comment: str = Param(
        description="Adds a comment for all the incident(s) in the ids list",
        required=False,
    )


class UpdateIncidentMeta(PermissiveActionOutput):
    powered_by: str | None = None
    query_time: float | None = None
    trace_id: str | None = None


class UpdateIncidentOutput(PermissiveActionOutput):
    meta: UpdateIncidentMeta | None = None


@app.action(
    description="Update incident",
    action_type="generic",
    read_only=False,
    render_as="table",
)
def update_incident(
    params: UpdateIncidentParams, soar: SOARClient, asset: Asset
) -> list[UpdateIncidentOutput]:
    client = get_client(asset)

    ids = [x.strip() for x in params.ids.split(",")]
    ids = list(filter(None, ids))

    data: dict = {"action_parameters": [], "ids": ids}

    if params.add_tag:
        for tag in filter(None, (x.strip() for x in params.add_tag.split(","))):
            data["action_parameters"].append({"name": "add_tag", "value": tag})

    if params.delete_tag:
        for tag in filter(None, (x.strip() for x in params.delete_tag.split(","))):
            data["action_parameters"].append({"name": "delete_tag", "value": tag})

    if params.update_name:
        data["action_parameters"].append(
            {"name": "update_name", "value": params.update_name}
        )

    if params.update_description:
        data["action_parameters"].append(
            {"name": "update_description", "value": params.update_description}
        )

    if params.update_status:
        status = params.update_status.lower()
        data["action_parameters"].append(
            {
                "name": "update_status",
                "value": str(CROWDSTRIKE_UPDATE_INCIDENT_STATUSES[status]),
            }
        )

    if params.add_comment:
        data["action_parameters"].append(
            {"name": "add_comment", "value": params.add_comment}
        )

    resp_json = client.make_rest_call(
        CROWDSTRIKE_UPDATE_INCIDENT_ENDPOINT, json_data=data, method="post"
    )

    soar.set_message("Incident updated successfully")
    return [UpdateIncidentOutput(**resp_json)]
