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
    CROWDSTRIKE_EPP_ALERT_STATUSES,
    CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM,
    CROWDSTRIKE_UPDATE_ALERT_ENDPOINT,
)
from ..helper import validate_comma_separated_values


class UpdateEppAlertsParams(Params):
    alert_ids: str = Param(
        description="Comma-separated list of alert IDs (composite IDs)",
        required=True,
        primary=True,
        cef_types=["crowdstrike alert id"],
    )
    comment: str = Param(
        description="Comment to append to the alerts",
        required=False,
    )
    assigned_to_user: str = Param(
        description="User to assign the alerts to (email, UUID, or name)",
        required=False,
    )
    unassign: str = Param(
        description="Unassign the alerts",
        required=False,
    )
    show_in_ui: bool = Param(
        description="Whether the alerts should be displayed in the UI",
        required=False,
        default=True,
    )
    status: str = Param(
        description="Status to set the alerts to",
        required=False,
        value_list=CROWDSTRIKE_EPP_ALERT_STATUSES,
    )
    add_tags: str = Param(
        description="Comma-separated list of tags to add",
        required=False,
    )
    remove_tags: str = Param(
        description="Comma-separated list of tags to remove",
        required=False,
    )
    remove_tags_by_prefix: str = Param(
        description="Remove all tags matching the given prefix",
        required=False,
    )


class UpdateEppAlertsWrites(PermissiveActionOutput):
    resources_affected: int | None = OutputField(column_name="Alerts Affected")


class UpdateEppAlertsMeta(PermissiveActionOutput):
    writes: UpdateEppAlertsWrites


class UpdateEppAlertsOutput(PermissiveActionOutput):
    meta: UpdateEppAlertsMeta


class UpdateEppAlertsSummary(ActionOutput):
    alerts_affected: int


@app.action(
    description="Update the given EPP alerts",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=UpdateEppAlertsSummary,
)
def update_epp_alerts(
    params: UpdateEppAlertsParams, soar: SOARClient, asset: Asset
) -> list[UpdateEppAlertsOutput]:
    client = get_client(asset)

    composite_ids = validate_comma_separated_values(params.alert_ids)
    if not composite_ids:
        raise ValueError(CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM.format(key="alert_ids"))

    data: dict = {"composite_ids": composite_ids, "action_parameters": []}

    if params.show_in_ui is not None:
        data["action_parameters"].append(
            {"name": "show_in_ui", "value": str(params.show_in_ui).lower()}
        )

    if params.status:
        if params.status not in CROWDSTRIKE_EPP_ALERT_STATUSES:
            raise ValueError(
                CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM.format(key="status")
            )
        data["action_parameters"].append(
            {"name": "update_status", "value": params.status}
        )

    assigned_to_user = params.assigned_to_user
    if params.unassign:
        data["action_parameters"].append({"name": "unassign", "value": ""})
    elif assigned_to_user:
        if "@" in assigned_to_user:
            assign_action = "assign_to_user_id"
        elif len(assigned_to_user) == 36 and "-" in assigned_to_user:
            assign_action = "assign_to_uuid"
        else:
            assign_action = "assign_to_name"
        data["action_parameters"].append(
            {"name": assign_action, "value": assigned_to_user}
        )

    if params.add_tags:
        for tag in (tag.strip() for tag in params.add_tags.split(",")):
            if tag:
                data["action_parameters"].append({"name": "add_tag", "value": tag})

    if params.remove_tags:
        for tag in (tag.strip() for tag in params.remove_tags.split(",")):
            if tag:
                data["action_parameters"].append({"name": "remove_tag", "value": tag})

    if params.remove_tags_by_prefix:
        data["action_parameters"].append(
            {
                "name": "remove_tags_by_prefix",
                "value": params.remove_tags_by_prefix.strip(),
            }
        )

    if params.comment:
        data["action_parameters"].append(
            {"name": "append_comment", "value": params.comment}
        )

    response = client.make_rest_call(
        CROWDSTRIKE_UPDATE_ALERT_ENDPOINT,
        json_data=data,
        method="patch",
    )

    resources_affected = (
        response.get("meta", {}).get("writes", {}).get("resources_affected", 0)
    )
    if resources_affected != len(composite_ids):
        errors = [error.get("message") for error in response.get("errors", [])]
        raise ValueError(
            "Errors occurred while updating alerts: {}".format("\r\n".join(errors))
        )

    soar.set_summary(UpdateEppAlertsSummary(alerts_affected=resources_affected))
    soar.set_message(f"Alerts affected: {resources_affected}")
    return [UpdateEppAlertsOutput(**response)]
