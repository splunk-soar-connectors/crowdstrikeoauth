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


class ResolveEppAlertsParams(Params):
    alert_ids: str = Param(
        description="Comma-separated list of alert IDs (composite IDs)",
        required=True,
        primary=True,
        cef_types=["crowdstrike alert id"],
    )
    status: str = Param(
        description="Status to set the alerts to",
        required=True,
        value_list=CROWDSTRIKE_EPP_ALERT_STATUSES,
    )


class ResolveEppAlertsWrites(PermissiveActionOutput):
    resources_affected: int | None = OutputField(column_name="Alerts Affected")


class ResolveEppAlertsMeta(PermissiveActionOutput):
    writes: ResolveEppAlertsWrites


class ResolveEppAlertsOutput(PermissiveActionOutput):
    meta: ResolveEppAlertsMeta


class ResolveEppAlertsSummary(ActionOutput):
    alerts_affected: int


@app.action(
    description="Update the status of the given EPP alerts",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=ResolveEppAlertsSummary,
)
def resolve_epp_alerts(
    params: ResolveEppAlertsParams, soar: SOARClient, asset: Asset
) -> list[ResolveEppAlertsOutput]:
    client = get_client(asset)

    composite_ids = validate_comma_separated_values(params.alert_ids)
    if not composite_ids:
        raise ValueError(CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM.format(key="alert_ids"))

    to_state = params.status
    if to_state not in CROWDSTRIKE_EPP_ALERT_STATUSES:
        raise ValueError(CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM.format(key="status"))

    api_data = {
        "composite_ids": composite_ids,
        "action_parameters": [{"name": "update_status", "value": to_state}],
    }

    response = client.make_rest_call(
        CROWDSTRIKE_UPDATE_ALERT_ENDPOINT,
        json_data=api_data,
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

    soar.set_summary(ResolveEppAlertsSummary(alerts_affected=resources_affected))
    soar.set_message(f"Alerts affected: {resources_affected}")
    return [ResolveEppAlertsOutput(**response)]
