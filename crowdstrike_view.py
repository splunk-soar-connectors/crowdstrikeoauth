# File: crowdstrike_view.py
#
# Copyright (c) 2019-2025 Splunk Inc.
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
import ipaddress

import phantom.app as phantom
import phantom.utils as util


def _get_hash_type(hash_value):
    if util.is_md5(hash_value):
        return phantom.APP_SUCCESS, "md5"

    if util.is_sha1(hash_value):
        return phantom.APP_SUCCESS, "sha1"

    if util.is_sha256(hash_value):
        return phantom.APP_SUCCESS, "sha256"

    return phantom.APP_ERROR, None


def get_ctx_result_ps(result):
    ctx_result = {}

    param = result.get_param()

    if "ioc" in param:
        ioc = param.get("ioc")
        ret_val, param["ioc_type"] = _get_ioc_type(ioc)

    ctx_result["param"] = param

    message = result.get_message()
    ctx_result["message"] = message

    summary = result.get_summary()
    ctx_result["summary"] = summary

    data = result.get_data()

    if not data:
        return ctx_result

    ctx_result["data"] = data

    return ctx_result


def _get_ioc_type(ioc):
    if util.is_ip(ioc):
        return phantom.APP_SUCCESS, "ip"

    try:
        ipv6_type = ipaddress.IPv6Address(ioc)
        if ipv6_type:
            return phantom.APP_SUCCESS, "ip"
    except:
        pass

    if util.is_hash(ioc):
        return _get_hash_type(ioc)

    if util.is_domain(ioc):
        return phantom.APP_SUCCESS, "domain"

    return phantom.APP_ERROR, "Failed to detect the IOC type"


def _trim_results(data, key):
    if key not in data:
        return

    if len(data[key]) <= 100:
        return

    data[key] = data[key][:101]

    data[key][-1] = "..."


def get_ctx_result_hunt(result):
    ctx_result = {}

    param = result.get_param()

    if "hash" in param:
        hunt_object = param.get("hash")
    elif "domain" in param:
        hunt_object = param.get("domain")
    else:
        hunt_object = param.get("ip")

    param["ioc"] = hunt_object
    ret_val, param["ioc_type"] = _get_ioc_type(hunt_object)

    ctx_result["param"] = param

    message = result.get_message()
    ctx_result["message"] = message

    summary = result.get_summary()
    ctx_result["summary"] = summary

    data = result.get_data()

    if not data:
        return ctx_result

    ctx_result["data"] = data

    return ctx_result


def get_ctx_result(result):
    ctx_result = {}

    param = result.get_param()

    if "ioc" in param:
        ioc = param.get("ioc")
        ret_val, param["ioc_type"] = _get_ioc_type(ioc)

    ctx_result["param"] = param

    message = result.get_message()
    ctx_result["message"] = message

    summary = result.get_summary()
    ctx_result["summary"] = summary

    data = result.get_data()

    if not data:
        return ctx_result

    data = data[0]

    if not data:
        return ctx_result

    _trim_results(data, "ip")
    _trim_results(data, "domain")
    _trim_results(data, "sha256")
    _trim_results(data, "sha1")
    _trim_results(data, "md5")

    ctx_result["data"] = data

    return ctx_result


def get_ctx_result_indicator(result):
    ctx_result = {}

    param = result.get_param()

    if "ioc" in param:
        ioc = param.get("ioc")
        ret_val, param["ioc_type"] = _get_ioc_type(ioc)

    if "indicator_value" in param:
        ioc = param.get("indicator_value")
        ret_val, param["ioc_type"] = _get_ioc_type(ioc)

    ctx_result["param"] = param

    data = result.get_data()
    if not data:
        return ctx_result

    ctx_result["data"] = data

    return ctx_result


def _get_ctx_result(result, provides):
    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result["check_param"] = False

    if len(list(param.keys())) > 1:
        ctx_result["check_param"] = True

    ctx_result["param"] = param
    ctx_result["action_name"] = provides
    if summary:
        ctx_result["summary"] = summary

    if not data:
        ctx_result["data"] = {}
        return ctx_result

    ctx_result["data"] = data

    return ctx_result


def display_view(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result, provides)
            if not ctx_result:
                continue
            results.append(ctx_result)

    if provides == "assign hosts":
        return "crowdstrike_assign_hosts.html"

    if provides == "remove hosts":
        return "crowdstrike_remove_hosts.html"

    if provides == "create session":
        return "crowdstrike_create_session.html"

    if provides == "list incidents":
        return "crowdstrike_list_incidents.html"

    if provides == "list incident behaviors":
        return "crowdstrike_list_incident_behaviors.html"

    if provides == "list custom indicators":
        return "crowdstrike_list_custom_indicators.html"

    if provides == "get user roles":
        return "crowdstrike_get_user_roles.html"

    if provides == "file reputation":
        return "crowdstrike_file_reputation.html"

    if provides == "url reputation":
        return "crowdstrike_url_reputation.html"

    if provides == "detonate file":
        return "crowdstrike_detonate_file.html"

    if provides == "detonate url":
        return "crowdstrike_detonate_url.html"

    if provides == "get zta data":
        return "crowdstrike_get_zta_data.html"

    if provides == "get device scroll":
        return "crowdstrike_get_device_scroll.html"

    if provides == "list users":
        return "crowdstrike_list_users.html"

    if provides == "list detections":
        return "crowdstrike_list_detections.html"

    if provides == "list epp alerts":
        return "crowdstrike_list_epp_alerts.html"

    if provides == "get detections details":
        return "crowdstrike_get_detections_details.html"

    if provides == "get epp alerts details":
        return "crowdstrike_get_alerts_details.html"

    if provides == "create ioa rule group":
        return "crowdstrike_create_ioa_rule_group.html"

    if provides == "update ioa rule group":
        return "crowdstrike_update_ioa_rule_group.html"

    if provides == "delete ioa rule group":
        return "crowdstrike_delete_ioa_rule_group.html"

    if provides == "list ioa rule groups":
        return "crowdstrike_list_ioa_rule_groups.html"

    if provides == "list ioa platforms":
        return "crowdstrike_list_ioa_platforms.html"

    if provides == "list ioa severities":
        return "crowdstrike_list_ioa_severities.html"

    if provides == "list ioa types":
        return "crowdstrike_list_ioa_types.html"

    if provides == "create ioa rule":
        return "crowdstrike_create_ioa_rule.html"

    if provides == "update ioa rule":
        return "crowdstrike_update_ioa_rule.html"

    if provides == "delete ioa rule":
        return "crowdstrike_delete_ioa_rule.html"


def hunt_view(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result_hunt(result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    # print context
    return "crowdstrike_hunt_view.html"


def indicator_view(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result_indicator(result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    if provides == "update indicator":
        return "crowdstrike_update_indicator.html"

    if provides == "delete indicator":
        return "crowdstrike_delete_indicator.html"

    return "crowdstrike_get_indicator.html"


def set_status_view(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    # print context
    return "crowdstrike_set_status_view.html"


def process_list_view(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result_ps(result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    # print context
    return "crowdstrike_process_list_view.html"


def command_view(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result_ps(result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    # print context
    return "crowdstrike_command_output.html"
