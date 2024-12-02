# File: parse_cs_events.py
#
# Copyright (c) 2019-2024 Splunk Inc.
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
import hashlib
import json
import sys
import time
from datetime import datetime

from bs4 import UnicodeDammit
from phantom import utils as ph_utils

from crowdstrikeoauthapi_consts import CROWDSTRIKE_EVENT_TYPES

_container_common = {
    "description": "Container added by Phantom",
    "run_automation": False,  # Don't run any playbooks, when this container is added
}

_artifact_common = {
    "label": "event",
    "type": "network",
    "description": "Artifact added by Phantom",
    "run_automation": False,  # Don't run any playbooks, when this artifact is added
}

_sub_artifact_common = {
    "label": "sub event",
    "description": "Artifact added by Phantom",
    "run_automation": False,  # Don't run any playbooks, when this artifact is added
}
_severity_map = {
    # Old severity ranges
    "0": "low",
    "1": "low",
    "2": "low",
    "3": "medium",
    "4": "high",
    "5": "high",
}

_severity_name_map = {
    # EPP severity ranges
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "high"
}

IGNORE_CONTAINS_VALIDATORS = ["domain", "host name"]
key_to_name = dict()


def _get_value(in_dict, in_key, def_val=None, strip_it=True):
    if in_key not in in_dict:
        return def_val

    try:
        if not isinstance(in_dict[in_key], str):
            return in_dict[in_key]
    except:
        if not isinstance(in_dict[in_key], str):
            return in_dict[in_key]

    value = in_dict[in_key].strip() if (strip_it) else in_dict[in_key]

    return value if len(value) else def_val


def _set_cef_key(src_dict, src_key, dst_dict, dst_key, move=False):
    src_value = _get_value(src_dict, src_key)

    # Ignore if None
    if src_value is None:
        return False

    if src_value == "N/A":
        return False

    dst_dict[dst_key] = src_value

    if move:
        del src_dict[src_key]

    return True


def _set_cef_key_list(event_details, cef, event_type):
    if event_type == "DetectionSummaryEvent":
        _set_cef_key(event_details, "ComputerName", cef, "sourceHostName", move=True)
        _set_cef_key(event_details, "MachineDomain", cef, "sourceNtDomain", move=True)
    else:  # EppDetectionSummaryEvent
        _set_cef_key(event_details, "Hostname", cef, "sourceHostName", move=True)
        _set_cef_key(event_details, "LogonDomain", cef, "sourceNtDomain", move=True)

    # Common fields for both event types
    _set_cef_key(event_details, "UserName", cef, "sourceUserName", move=True)
    _set_cef_key(event_details, "FileName", cef, "fileName", move=True)
    _set_cef_key(event_details, "FilePath", cef, "filePath", move=True)
    _set_cef_key(event_details, "MD5String", cef, "fileHash")
    _set_cef_key(event_details, "MD5String", cef, "hash")
    _set_cef_key(event_details, "MD5String", cef, "fileHashMd5", move=True)

    _set_cef_key(event_details, "SHA1String", cef, "hash")
    _set_cef_key(event_details, "SHA1String", cef, "fileHashSha1", move=True)

    _set_cef_key(event_details, "SHA256String", cef, "hash")
    _set_cef_key(event_details, "SHA256String", cef, "fileHashSha256", move=True)

    _set_cef_key(event_details, "DetectId", cef, "detectId")
    _set_cef_key(event_details, "FalconHostLink", cef, "falconHostLink")

    if "CommandLine" in event_details:
        cef["cs1Label"] = "cmdLine"
        _set_cef_key(event_details, "CommandLine", cef, "cs1")
        _set_cef_key(event_details, "CommandLine", cef, "cmdLine", move=True)

    # EPP specific fields
    _set_cef_key(event_details, "CompositeId", cef, "compositeId", move=True)
    _set_cef_key(event_details, "AggregateId", cef, "aggregateId", move=True)


def _get_event_types(events):

    event_types = [x.get("metadata", {}).get("eventType", "") for x in events]
    event_types = list(set(event_types))

    return event_types


def _collate_results(base_connector, detection_events):
    results = []

    # Get the set of unique detection names, handling both event types
    detection_names = set()
    for event in detection_events:
        event_type = event.get("metadata", {}).get("eventType", "")
        if event_type == "DetectionSummaryEvent":
            name = event["event"].get("DetectName")
        else:  # EppDetectionSummaryEvent
            name = event["event"].get("Name")
        if name:
            detection_names.add(name)

    for detection_name in detection_names:
        # Update the filter to handle both event types
        per_detection_events = [
            x for x in detection_events 
            if (x["event"].get("DetectName") == detection_name or 
                x["event"].get("Name") == detection_name)
        ]

        # Get the set of unique machine names, handling both event types
        machine_names = set()
        for event in per_detection_events:
            event_type = event.get("metadata", {}).get("eventType", "")
            if event_type == "DetectionSummaryEvent":
                machine_name = event["event"].get("ComputerName", "")
            else:  # EppDetectionSummaryEvent
                machine_name = event["event"].get("Hostname", "")
            machine_names.add(machine_name)

        for machine_name in machine_names:
            # Update filter to check for both ComputerName and Hostname
            per_detection_machine_events = [
                x for x in per_detection_events 
                if (x["event"].get("ComputerName") == machine_name or 
                    x["event"].get("Hostname") == machine_name)
            ]

            ingest_event = dict()
            results.append(ingest_event)

            # This logic is required because _check_for_existing_container() method in connector checks on the basis of
            # name of the container created by trimming the last time attached in the container's name. Hence, if we do not
            # append the creation time over here, the ComputerName gets falsely truncated instead of the time and the events
            # start getting mixed up in the different ComputerName container falling in the time interval specified in the
            # merge_time_interval configuration parameter.
            creation_time = int(time.time() * 1000)

            if per_detection_machine_events:
                creation_time = per_detection_machine_events[0].get("metadata", {}).get("eventCreationTime", creation_time)

            if creation_time:
                creation_time = _get_str_from_epoch(creation_time)

            # Create the container
            container = dict()
            ingest_event["container"] = container
            container.update(_container_common)
            if sys.version_info[0] == 2:
                container["name"] = "{0} {1}".format(
                    UnicodeDammit(detection_name).unicode_markup.encode("utf-8"),
                    (
                        "at {0}".format(creation_time)
                        if (not machine_name)
                        else "on {0} at {1}".format(
                            UnicodeDammit(machine_name).unicode_markup.encode("utf-8"),
                            creation_time,
                        )
                    ),
                )
            else:
                container["name"] = "{0} {1}".format(
                    detection_name,
                    ("at {0}".format(creation_time) if (not machine_name) else "on {0} at {1}".format(machine_name, creation_time)),
                )
            container["source_data_identifier"] = _create_dict_hash(base_connector, container)

            # now the artifacts
            ingest_event["artifacts"] = artifacts = []
            for j, detection_event in enumerate(per_detection_machine_events):

                artifacts_ret = _create_artifacts_from_event(base_connector, detection_event)

                if artifacts_ret:
                    artifacts.extend(artifacts_ret)

    return results


def _convert_to_cef_dict(output_dict, input_dict):

    time_keys = list()
    # convert any remaining keys in the event_details to follow the cef naming conventions
    input_dict_items = input_dict.items()
    for k, v in input_dict_items:
        new_key_name = k[:1].lower() + k[1:]
        output_dict[new_key_name] = v
        if new_key_name.lower().endswith("time"):
            time_keys.append(new_key_name)

    for curr_item in time_keys:
        v = output_dict.get(curr_item)
        if not v:
            continue
        try:
            time_epoch = int(v)
        except:
            continue
        key_name = "{0}Iso".format(curr_item)
        output_dict[key_name] = datetime.utcfromtimestamp(time_epoch).isoformat() + "Z"

    return output_dict


def _set_cef_types(artifact, cef):

    cef_types = dict()
    cef_items = cef.items()
    for k, v in cef_items:

        if k.lower().endswith("filename"):
            cef_types[k] = ["file name"]
            continue

        if k.lower().endswith("domainname"):
            cef_types[k] = ["domain"]
            continue

        util_items = ph_utils.CONTAINS_VALIDATORS.items()
        for contains, function in util_items:
            if contains in IGNORE_CONTAINS_VALIDATORS:
                continue
            try:
                v_str = str(v)
            except UnicodeEncodeError:
                # None of these contains should match if there is a unicode characters in it
                continue
            if function(v_str):
                cef_types[k] = [contains]
                # it's ok to add only one contains
                break

    if not cef_types:
        return False

    artifact["cef_types"] = cef_types

    return True


def _get_artifact_name(key_name):

    # generate the artifact name, based on the key name
    # There should be a regex based way of replacing a Capital with '<space><CaP>'
    artifact_name = key_to_name.get(key_name, "")

    if artifact_name:
        return artifact_name

    for curr_char in key_name:

        if curr_char.isupper():
            artifact_name += " "

        artifact_name += curr_char

    artifact_name = artifact_name.title()

    key_to_name[key_name] = artifact_name

    return artifact_name


def _create_dict_hash(base_connector, input_dict):

    input_dict_str = None

    if not input_dict:
        return None

    try:
        input_dict_str = json.dumps(input_dict, sort_keys=True)
    except:
        return None

    if sys.version_info[0] == 3:
        input_dict_str = UnicodeDammit(input_dict_str).unicode_markup.encode("utf-8")

    fips_enabled = base_connector._get_fips_enabled()
    # if fips is not enabled, we should continue with our existing md5 usage for generating SDIs
    # to not impact existing customers
    if not fips_enabled:
        return hashlib.md5(input_dict_str).hexdigest()  # nosemgrep

    return hashlib.sha256(input_dict_str).hexdigest()


def _parse_sub_events(base_connector, artifacts_list, input_dict, key_name, parent_artifact):
    """A generic parser function"""

    # check if there is any data that can be parsed
    if key_name not in input_dict:
        return 0

    parent_sdi = parent_artifact["source_data_identifier"]
    input_list = input_dict[key_name]

    # make it into a list
    if not isinstance(input_list, list):
        input_list = [input_list]

    artifact_name = _get_artifact_name(key_name)

    artifacts_len = len(artifacts_list)

    for curr_item in input_list:
        artifact = dict()
        artifact.update(_sub_artifact_common)
        artifact["name"] = artifact_name
        artifact["cef"] = cef = dict()
        _convert_to_cef_dict(cef, curr_item)

        if not cef:
            continue

        cef["parentSdi"] = parent_sdi
        artifact["severity"] = parent_artifact["severity"]
        artifacts_list.append(artifact)
        artifact["source_data_identifier"] = _create_dict_hash(base_connector, artifact)
        _set_cef_types(artifact, cef)

    return len(artifacts_list) - artifacts_len


def _create_artifacts_from_event(base_connector, event):

    # Make a copy, since the dictionary will be modified
    event_details = dict(event["event"])
    event_metadata = event.get("metadata", {})
    event_type = event_metadata.get("eventType", "")

    artifact = dict()
    cef = dict()
    artifact["cef"] = cef

    # so this artifact needs to be added
    artifact.update(_artifact_common)
    artifact["source_data_identifier"] = event_metadata["offset"]

    # Handle both event types for description/name and severity
    if event_type == "DetectionSummaryEvent":
        artifact["name"] = event_details.get("DetectDescription", "Detection Artifact")
        artifact["severity"] = _severity_map.get(str(event_details.get("Severity", 3)), "medium")
    else:  # EppDetectionSummaryEvent
        artifact["name"] = event_details.get("Description", "Detection Artifact")
        severity_name = event_details.get("SeverityName", "").lower()
        artifact["severity"] = _severity_name_map.get(severity_name, "medium")

    _set_cef_key_list(event_details, cef, event_type)

    # convert any remaining keys in the event_details to follow the cef naming conventions
    _convert_to_cef_dict(cef, event_details)

    if cef:
        if event_metadata:
            # add the metadata as is, it already contains the keys in cef naming conventions
            cef.update(event_metadata)

    artifact["data"] = event

    if not cef:
        return []

    artifacts = list()
    artifacts.append(artifact)

    _parse_sub_events(base_connector, artifacts, cef, "networkAccesses", artifact)
    _parse_sub_events(base_connector, artifacts, cef, "documentsAccessed", artifact)
    _parse_sub_events(base_connector, artifacts, cef, "scanResults", artifact)
    _parse_sub_events(base_connector, artifacts, cef, "executablesWritten", artifact)
    _parse_sub_events(base_connector, artifacts, cef, "quarantineFiles", artifact)
    _parse_sub_events(base_connector, artifacts, cef, "dnsRequests", artifact)
    _parse_sub_events(base_connector, artifacts, cef, "filesAccessed", artifact)  # EPP format
    _parse_sub_events(base_connector, artifacts, cef, "filesWritten", artifact)   # EPP format

    return artifacts


def _get_dt_from_epoch(epoch_milli):
    return datetime.fromtimestamp(int(epoch_milli) / 1000)


def _get_str_from_epoch(epoch_milli):
    # 2015-07-21T00:27:59Z
    return datetime.fromtimestamp(int(epoch_milli) / 1000).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_events(events, base_connector, collate):
    results = []

    base_connector.save_progress("Extracting Detection events")

    # Extract both DetectionSummaryEvent and EppDetectionSummaryEvent events
    detection_events = [x for x in events if x["metadata"]["eventType"] in CROWDSTRIKE_EVENT_TYPES]

    if not detection_events:
        base_connector.save_progress("Did not match any events of supported types")
        return results

    base_connector.save_progress("Got {0} detection events".format(len(detection_events)))

    if collate:
        return _collate_results(base_connector, detection_events)

    for curr_event in detection_events:
        event_type = curr_event["metadata"]["eventType"]
        event_details = curr_event["event"]

        # Handle both detection types
        if event_type == "DetectionSummaryEvent":
            detection_name = event_details.get("DetectName", "Unknown Detection")
            container_severity = _severity_map.get(str(event_details.get("Severity", 3)), "medium")
            hostname = event_details.get("ComputerName", "Unknown Host")
        else:  # EppDetectionSummaryEvent
            detection_name = event_details.get("Name", "Unknown Detection")
            severity_name = event_details.get("SeverityName", "").lower()
            container_severity = _severity_name_map.get(severity_name, "medium")
            hostname = event_details.get("Hostname", "Unknown Host")

        creation_time = curr_event.get("metadata", {}).get("eventCreationTime", "")

        ingest_event = dict()
        results.append(ingest_event)

        if creation_time:
            creation_time = _get_str_from_epoch(creation_time)

        # Create the container
        container = dict()
        ingest_event["container"] = container
        container.update(_container_common)
        if sys.version_info[0] == 2:
            container["name"] = "{0} on {1} at {2}".format(
                UnicodeDammit(detection_name).unicode_markup.encode("utf-8"),
                UnicodeDammit(hostname).unicode_markup.encode("utf-8"),
                creation_time,
            )
        else:
            container["name"] = "{0} on {1} at {2}".format(detection_name, hostname, creation_time)
        container["severity"] = container_severity
        container["source_data_identifier"] = _create_dict_hash(base_connector, container)

        # Create artifacts
        artifacts_ret = _create_artifacts_from_event(base_connector, curr_event)
        ingest_event["artifacts"] = artifacts = []
        artifacts.extend(artifacts_ret)

    return results
