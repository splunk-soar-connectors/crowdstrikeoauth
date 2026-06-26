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
import hashlib
import json
import time
from datetime import datetime, UTC

from bs4 import UnicodeDammit

from .consts import CROWDSTRIKE_EVENT_TYPES


try:
    from phantom import utils as ph_utils

    _CONTAINS_VALIDATORS = ph_utils.CONTAINS_VALIDATORS
except ImportError:
    _CONTAINS_VALIDATORS = {}


_container_common = {
    "description": "Container added by Phantom",
    "run_automation": False,
}

_artifact_common = {
    "label": "event",
    "type": "network",
    "description": "Artifact added by Phantom",
    "run_automation": False,
}

_sub_artifact_common = {
    "label": "sub event",
    "description": "Artifact added by Phantom",
    "run_automation": False,
}

_severity_map = {
    "0": "low",
    "1": "low",
    "2": "low",
    "3": "medium",
    "4": "high",
    "5": "high",
}

_severity_name_map = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "high",
}

IGNORE_CONTAINS_VALIDATORS = ["domain", "host name"]
key_to_name = {}


def _get_value(in_dict, in_key, def_val=None, strip_it=True):
    if in_key not in in_dict:
        return def_val

    if not isinstance(in_dict[in_key], str):
        return in_dict[in_key]

    value = in_dict[in_key].strip() if strip_it else in_dict[in_key]

    return value if len(value) else def_val


def _set_cef_key(src_dict, src_key, dst_dict, dst_key, move=False):
    src_value = _get_value(src_dict, src_key)

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
    else:
        _set_cef_key(event_details, "Hostname", cef, "sourceHostName", move=True)
        _set_cef_key(event_details, "LogonDomain", cef, "sourceNtDomain", move=True)

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

    _set_cef_key(event_details, "CompositeId", cef, "compositeId", move=True)
    _set_cef_key(event_details, "AggregateId", cef, "aggregateId", move=True)


def _collate_results(detection_events):
    results = []

    detection_names = set()
    for event in detection_events:
        event_type = event.get("metadata", {}).get("eventType", "")
        if event_type == "DetectionSummaryEvent":
            name = event["event"].get("DetectName")
        else:
            name = event["event"].get("Name")
        if name:
            detection_names.add(name)

    for detection_name in detection_names:
        per_detection_events = [
            x
            for x in detection_events
            if (
                x["event"].get("DetectName") == detection_name
                or x["event"].get("Name") == detection_name
            )
        ]

        machine_names = set()
        for event in per_detection_events:
            event_type = event.get("metadata", {}).get("eventType", "")
            if event_type == "DetectionSummaryEvent":
                machine_name = event["event"].get("ComputerName", "")
            else:
                machine_name = event["event"].get("Hostname", "")
            machine_names.add(machine_name)

        for machine_name in machine_names:
            per_detection_machine_events = [
                x
                for x in per_detection_events
                if (
                    x["event"].get("ComputerName") == machine_name
                    or x["event"].get("Hostname") == machine_name
                )
            ]

            ingest_event = {}
            results.append(ingest_event)

            creation_time = int(time.time() * 1000)

            if per_detection_machine_events:
                creation_time = (
                    per_detection_machine_events[0]
                    .get("metadata", {})
                    .get("eventCreationTime", creation_time)
                )

            if creation_time:
                creation_time = _get_str_from_epoch(creation_time)

            container = {}
            ingest_event["container"] = container
            container.update(_container_common)
            container["name"] = "{} {}".format(
                detection_name,
                (
                    f"at {creation_time}"
                    if (not machine_name)
                    else f"on {machine_name} at {creation_time}"
                ),
            )
            container["source_data_identifier"] = _create_dict_hash(container)

            ingest_event["artifacts"] = artifacts = []
            for detection_event in per_detection_machine_events:
                artifacts_ret = _create_artifacts_from_event(detection_event)

                if artifacts_ret:
                    artifacts.extend(artifacts_ret)

    return results


def _convert_to_cef_dict(output_dict, input_dict):
    time_keys = []
    for k, v in input_dict.items():
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
        except (TypeError, ValueError):
            continue
        key_name = f"{curr_item}Iso"
        output_dict[key_name] = (
            datetime.fromtimestamp(time_epoch, tz=UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )

    return output_dict


def _set_cef_types(artifact, cef):
    cef_types = {}
    for k, v in cef.items():
        if k.lower().endswith("filename"):
            cef_types[k] = ["file name"]
            continue

        if k.lower().endswith("domainname"):
            cef_types[k] = ["domain"]
            continue

        for contains, function in _CONTAINS_VALIDATORS.items():
            if contains in IGNORE_CONTAINS_VALIDATORS:
                continue
            try:
                v_str = str(v)
            except UnicodeEncodeError:
                continue
            if function(v_str):
                cef_types[k] = [contains]
                break

    if not cef_types:
        return False

    artifact["cef_types"] = cef_types

    return True


def _get_artifact_name(key_name):
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


def _create_dict_hash(input_dict):
    if not input_dict:
        return None

    try:
        input_dict_str = json.dumps(input_dict, sort_keys=True)
    except (TypeError, ValueError):
        return None

    input_dict_str = UnicodeDammit(input_dict_str).unicode_markup.encode("utf-8")

    return hashlib.sha256(input_dict_str).hexdigest()


def _parse_sub_events(artifacts_list, input_dict, key_name, parent_artifact):
    if key_name not in input_dict:
        return 0

    parent_sdi = parent_artifact["source_data_identifier"]
    input_list = input_dict[key_name]

    if not isinstance(input_list, list):
        input_list = [input_list]

    artifact_name = _get_artifact_name(key_name)

    artifacts_len = len(artifacts_list)

    for curr_item in input_list:
        artifact = {}
        artifact.update(_sub_artifact_common)
        artifact["name"] = artifact_name
        artifact["cef"] = cef = {}
        _convert_to_cef_dict(cef, curr_item)

        if not cef:
            continue

        cef["parentSdi"] = parent_sdi
        artifact["severity"] = parent_artifact["severity"]
        artifacts_list.append(artifact)
        artifact["source_data_identifier"] = _create_dict_hash(artifact)
        _set_cef_types(artifact, cef)

    return len(artifacts_list) - artifacts_len


def _create_artifacts_from_event(event):
    event_details = dict(event["event"])
    event_metadata = event.get("metadata", {})
    event_type = event_metadata.get("eventType", "")

    artifact = {}
    cef = {}
    artifact["cef"] = cef

    artifact.update(_artifact_common)
    artifact["source_data_identifier"] = str(event_metadata["offset"])

    if event_type == "DetectionSummaryEvent":
        artifact["name"] = event_details.get("DetectDescription", "Detection Artifact")
        artifact["severity"] = _severity_map.get(
            str(event_details.get("Severity", 3)), "medium"
        )
    else:
        artifact["name"] = event_details.get("Description", "Detection Artifact")
        severity_name = event_details.get("SeverityName", "").lower()
        artifact["severity"] = _severity_name_map.get(severity_name, "medium")

    _set_cef_key_list(event_details, cef, event_type)

    _convert_to_cef_dict(cef, event_details)

    if cef and event_metadata:
        cef.update(event_metadata)

    artifact["data"] = event

    if not cef:
        return []

    artifacts = [artifact]

    _parse_sub_events(artifacts, cef, "networkAccesses", artifact)
    _parse_sub_events(artifacts, cef, "documentsAccessed", artifact)
    _parse_sub_events(artifacts, cef, "scanResults", artifact)
    _parse_sub_events(artifacts, cef, "executablesWritten", artifact)
    _parse_sub_events(artifacts, cef, "quarantineFiles", artifact)
    _parse_sub_events(artifacts, cef, "dnsRequests", artifact)
    _parse_sub_events(artifacts, cef, "filesAccessed", artifact)
    _parse_sub_events(artifacts, cef, "filesWritten", artifact)

    return artifacts


def _get_str_from_epoch(epoch_milli):
    return datetime.fromtimestamp(int(epoch_milli) / 1000, tz=UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def parse_events(events, collate):
    results = []

    detection_events = [
        x for x in events if x["metadata"]["eventType"] in CROWDSTRIKE_EVENT_TYPES
    ]

    if not detection_events:
        return results

    if collate:
        return _collate_results(detection_events)

    for curr_event in detection_events:
        event_type = curr_event["metadata"]["eventType"]
        event_details = curr_event["event"]

        if event_type == "DetectionSummaryEvent":
            detection_name = event_details.get("DetectName", "Unknown Detection")
            container_severity = _severity_map.get(
                str(event_details.get("Severity", 3)), "medium"
            )
            hostname = event_details.get("ComputerName", "Unknown Host")
        else:
            detection_name = event_details.get("Name", "Unknown Detection")
            severity_name = event_details.get("SeverityName", "").lower()
            container_severity = _severity_name_map.get(severity_name, "medium")
            hostname = event_details.get("Hostname", "Unknown Host")

        creation_time = curr_event.get("metadata", {}).get("eventCreationTime", "")

        ingest_event = {}
        results.append(ingest_event)

        if creation_time:
            creation_time = _get_str_from_epoch(creation_time)

        container = {}
        ingest_event["container"] = container
        container.update(_container_common)
        container["name"] = f"{detection_name} on {hostname} at {creation_time}"
        container["severity"] = container_severity
        container["source_data_identifier"] = _create_dict_hash(container)

        artifacts_ret = _create_artifacts_from_event(curr_event)
        ingest_event["artifacts"] = artifacts = []
        artifacts.extend(artifacts_ret)

    return results
