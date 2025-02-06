# File: parse_cs_incidents.py
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

import sys

from bs4 import UnicodeDammit

_container_common = {
    "description": "Container added by Phantom",
    "run_automation": False,  # Don't run any playbooks when this container is added
}

_artifact_common = {
    "label": "incident",
    "type": "network",
    "description": "Artifact added by Phantom",
    "run_automation": False,  # Don't run any playbooks when this artifact is added
}

_host_artifact_common = {
    "label": "host",
    "type": "host",
    "description": "Artifact added by Phantom",
    "run_automation": False,  # Don't run any playbooks when this artifact is added
}


def _get_incident_severity(fine_score):
    if fine_score >= 80:
        return "high"
    elif fine_score >= 60:
        return "medium"
    elif fine_score >= 40:
        return "low"
    else:
        return "low"


def _create_incident_artifact(incident):
    artifact = dict(_artifact_common)
    artifact["name"] = "Incident Details"
    artifact["source_data_identifier"] = incident.get("incident_id")
    artifact["severity"] = _get_incident_severity(incident.get("fine_score", 0))

    # Key CEF mapping
    artifact["cef"] = {
        "status": incident.get("status"),
        "name": incident.get("name"),
        "description": incident.get("description"),
        "severity": incident.get("fine_score"),
        "state": incident.get("state"),
        "tags": incident.get("tags", []),
        "created_time": incident.get("created"),
        "modified_time": incident.get("modified_timestamp"),
        "incident_id": incident.get("incident_id"),
        "tactics": incident.get("tactics", []),
        "techniques": incident.get("techniques", []),
        "objectives": incident.get("objectives", []),
    }

    return artifact


def _create_host_artifact(host, incident):
    artifact = dict(_host_artifact_common)
    artifact["name"] = "Affected Host"
    artifact["source_data_identifier"] = f"{incident.get('incident_id')}_{host.get('device_id')}"
    artifact["severity"] = _get_incident_severity(incident.get("fine_score", 0))

    # Key CEF mapping
    artifact["cef"] = {
        "hostname": host.get("hostname"),
        "host_id": host.get("device_id"),
        "local_ip": host.get("local_ip"),
        "external_ip": host.get("external_ip"),
        "platform": host.get("platform_name"),
        "os_version": host.get("os_version"),
        "mac_address": host.get("mac_address"),
        "system_manufacturer": host.get("system_manufacturer"),
        "last_seen": host.get("last_seen"),
        "status": host.get("status"),
    }

    return artifact


def process_incidents(incidents):
    results = []

    for incident in incidents:
        ingest_event = dict()
        results.append(ingest_event)

        # Incident
        artifacts = [_create_incident_artifact(incident)]

        # Host
        for host in incident.get("hosts", []):
            artifacts.append(_create_host_artifact(host, incident))

        # Container
        container = dict()
        ingest_event["container"] = container
        container.update(_container_common)

        if sys.version_info[0] == 2:
            container["name"] = "{0} on {1} at {2}".format(
                UnicodeDammit(incident.get("name", "Unnamed Incident")).unicode_markup.encode("utf-8"),
                UnicodeDammit(incident.get("hosts", [{}])[0].get("hostname", "Unknown Host")).unicode_markup.encode("utf-8"),
                incident.get("start", "Unknown Time"),
            )
        else:
            container["name"] = "{0} on {1} at {2}".format(
                incident.get("name", "Unnamed Incident"),
                incident.get("hosts", [{}])[0].get("hostname", "Unknown Host"),
                incident.get("start", "Unknown Time"),
            )

        # Container properties
        container["description"] = incident.get("description", "No description available")
        container["source_data_identifier"] = incident.get("incident_id")
        container["severity"] = _get_incident_severity(incident.get("fine_score", 0))

        ingest_event["artifacts"] = artifacts

    return results
