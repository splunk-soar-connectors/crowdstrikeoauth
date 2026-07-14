# CrowdStrike OAuth API

Publisher: Splunk <br>
Connector Version: 5.1.3 <br>
Product Vendor: CrowdStrike <br>
Product Name: CrowdStrike <br>
Minimum Product Version: 8.6

This app integrates with CrowdStrike OAuth2 authentication standard to implement querying of endpoint security data

### Configuration variables

This table lists the configuration variables required to operate CrowdStrike OAuth API. These variables are specified when configuring a CrowdStrike asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** | required | string | Base URL |
**client_id** | required | password | Client ID |
**client_secret** | required | password | Client Secret |
**subtenants** | optional | string | Comma-separated list of subtenant CIDs. Example: 123,456,789 |
**app_id** | optional | string | App ID |
**max_events** | optional | numeric | Maximum events to get for scheduled and interval polling |
**max_events_poll_now** | optional | numeric | Maximum events to get while POLL NOW |
**max_incidents** | optional | numeric | Maximum incidents to get for scheduled and interval polling |
**max_incidents_poll_now** | optional | numeric | Maximum incidents to get while POLL NOW |
**ingest_incidents** | optional | boolean | Should ingest incidents during polling |
**collate** | optional | boolean | Merge containers for hostname and eventname |
**max_crlf** | optional | numeric | Maximum allowed continuous blank lines |
**detonate_timeout** | optional | numeric | Timeout for detonation result in minutes (Default: 15 minutes) |

### Supported Actions

[test connectivity](#action-test-connectivity) - test connectivity <br>
[on poll](#action-on-poll) - on poll <br>
[assign hosts](#action-assign-hosts) - Assign one or more hosts to an existing static host group <br>
[check status](#action-check-status) - Check detonation status using the resource ID <br>
[create ioa rule](#action-create-ioa-rule) - Create a new IOA rule within a rule group <br>
[create ioa rule group](#action-create-ioa-rule-group) - Create an empty IOA rule group <br>
[create session](#action-create-session) - Initialize a new session with the Real Time Response cloud <br>
[delete indicator](#action-delete-indicator) - Delete an IOC <br>
[delete ioa rule](#action-delete-ioa-rule) - Delete IOA rules from a rule group <br>
[delete ioa rule group](#action-delete-ioa-rule-group) - Delete IOA rule groups <br>
[delete session](#action-delete-session) - Deletes a Real Time Response session <br>
[detonate file](#action-detonate-file) - Upload a file to CrowdStrike and retrieve the analysis results <br>
[detonate url](#action-detonate-url) - Detonate a URL in the CrowdStrike sandbox <br>
[download report](#action-download-report) - Download the report of a detonated file or URL <br>
[file reputation](#action-file-reputation) - Queries CrowdStrike for the file reputation info <br>
[get command details](#action-get-command-details) - Retrieve results of an active responder command executed on a single host <br>
[get system info](#action-get-system-info) - Queries CrowdStrike for the details of a device <br>
[get device scroll](#action-get-device-scroll) - Get a list of device IDs using pagination <br>
[get epp details](#action-get-epp-details) - Get details for the given EPP alerts <br>
[get indicator](#action-get-indicator) - Get the details for an indicator <br>
[get process detail](#action-get-process-detail) - Queries CrowdStrike for the details of a process <br>
[get role](#action-get-role) - Get information about a specific role <br>
[get session file](#action-get-session-file) - Get RTR extracted file contents for the specified session and sha256 and add it to the vault <br>
[get user roles](#action-get-user-roles) - Get user roles <br>
[get zta data](#action-get-zta-data) - Get Zero Trust Assessment data for one or more hosts by providing agent IDs (AID) <br>
[hunt domain](#action-hunt-domain) - Hunt for a domain across all hosts in the environment <br>
[hunt file](#action-hunt-file) - Hunt for a file across all hosts in the environment <br>
[hunt ip](#action-hunt-ip) - Hunt for an IP across all hosts in the environment <br>
[list alerts](#action-list-alerts) - Fetch the list of alerts <br>
[list custom indicators](#action-list-custom-indicators) - List the custom indicators <br>
[list epp alerts](#action-list-epp-alerts) - Fetch the list of EPP alerts <br>
[list groups](#action-list-groups) - Fetch the details of the host groups <br>
[list ioa platforms](#action-list-ioa-platforms) - Get the platforms that support IOA rules <br>
[list ioa rule groups](#action-list-ioa-rule-groups) - Get the configured IOA rule groups <br>
[list ioa severities](#action-list-ioa-severities) - Get the severity levels that can be assigned to IOA rules <br>
[list ioa types](#action-list-ioa-types) - Get the IOA types and their parameters <br>
[list processes](#action-list-processes) - Lists the processes a specified IOC ran on for a specific device <br>
[list put files](#action-list-put-files) - Queries for files uploaded to Crowdstrike for use with the RTR `put` command <br>
[list roles](#action-list-roles) - Get the list of roles <br>
[list session files](#action-list-session-files) - Get a list of files for the specified RTR session <br>
[list sessions](#action-list-sessions) - Lists the active RTR sessions <br>
[make request](#action-make-request) - make request <br>
[list users](#action-list-users) - Gets the list of users <br>
[query device](#action-query-device) - Fetch the list of devices <br>
[quarantine device](#action-quarantine-device) - This action contains the host, which stops any network communications to locations other than the CrowdStrike cloud and IPs specified in the user's containment policy. <br>
[remove hosts](#action-remove-hosts) - Remove one or more hosts from an existing static host group <br>
[resolve epp alerts](#action-resolve-epp-alerts) - Update the status of the given EPP alerts <br>
[run admin command](#action-run-admin-command) - Execute an RTR administrator command on a single host <br>
[run command](#action-run-command) - Execute an RTR command on a single host <br>
[run query](#action-run-query) - Run a generic query against a CrowdStrike API query endpoint <br>
[unquarantine device](#action-unquarantine-device) - This action lifts containment on the host, which returns its network communications to normal. <br>
[url reputation](#action-url-reputation) - Queries CrowdStrike for the URL reputation info <br>
[update epp alerts](#action-update-epp-alerts) - Update the given EPP alerts <br>
[update indicator](#action-update-indicator) - Update an IOC <br>
[update ioa rule](#action-update-ioa-rule) - Update an existing IOA rule <br>
[update ioa rule group](#action-update-ioa-rule-group) - Update an existing IOA rule group <br>
[upload indicator](#action-upload-indicator) - Upload an IOC <br>
[upload put file](#action-upload-put-file) - Upload a new put-file to use for the RTR `put` command

## action: 'test connectivity'

test connectivity

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'on poll'

on poll

Type: **ingest** <br>
Read only: **True**

Callback action for the on_poll ingest functionality

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Start of time range, in epoch time (milliseconds). | numeric | |
**end_time** | optional | End of time range, in epoch time (milliseconds). | numeric | |
**container_count** | optional | Maximum number of container records to query for. | numeric | |
**artifact_count** | optional | Maximum number of artifact records to query for. | numeric | |
**container_id** | optional | Comma-separated list of container IDs to limit the ingestion to. | string | |

#### Action Output

No Output

## action: 'assign hosts'

Assign one or more hosts to an existing static host group

Type: **correct** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | optional | Comma-separated list of device IDs | string | `crowdstrike device id` |
**hostname** | optional | Comma separated list of hostnames | string | `host name` |
**host_group_id** | required | Static host group ID | string | `crowdstrike host group id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.device_id | string | `crowdstrike device id` | |
action_result.parameter.hostname | string | `host name` | |
action_result.parameter.host_group_id | string | `crowdstrike host group id` | |
action_result.data.\*.id | string | `crowdstrike host group id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.group_type | string | | |
action_result.data.\*.assignment_rule | string | | |
action_result.data.\*.created_by | string | | |
action_result.data.\*.created_timestamp | string | | |
action_result.data.\*.modified_by | string | | |
action_result.data.\*.modified_timestamp | string | | |
action_result.summary.total_assigned_device | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'check status'

Check detonation status using the resource ID

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**resource_id** | required | Resource ID of the submitted detonation | string | `crowdstrike resource id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.resource_id | string | `crowdstrike resource id` | |
action_result.data.\*.cid | string | | |
action_result.data.\*.created_timestamp | string | `date` | |
action_result.data.\*.id | string | `crowdstrike resource id` | |
action_result.data.\*.origin | string | | |
action_result.data.\*.state | string | | |
action_result.data.\*.user_id | string | | |
action_result.data.\*.user_name | string | | |
action_result.data.\*.user_uuid | string | | |
action_result.data.\*.sandbox.\*.action_script | string | | |
action_result.data.\*.sandbox.\*.command_line | string | | |
action_result.data.\*.sandbox.\*.enable_tor | boolean | | True False |
action_result.data.\*.sandbox.\*.environment_id | numeric | | |
action_result.data.\*.sandbox.\*.network_settings | string | | |
action_result.data.\*.sandbox.\*.sha256 | string | `sha256` | |
action_result.data.\*.sandbox.\*.submit_name | string | | |
action_result.data.\*.sandbox.\*.url | string | `url` | |
action_result.summary.state | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create ioa rule'

Create a new IOA rule within a rule group

Type: **contain** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**rule_group_id** | required | ID of the rule group to add the rule to | string | `crowdstrike ioa rule group id` |
**name** | required | Name of the rule | string | |
**description** | required | Description of the rule | string | |
**severity** | required | Severity of the rule | string | |
**rule_type_id** | required | Rule type ID | numeric | |
**disposition_id** | required | Disposition ID | numeric | |
**field_values** | required | JSON list of field values for the rule | string | |
**comment** | optional | Comment for the rule | string | |
**enabled** | optional | Whether the rule is enabled | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.rule_group_id | string | `crowdstrike ioa rule group id` | |
action_result.parameter.name | string | | |
action_result.parameter.description | string | | |
action_result.parameter.severity | string | | |
action_result.parameter.rule_type_id | numeric | | |
action_result.parameter.disposition_id | numeric | | |
action_result.parameter.field_values | string | | |
action_result.parameter.comment | string | | |
action_result.parameter.enabled | boolean | | |
action_result.data.\*.resources.\*.instance_id | string | `crowdstrike ioa rule id` | |
action_result.data.\*.resources.\*.customer_id | string | `crowdstrike customer id` | |
action_result.data.\*.resources.\*.ruletype_id | string | | |
action_result.data.\*.resources.\*.ruletype_name | string | | |
action_result.data.\*.resources.\*.comment | string | | |
action_result.data.\*.resources.\*.enabled | boolean | | True False |
action_result.data.\*.resources.\*.deleted | boolean | | True False |
action_result.data.\*.resources.\*.magic_cookie | numeric | | |
action_result.data.\*.resources.\*.rulegroup_id | string | `crowdstrike ioa rule group id` | |
action_result.data.\*.resources.\*.version_ids.\* | string | | |
action_result.data.\*.resources.\*.instance_version | numeric | | |
action_result.data.\*.resources.\*.name | string | | |
action_result.data.\*.resources.\*.description | string | | |
action_result.data.\*.resources.\*.pattern_id | string | | |
action_result.data.\*.resources.\*.pattern_severity | string | | |
action_result.data.\*.resources.\*.action_label | string | | |
action_result.data.\*.resources.\*.disposition_id | numeric | | |
action_result.data.\*.resources.\*.field_values.\*.name | string | | |
action_result.data.\*.resources.\*.field_values.\*.value | string | | |
action_result.data.\*.resources.\*.field_values.\*.label | string | | |
action_result.data.\*.resources.\*.field_values.\*.type | string | | |
action_result.data.\*.resources.\*.field_values.\*.values.\*.label | string | | |
action_result.data.\*.resources.\*.field_values.\*.values.\*.value | string | | |
action_result.data.\*.resources.\*.field_values.\*.final_value | string | | |
action_result.summary.rule_group_id | string | `crowdstrike ioa rule group id` | |
action_result.summary.rule_id | string | `crowdstrike ioa rule id` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create ioa rule group'

Create an empty IOA rule group

Type: **contain** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | required | Name of the rule group | string | |
**description** | required | Description of the rule group | string | |
**platform** | required | Platform for the rule group | string | |
**enabled** | optional | Whether the rule group is enabled | boolean | |
**policy_id** | optional | Comma-separated list of prevention policy IDs to attach | string | `crowdstrike prevention policy id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.name | string | | |
action_result.parameter.description | string | | |
action_result.parameter.platform | string | | |
action_result.parameter.enabled | boolean | | |
action_result.parameter.policy_id | string | `crowdstrike prevention policy id` | |
action_result.data.\*.resources.\*.id | string | `crowdstrike ioa rule group id` | |
action_result.data.\*.resources.\*.customer_id | string | `crowdstrike customer id` | |
action_result.data.\*.resources.\*.enabled | boolean | | True False |
action_result.data.\*.resources.\*.name | string | | |
action_result.data.\*.resources.\*.description | string | | |
action_result.data.\*.resources.\*.platform | string | | |
action_result.data.\*.resources.\*.deleted | boolean | | True False |
action_result.data.\*.resources.\*.rule_ids.\* | string | `crowdstrike ioa rule id` | |
action_result.data.\*.resources.\*.comment | string | | |
action_result.data.\*.resources.\*.version | numeric | | |
action_result.data.\*.resources.\*.created_by | string | `crowdstrike user id` | |
action_result.data.\*.resources.\*.created_on | string | | |
action_result.data.\*.resources.\*.modified_by | string | `crowdstrike user id` | |
action_result.data.\*.resources.\*.modified_on | string | | |
action_result.data.\*.resources.\*.committed_on | string | | |
action_result.data.\*.resources.\*.assigned_policy_ids.\* | string | `crowdstrike prevention policy id` | |
action_result.summary.rule_group_id | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create session'

Initialize a new session with the Real Time Response cloud

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | Device ID for session to be created | string | `crowdstrike device id` |
**queue_offline** | optional | Queue commands for offline devices, will execute when system comes back online | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.device_id | string | `crowdstrike device id` | |
action_result.parameter.queue_offline | boolean | | |
action_result.data.\*.device_id | string | `crowdstrike device id` | |
action_result.data.\*.resources.\*.session_id | string | `crowdstrike rtr session id` | |
action_result.data.\*.resources.\*.created_at | string | | |
action_result.data.\*.resources.\*.existing_aid_sessions | numeric | | |
action_result.data.\*.resources.\*.offline_queued | boolean | | True False |
action_result.data.\*.resources.\*.pwd | string | `file path` | |
action_result.summary.session_id | string | `crowdstrike rtr session id` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'delete indicator'

Delete an IOC

Type: **correct** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** | optional | The IOC to delete | string | `ip` `ipv6` `md5` `sha256` `domain` |
**resource_id** | optional | The resource ID of the IOC to delete | string | `crowdstrike indicator id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ioc | string | `ip` `ipv6` `md5` `sha256` `domain` | |
action_result.parameter.resource_id | string | `crowdstrike indicator id` | |
action_result.data.\*.ioc | string | | |
action_result.data.\*.resource_id | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'delete ioa rule'

Delete IOA rules from a rule group

Type: **contain** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**rule_group_id** | required | ID of the rule group | string | `crowdstrike ioa rule group id` |
**rule_id** | required | Comma-separated list of rule IDs to delete | string | `crowdstrike ioa rule id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.rule_group_id | string | `crowdstrike ioa rule group id` | |
action_result.parameter.rule_id | string | `crowdstrike ioa rule id` | |
action_result.summary.resources_affected | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'delete ioa rule group'

Delete IOA rule groups

Type: **contain** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | Comma-separated list of rule group IDs to delete | string | `crowdstrike ioa rule group id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.id | string | `crowdstrike ioa rule group id` | |
action_result.summary.resources_affected | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'delete session'

Deletes a Real Time Response session

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**session_id** | required | RTR Session ID | string | `crowdstrike rtr session id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.session_id | string | `crowdstrike rtr session id` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'detonate file'

Upload a file to CrowdStrike and retrieve the analysis results

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | required | Vault ID of file to detonate | string | `vault id` |
**environment** | required | Sandbox environment to use for analysis | string | `crowdstrike environment` |
**comment** | optional | A descriptive comment to identify the file for other users | string | |
**limit** | optional | Maximum reports to be fetched | numeric | |
**offset** | optional | Starting index of overall result set | numeric | |
**command_line** | optional | Command line script passed to the submitted file at runtime | string | |
**document_password** | optional | Auto-filled password for Adobe or Office files | string | |
**submit_name** | optional | Name of the malware sample that is used for file type detection and analysis | string | |
**user_tags** | optional | Comma-separated list of tags to categorize the submission | string | |
**sort** | optional | Property to sort by | string | |
**action_script** | optional | Runtime script for sandbox analysis | string | |
**detail_report** | optional | Provide a detailed report of the file | boolean | |
**enable_tor** | optional | Route the analysis through the TOR network | boolean | |
**is_confidential** | optional | Make the sample confidential and visible only to your organization | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.vault_id | string | `vault id` | |
action_result.parameter.environment | string | `crowdstrike environment` | |
action_result.parameter.comment | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
action_result.parameter.command_line | string | | |
action_result.parameter.document_password | string | | |
action_result.parameter.submit_name | string | | |
action_result.parameter.user_tags | string | | |
action_result.parameter.sort | string | | |
action_result.parameter.action_script | string | | |
action_result.parameter.detail_report | boolean | | |
action_result.parameter.enable_tor | boolean | | |
action_result.parameter.is_confidential | boolean | | |
action_result.data.\*.cid | string | | |
action_result.data.\*.created_timestamp | string | `date` | |
action_result.data.\*.id | string | `crowdstrike resource id` | |
action_result.data.\*.ioc_report_broad_csv_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_broad_json_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_broad_maec_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_broad_stix_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_strict_csv_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_strict_json_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_strict_maec_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_strict_stix_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.origin | string | | |
action_result.data.\*.user_id | string | | |
action_result.data.\*.user_name | string | | |
action_result.data.\*.user_uuid | string | | |
action_result.data.\*.user_tags | string | | |
action_result.data.\*.verdict | string | | |
action_result.summary.verdict | string | | |
action_result.summary.total_reports | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'detonate url'

Detonate a URL in the CrowdStrike sandbox

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to detonate | string | `url` |
**environment** | required | Sandbox environment to use for analysis | string | `crowdstrike environment` |
**limit** | optional | Maximum reports to be fetched | numeric | |
**offset** | optional | Starting index of overall result set | numeric | |
**document_password** | optional | Auto-filled password for Adobe or Office files | string | |
**command_line** | optional | Command line script passed to the submitted file at runtime | string | |
**user_tags** | optional | Comma-separated list of tags to categorize the submission | string | |
**sort** | optional | Property to sort by | string | |
**action_script** | optional | Runtime script for sandbox analysis | string | |
**detail_report** | optional | Provide a detailed report of the URL | boolean | |
**enable_tor** | optional | Route the analysis through the TOR network | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.url | string | `url` | |
action_result.parameter.environment | string | `crowdstrike environment` | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
action_result.parameter.document_password | string | | |
action_result.parameter.command_line | string | | |
action_result.parameter.user_tags | string | | |
action_result.parameter.sort | string | | |
action_result.parameter.action_script | string | | |
action_result.parameter.detail_report | boolean | | |
action_result.parameter.enable_tor | boolean | | |
action_result.data.\*.cid | string | | |
action_result.data.\*.created_timestamp | string | `date` | |
action_result.data.\*.id | string | `crowdstrike resource id` | |
action_result.data.\*.ioc_report_broad_csv_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_broad_json_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_broad_maec_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_broad_stix_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_strict_csv_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_strict_json_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_strict_maec_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_strict_stix_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.origin | string | | |
action_result.data.\*.user_id | string | | |
action_result.data.\*.user_name | string | | |
action_result.data.\*.user_uuid | string | | |
action_result.data.\*.user_tags | string | | |
action_result.data.\*.verdict | string | | |
action_result.summary.verdict | string | | |
action_result.summary.total_reports | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'download report'

Download the report of a detonated file or URL

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**artifact_id** | required | Artifact ID to download | string | `crowdstrike artifact id` |
**file_name** | optional | Filename to use for the downloaded artifact | string | `filename` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.artifact_id | string | `crowdstrike artifact id` | |
action_result.parameter.file_name | string | `filename` | |
action_result.data.\*.vault_id | string | `sha1` `vault id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.size | numeric | | |
action_result.data.\*.container_id | numeric | | |
action_result.summary.vault_id | string | `sha1` `vault id` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'file reputation'

Queries CrowdStrike for the file reputation info

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | optional | Vault ID of file to get the reputation of | string | `vault id` |
**sha256** | optional | SHA256 of file to get the reputation of | string | `sha256` |
**limit** | optional | Maximum reports to be fetched | numeric | |
**sort** | optional | Property to sort by | string | |
**offset** | optional | Starting index of overall result set | numeric | |
**detail_report** | optional | Provide a detailed report of the file | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.vault_id | string | `vault id` | |
action_result.parameter.sha256 | string | `sha256` | |
action_result.parameter.limit | numeric | | |
action_result.parameter.sort | string | | |
action_result.parameter.offset | numeric | | |
action_result.parameter.detail_report | boolean | | |
action_result.data.\*.cid | string | | |
action_result.data.\*.created_timestamp | string | `date` | |
action_result.data.\*.id | string | `crowdstrike resource id` | |
action_result.data.\*.ioc_report_broad_csv_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_broad_json_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_broad_maec_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_broad_stix_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_strict_csv_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_strict_json_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_strict_maec_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_strict_stix_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.origin | string | | |
action_result.data.\*.user_id | string | | |
action_result.data.\*.user_name | string | | |
action_result.data.\*.user_uuid | string | | |
action_result.data.\*.user_tags | string | | |
action_result.data.\*.verdict | string | | |
action_result.summary.verdict | string | | |
action_result.summary.total_reports | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get command details'

Retrieve results of an active responder command executed on a single host

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**cloud_request_id** | required | Cloud Request ID for Command | string | `crowdstrike cloud request id` |
**timeout_seconds** | required | Time (in seconds; default is 60) to wait before timing out poll for results | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.cloud_request_id | string | `crowdstrike cloud request id` | |
action_result.parameter.timeout_seconds | numeric | | |
action_result.data.\*.resources.\*.base_command | string | | |
action_result.data.\*.resources.\*.stdout | string | | |
action_result.data.\*.resources.\*.stderr | string | | |
action_result.data.\*.resources.\*.complete | boolean | | True False |
action_result.data.\*.resources.\*.session_id | string | `crowdstrike rtr session id` | |
action_result.data.\*.resources.\*.task_id | string | | |
action_result.summary.results | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get system info'

Queries CrowdStrike for the details of a device

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | ID of the device to get the details of | string | `crowdstrike device id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.id | string | `crowdstrike device id` | |
action_result.data.\*.device_id | string | `crowdstrike device id` | |
action_result.data.\*.hostname | string | `host name` | |
action_result.data.\*.last_seen | string | | |
action_result.data.\*.os_version | string | | |
action_result.data.\*.platform_name | string | | |
action_result.summary.hostname | string | `host name` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get device scroll'

Get a list of device IDs using pagination

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**offset** | optional | The offset to page from, for the next result set | string | |
**limit** | optional | The maximum records to return. [1-5000] | numeric | |
**sort** | optional | The property to sort by (e.g. status.desc or hostname.asc) | string | |
**filter** | optional | The filter expression that should be used to limit the results (FQL syntax) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.offset | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.sort | string | | |
action_result.parameter.filter | string | | |
action_result.data.\*.resources.\* | string | `crowdstrike device id` | |
action_result.data.\*.meta.pagination.expires_at | numeric | | |
action_result.data.\*.meta.pagination.limit | string | | |
action_result.data.\*.meta.pagination.offset | string | | |
action_result.data.\*.meta.pagination.total | numeric | | |
action_result.data.\*.meta.powered_by | string | | |
action_result.data.\*.meta.query_time | numeric | | |
action_result.data.\*.meta.trace_id | string | | |
action_result.data.\*.param_offset | string | | |
action_result.data.\*.param_limit | numeric | | |
action_result.data.\*.param_sort | string | | |
action_result.data.\*.param_filter | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get epp details'

Get details for the given EPP alerts

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_ids** | required | Comma-separated list of alert IDs (composite IDs) | string | `crowdstrike alert id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.alert_ids | string | `crowdstrike alert id` | |
action_result.data.\*.composite_id | string | `crowdstrike alert id` | |
action_result.data.\*.status | string | | |
action_result.data.\*.severity | string | | |
action_result.data.\*.created_timestamp | string | | |
action_result.summary.total_alerts | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get indicator'

Get the details for an indicator

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator_value** | optional | The IOC value to fetch | string | `domain` `md5` `sha256` `ip` `ipv6` |
**indicator_type** | optional | The IOC type of the indicator value | string | `crowdstrike indicator type` |
**resource_id** | optional | The resource ID of the IOC | string | `crowdstrike indicator id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.indicator_value | string | `domain` `md5` `sha256` `ip` `ipv6` | |
action_result.parameter.indicator_type | string | `crowdstrike indicator type` | |
action_result.parameter.resource_id | string | `crowdstrike indicator id` | |
action_result.data.\*.action | string | `crowdstrike indicator action` | |
action_result.data.\*.applied_globally | boolean | | True False |
action_result.data.\*.created_by | string | | |
action_result.data.\*.created_on | string | `date` | |
action_result.data.\*.created_timestamp | string | `date` | |
action_result.data.\*.deleted | boolean | | True False |
action_result.data.\*.description | string | | |
action_result.data.\*.expiration | string | `date` | |
action_result.data.\*.expiration_timestamp | string | `date` | |
action_result.data.\*.expired | boolean | | True False |
action_result.data.\*.from_parent | boolean | | True False |
action_result.data.\*.host_groups.\* | string | `crowdstrike host group id` | |
action_result.data.\*.id | string | `crowdstrike indicator id` | |
action_result.data.\*.metadata.av_hits | numeric | | |
action_result.data.\*.metadata.company_name | string | | |
action_result.data.\*.metadata.file_description | string | | |
action_result.data.\*.metadata.file_version | string | | |
action_result.data.\*.metadata.filename | string | | |
action_result.data.\*.metadata.original_filename | string | | |
action_result.data.\*.metadata.product_name | string | | |
action_result.data.\*.metadata.product_version | string | | |
action_result.data.\*.metadata.signed | boolean | | True False |
action_result.data.\*.mobile_action | string | | |
action_result.data.\*.modified_by | string | | |
action_result.data.\*.modified_on | string | | |
action_result.data.\*.modified_timestamp | string | `date` | |
action_result.data.\*.platforms.\* | string | `crowdstrike indicator platforms` | |
action_result.data.\*.severity | string | `severity` | |
action_result.data.\*.source | string | | |
action_result.data.\*.tags.\* | string | | |
action_result.data.\*.type | string | `crowdstrike indicator type` | |
action_result.data.\*.value | string | `ip` `ipv6` `md5` `sha256` `domain` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get process detail'

Queries CrowdStrike for the details of a process

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**falcon_process_id** | required | ID of the process to get the details of | string | `falcon process id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.falcon_process_id | string | `falcon process id` | |
action_result.data.\*.command_line | string | | |
action_result.data.\*.file_name | string | | |
action_result.data.\*.start_timestamp | string | | |
action_result.data.\*.stop_timestamp | string | | |
action_result.data.\*.device_id | string | `crowdstrike device id` | |
action_result.data.\*.start_timestamp_raw | string | | |
action_result.data.\*.stop_timestamp_raw | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get role'

Get information about a specific role

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**role_id** | required | Role ID to get information about. Comma separated list allowed | string | `crowdstrike user role id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.role_id | string | `crowdstrike user role id` | |
action_result.data.\*.id | string | | |
action_result.data.\*.display_name | string | | |
action_result.data.\*.description | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get session file'

Get RTR extracted file contents for the specified session and sha256 and add it to the vault

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**session_id** | required | RTR Session ID | string | `crowdstrike rtr session id` |
**file_hash** | required | SHA256 hash to retrieve | string | `sha256` |
**file_name** | optional | Filename to use for the archive name and the file within the archive | string | `filename` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.session_id | string | `crowdstrike rtr session id` | |
action_result.parameter.file_hash | string | `sha256` | |
action_result.parameter.file_name | string | `filename` | |
action_result.data.\*.vault_id | string | `sha1` `vault id` | |
action_result.data.\*.hash | string | `sha1` | |
action_result.data.\*.name | string | | |
action_result.data.\*.size | numeric | | |
action_result.data.\*.container_id | numeric | | |
action_result.summary.vault_id | string | `sha1` `vault id` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get user roles'

Get user roles

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_uuid** | required | Users Unqiue ID to get the roles for | string | `crowdstrike unique user id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.user_uuid | string | `crowdstrike unique user id` | |
action_result.data.\*.cid | string | | |
action_result.data.\*.grant_type | string | | |
action_result.data.\*.role_id | string | `crowdstrike user role id` | |
action_result.data.\*.role_name | string | | |
action_result.data.\*.uuid | string | `crowdstrike unique user id` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get zta data'

Get Zero Trust Assessment data for one or more hosts by providing agent IDs (AID)

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**agent_id** | required | List of agent IDs. Comma separated list allowed | string | `crowdstrike device id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.agent_id | string | `crowdstrike device id` | |
action_result.data.\*.aid | string | `crowdstrike device id` | |
action_result.data.\*.cid | string | `crowdstrike customer id` | |
action_result.data.\*.event_platform | string | | |
action_result.data.\*.sensor_file_status | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'hunt domain'

Hunt for a domain across all hosts in the environment

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | Domain to hunt | string | `domain` |
**count_only** | optional | Returns count of the devices the IOC ran on | boolean | |
**limit** | optional | Maximum devices to be fetched | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.domain | string | `domain` | |
action_result.parameter.count_only | boolean | | |
action_result.parameter.limit | numeric | | |
action_result.data.\*.device_id | string | `crowdstrike device id` | |
action_result.summary.device_count | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'hunt file'

Hunt for a file across all hosts in the environment

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** | required | Hash of the sample to hunt | string | `hash` `sha256` `sha1` `md5` |
**count_only** | optional | Returns count of the devices the IOC ran on | boolean | |
**limit** | optional | Maximum devices to be fetched | numeric | |
**cid** | optional | API uses the CID, of the parent or child, to determine which scope to query | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.hash | string | `hash` `sha256` `sha1` `md5` | |
action_result.parameter.count_only | boolean | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.cid | string | | |
action_result.data.\*.device_id | string | `crowdstrike device id` | |
action_result.summary.device_count | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'hunt ip'

Hunt for an IP across all hosts in the environment

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP to hunt | string | `ip` `ipv6` |
**count_only** | optional | Returns count of the devices the IOC ran on | boolean | |
**limit** | optional | Maximum devices to be fetched | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip | string | `ip` `ipv6` | |
action_result.parameter.count_only | boolean | | |
action_result.parameter.limit | numeric | | |
action_result.data.\*.device_id | string | `crowdstrike device id` | |
action_result.summary.device_count | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list alerts'

Fetch the list of alerts

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** | optional | Maximum alerts to be fetched | numeric | |
**filter** | optional | Filter expression used to limit the fetched alerts (FQL Syntax) | string | |
**sort** | optional | Property to sort by | string | |
**include_hidden** | optional | Include hidden alerts | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.filter | string | | |
action_result.parameter.sort | string | | |
action_result.parameter.include_hidden | boolean | | |
action_result.data.\*.composite_id | string | `crowdstrike alert id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.created_timestamp | string | | |
action_result.summary.total_alerts | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list custom indicators'

List the custom indicators

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator_value** | optional | The IOC value to filter on | string | `ip` `ipv6` `md5` `sha256` `domain` |
**indicator_type** | optional | The IOC type to filter on | string | `crowdstrike indicator type` |
**action** | optional | The action to filter on | string | `crowdstrike indicator action` |
**source** | optional | The source to filter on | string | |
**from_expiration** | optional | Filter by expiration date greater than or equal to this value | string | `date` |
**to_expiration** | optional | Filter by expiration date less than or equal to this value | string | `date` |
**limit** | optional | Maximum indicators to be fetched | numeric | |
**sort** | optional | Property to sort by | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.indicator_value | string | `ip` `ipv6` `md5` `sha256` `domain` | |
action_result.parameter.indicator_type | string | `crowdstrike indicator type` | |
action_result.parameter.action | string | `crowdstrike indicator action` | |
action_result.parameter.source | string | | |
action_result.parameter.from_expiration | string | `date` | |
action_result.parameter.to_expiration | string | `date` | |
action_result.parameter.limit | numeric | | |
action_result.parameter.sort | string | | |
action_result.data.\*.domain.\*.action | string | `crowdstrike indicator action` | |
action_result.data.\*.domain.\*.applied_globally | boolean | | True False |
action_result.data.\*.domain.\*.created_by | string | | |
action_result.data.\*.domain.\*.created_on | string | `date` | |
action_result.data.\*.domain.\*.created_timestamp | string | `date` | |
action_result.data.\*.domain.\*.deleted | boolean | | True False |
action_result.data.\*.domain.\*.description | string | | |
action_result.data.\*.domain.\*.expiration | string | `date` | |
action_result.data.\*.domain.\*.expiration_timestamp | string | `date` | |
action_result.data.\*.domain.\*.expired | boolean | | True False |
action_result.data.\*.domain.\*.from_parent | boolean | | True False |
action_result.data.\*.domain.\*.host_groups.\* | string | `crowdstrike host group id` | |
action_result.data.\*.domain.\*.id | string | `crowdstrike indicator id` | |
action_result.data.\*.domain.\*.metadata.av_hits | numeric | | |
action_result.data.\*.domain.\*.metadata.company_name | string | | |
action_result.data.\*.domain.\*.metadata.file_description | string | | |
action_result.data.\*.domain.\*.metadata.file_version | string | | |
action_result.data.\*.domain.\*.metadata.filename | string | | |
action_result.data.\*.domain.\*.metadata.original_filename | string | | |
action_result.data.\*.domain.\*.metadata.product_name | string | | |
action_result.data.\*.domain.\*.metadata.product_version | string | | |
action_result.data.\*.domain.\*.metadata.signed | boolean | | True False |
action_result.data.\*.domain.\*.mobile_action | string | | |
action_result.data.\*.domain.\*.modified_by | string | | |
action_result.data.\*.domain.\*.modified_on | string | | |
action_result.data.\*.domain.\*.modified_timestamp | string | `date` | |
action_result.data.\*.domain.\*.platforms.\* | string | `crowdstrike indicator platforms` | |
action_result.data.\*.domain.\*.severity | string | `severity` | |
action_result.data.\*.domain.\*.source | string | | |
action_result.data.\*.domain.\*.tags.\* | string | | |
action_result.data.\*.domain.\*.type | string | `crowdstrike indicator type` | |
action_result.data.\*.domain.\*.value | string | | |
action_result.data.\*.ipv4.\*.action | string | `crowdstrike indicator action` | |
action_result.data.\*.ipv4.\*.applied_globally | boolean | | True False |
action_result.data.\*.ipv4.\*.created_by | string | | |
action_result.data.\*.ipv4.\*.created_on | string | `date` | |
action_result.data.\*.ipv4.\*.created_timestamp | string | `date` | |
action_result.data.\*.ipv4.\*.deleted | boolean | | True False |
action_result.data.\*.ipv4.\*.description | string | | |
action_result.data.\*.ipv4.\*.expiration | string | `date` | |
action_result.data.\*.ipv4.\*.expiration_timestamp | string | `date` | |
action_result.data.\*.ipv4.\*.expired | boolean | | True False |
action_result.data.\*.ipv4.\*.from_parent | boolean | | True False |
action_result.data.\*.ipv4.\*.host_groups.\* | string | `crowdstrike host group id` | |
action_result.data.\*.ipv4.\*.id | string | `crowdstrike indicator id` | |
action_result.data.\*.ipv4.\*.metadata.av_hits | numeric | | |
action_result.data.\*.ipv4.\*.metadata.company_name | string | | |
action_result.data.\*.ipv4.\*.metadata.file_description | string | | |
action_result.data.\*.ipv4.\*.metadata.file_version | string | | |
action_result.data.\*.ipv4.\*.metadata.filename | string | | |
action_result.data.\*.ipv4.\*.metadata.original_filename | string | | |
action_result.data.\*.ipv4.\*.metadata.product_name | string | | |
action_result.data.\*.ipv4.\*.metadata.product_version | string | | |
action_result.data.\*.ipv4.\*.metadata.signed | boolean | | True False |
action_result.data.\*.ipv4.\*.mobile_action | string | | |
action_result.data.\*.ipv4.\*.modified_by | string | | |
action_result.data.\*.ipv4.\*.modified_on | string | | |
action_result.data.\*.ipv4.\*.modified_timestamp | string | `date` | |
action_result.data.\*.ipv4.\*.platforms.\* | string | `crowdstrike indicator platforms` | |
action_result.data.\*.ipv4.\*.severity | string | `severity` | |
action_result.data.\*.ipv4.\*.source | string | | |
action_result.data.\*.ipv4.\*.tags.\* | string | | |
action_result.data.\*.ipv4.\*.type | string | `crowdstrike indicator type` | |
action_result.data.\*.ipv4.\*.value | string | | |
action_result.data.\*.ipv6.\*.action | string | `crowdstrike indicator action` | |
action_result.data.\*.ipv6.\*.applied_globally | boolean | | True False |
action_result.data.\*.ipv6.\*.created_by | string | | |
action_result.data.\*.ipv6.\*.created_on | string | `date` | |
action_result.data.\*.ipv6.\*.created_timestamp | string | `date` | |
action_result.data.\*.ipv6.\*.deleted | boolean | | True False |
action_result.data.\*.ipv6.\*.description | string | | |
action_result.data.\*.ipv6.\*.expiration | string | `date` | |
action_result.data.\*.ipv6.\*.expiration_timestamp | string | `date` | |
action_result.data.\*.ipv6.\*.expired | boolean | | True False |
action_result.data.\*.ipv6.\*.from_parent | boolean | | True False |
action_result.data.\*.ipv6.\*.host_groups.\* | string | `crowdstrike host group id` | |
action_result.data.\*.ipv6.\*.id | string | `crowdstrike indicator id` | |
action_result.data.\*.ipv6.\*.metadata.av_hits | numeric | | |
action_result.data.\*.ipv6.\*.metadata.company_name | string | | |
action_result.data.\*.ipv6.\*.metadata.file_description | string | | |
action_result.data.\*.ipv6.\*.metadata.file_version | string | | |
action_result.data.\*.ipv6.\*.metadata.filename | string | | |
action_result.data.\*.ipv6.\*.metadata.original_filename | string | | |
action_result.data.\*.ipv6.\*.metadata.product_name | string | | |
action_result.data.\*.ipv6.\*.metadata.product_version | string | | |
action_result.data.\*.ipv6.\*.metadata.signed | boolean | | True False |
action_result.data.\*.ipv6.\*.mobile_action | string | | |
action_result.data.\*.ipv6.\*.modified_by | string | | |
action_result.data.\*.ipv6.\*.modified_on | string | | |
action_result.data.\*.ipv6.\*.modified_timestamp | string | `date` | |
action_result.data.\*.ipv6.\*.platforms.\* | string | `crowdstrike indicator platforms` | |
action_result.data.\*.ipv6.\*.severity | string | `severity` | |
action_result.data.\*.ipv6.\*.source | string | | |
action_result.data.\*.ipv6.\*.tags.\* | string | | |
action_result.data.\*.ipv6.\*.type | string | `crowdstrike indicator type` | |
action_result.data.\*.ipv6.\*.value | string | | |
action_result.data.\*.md5.\*.action | string | `crowdstrike indicator action` | |
action_result.data.\*.md5.\*.applied_globally | boolean | | True False |
action_result.data.\*.md5.\*.created_by | string | | |
action_result.data.\*.md5.\*.created_on | string | `date` | |
action_result.data.\*.md5.\*.created_timestamp | string | `date` | |
action_result.data.\*.md5.\*.deleted | boolean | | True False |
action_result.data.\*.md5.\*.description | string | | |
action_result.data.\*.md5.\*.expiration | string | `date` | |
action_result.data.\*.md5.\*.expiration_timestamp | string | `date` | |
action_result.data.\*.md5.\*.expired | boolean | | True False |
action_result.data.\*.md5.\*.from_parent | boolean | | True False |
action_result.data.\*.md5.\*.host_groups.\* | string | `crowdstrike host group id` | |
action_result.data.\*.md5.\*.id | string | `crowdstrike indicator id` | |
action_result.data.\*.md5.\*.metadata.av_hits | numeric | | |
action_result.data.\*.md5.\*.metadata.company_name | string | | |
action_result.data.\*.md5.\*.metadata.file_description | string | | |
action_result.data.\*.md5.\*.metadata.file_version | string | | |
action_result.data.\*.md5.\*.metadata.filename | string | | |
action_result.data.\*.md5.\*.metadata.original_filename | string | | |
action_result.data.\*.md5.\*.metadata.product_name | string | | |
action_result.data.\*.md5.\*.metadata.product_version | string | | |
action_result.data.\*.md5.\*.metadata.signed | boolean | | True False |
action_result.data.\*.md5.\*.mobile_action | string | | |
action_result.data.\*.md5.\*.modified_by | string | | |
action_result.data.\*.md5.\*.modified_on | string | | |
action_result.data.\*.md5.\*.modified_timestamp | string | `date` | |
action_result.data.\*.md5.\*.platforms.\* | string | `crowdstrike indicator platforms` | |
action_result.data.\*.md5.\*.severity | string | `severity` | |
action_result.data.\*.md5.\*.source | string | | |
action_result.data.\*.md5.\*.tags.\* | string | | |
action_result.data.\*.md5.\*.type | string | `crowdstrike indicator type` | |
action_result.data.\*.md5.\*.value | string | | |
action_result.data.\*.sha256.\*.action | string | `crowdstrike indicator action` | |
action_result.data.\*.sha256.\*.applied_globally | boolean | | True False |
action_result.data.\*.sha256.\*.created_by | string | | |
action_result.data.\*.sha256.\*.created_on | string | `date` | |
action_result.data.\*.sha256.\*.created_timestamp | string | `date` | |
action_result.data.\*.sha256.\*.deleted | boolean | | True False |
action_result.data.\*.sha256.\*.description | string | | |
action_result.data.\*.sha256.\*.expiration | string | `date` | |
action_result.data.\*.sha256.\*.expiration_timestamp | string | `date` | |
action_result.data.\*.sha256.\*.expired | boolean | | True False |
action_result.data.\*.sha256.\*.from_parent | boolean | | True False |
action_result.data.\*.sha256.\*.host_groups.\* | string | `crowdstrike host group id` | |
action_result.data.\*.sha256.\*.id | string | `crowdstrike indicator id` | |
action_result.data.\*.sha256.\*.metadata.av_hits | numeric | | |
action_result.data.\*.sha256.\*.metadata.company_name | string | | |
action_result.data.\*.sha256.\*.metadata.file_description | string | | |
action_result.data.\*.sha256.\*.metadata.file_version | string | | |
action_result.data.\*.sha256.\*.metadata.filename | string | | |
action_result.data.\*.sha256.\*.metadata.original_filename | string | | |
action_result.data.\*.sha256.\*.metadata.product_name | string | | |
action_result.data.\*.sha256.\*.metadata.product_version | string | | |
action_result.data.\*.sha256.\*.metadata.signed | boolean | | True False |
action_result.data.\*.sha256.\*.mobile_action | string | | |
action_result.data.\*.sha256.\*.modified_by | string | | |
action_result.data.\*.sha256.\*.modified_on | string | | |
action_result.data.\*.sha256.\*.modified_timestamp | string | `date` | |
action_result.data.\*.sha256.\*.platforms.\* | string | `crowdstrike indicator platforms` | |
action_result.data.\*.sha256.\*.severity | string | `severity` | |
action_result.data.\*.sha256.\*.source | string | | |
action_result.data.\*.sha256.\*.tags.\* | string | | |
action_result.data.\*.sha256.\*.type | string | `crowdstrike indicator type` | |
action_result.data.\*.sha256.\*.value | string | | |
action_result.summary.alerts_found | numeric | | |
action_result.summary.total_domain | numeric | | |
action_result.summary.total_ipv4 | numeric | | |
action_result.summary.total_ipv6 | numeric | | |
action_result.summary.total_md5 | numeric | | |
action_result.summary.total_sha256 | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list epp alerts'

Fetch the list of EPP alerts

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** | optional | Maximum alerts to be fetched | numeric | |
**filter** | optional | Filter expression used to limit the fetched alerts (FQL Syntax) | string | |
**sort** | optional | Property to sort by | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.filter | string | | |
action_result.parameter.sort | string | | |
action_result.data.\*.composite_id | string | `crowdstrike alert id` | |
action_result.data.\*.status | string | | |
action_result.data.\*.created_timestamp | string | | |
action_result.summary.total_alerts | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list groups'

Fetch the details of the host groups

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** | optional | Maximum host groups to be fetched | numeric | |
**filter** | optional | Filter expression used to limit the fetched host groups (FQL Syntax) | string | |
**sort** | optional | Property to sort by | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.filter | string | | |
action_result.parameter.sort | string | | |
action_result.data.\*.name | string | | |
action_result.data.\*.id | string | `crowdstrike host group id` | |
action_result.data.\*.description | string | | |
action_result.data.\*.assignment_rule | string | | |
action_result.data.\*.created_by | string | `email` | |
action_result.data.\*.created_timestamp | string | | |
action_result.data.\*.group_type | string | | |
action_result.data.\*.modified_by | string | `email` | |
action_result.data.\*.modified_timestamp | string | | |
action_result.summary.total_host_groups | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list ioa platforms'

Get the platforms that support IOA rules

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.data.\*.resources.\* | string | | |
action_result.summary.result_count | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list ioa rule groups'

Get the configured IOA rule groups

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**fql_query** | optional | FQL query to filter rule groups | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.fql_query | string | | |
action_result.data.\*.resources.\*.id | string | `crowdstrike ioa rule group id` | |
action_result.data.\*.resources.\*.version | numeric | | |
action_result.data.\*.resources.\*.enabled | boolean | | True False |
action_result.data.\*.resources.\*.name | string | | |
action_result.data.\*.resources.\*.description | string | | |
action_result.data.\*.resources.\*.platform | string | | |
action_result.data.\*.resources.\*.comment | string | | |
action_result.summary.result_count | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list ioa severities'

Get the severity levels that can be assigned to IOA rules

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.data.\*.resources.\* | string | | |
action_result.summary.result_count | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list ioa types'

Get the IOA types and their parameters

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**platform** | optional | Show only IOA types supported by the given platform | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.platform | string | | |
action_result.data.\*.resources.\*.id | string | | |
action_result.data.\*.resources.\*.name | string | | |
action_result.data.\*.resources.\*.platform | string | | |
action_result.data.\*.resources.\*.long_desc | string | | |
action_result.data.\*.resources.\*.fields_pretty | string | | |
action_result.summary.result_count | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list processes'

Lists the processes a specified IOC ran on for a specific device

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** | required | IOC to get the processes of | string | `hash` `sha256` `sha1` `md5` `domain` |
**id** | required | Device ID to get the processes ran on | string | `crowdstrike device id` |
**limit** | optional | Maximum processes to be fetched | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ioc | string | `hash` `sha256` `sha1` `md5` `domain` | |
action_result.parameter.id | string | `crowdstrike device id` | |
action_result.parameter.limit | numeric | | |
action_result.data.\*.falcon_process_id | string | `falcon process id` | |
action_result.data.\*.device_id | string | | |
action_result.data.\*.ioc | string | | |
action_result.data.\*.ioc_type | string | | |
action_result.data.\*.limit | numeric | | |
action_result.summary.process_count | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list put files'

Queries for files uploaded to Crowdstrike for use with the RTR `put` command

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** | optional | FQL query to filter results | string | |
**sort** | optional | Sort results | string | |
**offset** | optional | Starting index of overall result set | string | |
**limit** | optional | Number of files to return | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.filter | string | | |
action_result.parameter.sort | string | | |
action_result.parameter.offset | string | | |
action_result.parameter.limit | numeric | | |
action_result.data.\*.name | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.file_type | string | | |
action_result.data.\*.size | numeric | | |
action_result.summary.total_files | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list roles'

Get the list of roles

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.data.\*.resources.\*.id | string | | |
action_result.data.\*.resources.\*.display_name | string | | |
action_result.data.\*.resources.\*.description | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list session files'

Get a list of files for the specified RTR session

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**session_id** | required | RTR Session ID | string | `crowdstrike rtr session id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.session_id | string | `crowdstrike rtr session id` | |
action_result.data.\*.resources.\*.name | string | `file name` | |
action_result.data.\*.resources.\*.sha256 | string | `sha256` | |
action_result.data.\*.resources.\*.session_id | string | `crowdstrike rtr session id` | |
action_result.summary.total_files | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list sessions'

Lists the active RTR sessions

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** | optional | Maximum sessions to be fetched | numeric | |
**filter** | optional | Filter expression used to limit the fetched sessions (FQL Syntax) | string | |
**sort** | optional | Property to sort by | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.filter | string | | |
action_result.parameter.sort | string | | |
action_result.data.\*.id | string | `crowdstrike rtr session id` | |
action_result.data.\*.hostname | string | | |
action_result.data.\*.created_at | string | | |
action_result.data.\*.device_id | string | `crowdstrike device id` | |
action_result.summary.total_sessions | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'make request'

make request

Type: **generic** <br>
Read only: **False**

'make request' action for the app. Used to handle arbitrary HTTP requests with the app's asset

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**http_method** | required | The HTTP method to use for the request. | string | |
**endpoint** | required | CrowdStrike API endpoint to call, appended to the asset base URL. Example: '/devices/queries/devices/v1' | string | |
**headers** | optional | The headers to send with the request (JSON object). An example is {'Content-Type': 'application/json'} | string | |
**query_parameters** | optional | Parameters to append to the URL (JSON object or query string). An example is ?key=value&key2=value2 | string | |
**body** | optional | The body to send with the request (JSON object). An example is {'key': 'value', 'key2': 'value2'} | string | |
**timeout** | optional | The timeout for the request in seconds. | numeric | |
**verify_ssl** | optional | Whether to verify the SSL certificate. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.http_method | string | | |
action_result.parameter.endpoint | string | | |
action_result.parameter.headers | string | | |
action_result.parameter.query_parameters | string | | |
action_result.parameter.body | string | | |
action_result.parameter.timeout | numeric | | |
action_result.parameter.verify_ssl | boolean | | |
action_result.data.\*.status_code | numeric | | 200 |
action_result.data.\*.response_body | string | | {"resources": [], "errors": []} |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list users'

Gets the list of users

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.data.\*.resources.\*.first_name | string | | |
action_result.data.\*.resources.\*.last_name | string | | |
action_result.data.\*.resources.\*.uid | string | `crowdstrike user id` | |
action_result.data.\*.resources.\*.uuid | string | `crowdstrike unique user id` | |
action_result.data.\*.resources.\*.cid | string | `crowdstrike customer id` | |
action_result.summary.total_users | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'query device'

Fetch the list of devices

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** | optional | Maximum devices to be fetched | numeric | |
**offset** | optional | Starting index of overall result set from which to return ids. (Defaults to 0) | numeric | |
**filter** | optional | Filter expression used to limit the fetched devices (FQL Syntax) | string | |
**sort** | optional | Property to sort by | string | |
**cid** | optional | A single, specific tenant id to search. By default, will search asset main tenant and all listed subtenants; to search only main tenant (even if you have subtenants) use 'main' | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.offset | numeric | | |
action_result.parameter.filter | string | | |
action_result.parameter.sort | string | | |
action_result.parameter.cid | string | | |
action_result.data.\*.hostname | string | `host name` | |
action_result.data.\*.device_id | string | `crowdstrike device id` | |
action_result.data.\*.status | string | | |
action_result.summary.total_devices | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'quarantine device'

This action contains the host, which stops any network communications to locations other than the CrowdStrike cloud and IPs specified in the user's containment policy.

Type: **contain** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | optional | Comma-separated list of device IDs | string | `crowdstrike device id` |
**hostname** | optional | Comma-separated list of hostnames | string | `host name` |
**cid** | optional | A single, specific tenant id to search. By default, will search asset main tenant and all listed subtenants; to search only main tenant (even if you have subtenants) use 'main' | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.device_id | string | `crowdstrike device id` | |
action_result.parameter.hostname | string | `host name` | |
action_result.parameter.cid | string | | |
action_result.data.\*.id | string | `crowdstrike device id` | |
action_result.data.\*.path | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'remove hosts'

Remove one or more hosts from an existing static host group

Type: **contain** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | optional | Comma-separated list of device IDs | string | `crowdstrike device id` |
**hostname** | optional | Comma-separated list of hostnames | string | `host name` |
**host_group_id** | required | Static host group ID | string | `crowdstrike host group id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.device_id | string | `crowdstrike device id` | |
action_result.parameter.hostname | string | `host name` | |
action_result.parameter.host_group_id | string | `crowdstrike host group id` | |
action_result.data.\*.id | string | `crowdstrike host group id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.group_type | string | | |
action_result.data.\*.assignment_rule | string | | |
action_result.data.\*.created_by | string | | |
action_result.data.\*.created_timestamp | string | | |
action_result.data.\*.modified_by | string | | |
action_result.data.\*.modified_timestamp | string | | |
action_result.summary.total_removed_device | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'resolve epp alerts'

Update the status of the given EPP alerts

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_ids** | required | Comma-separated list of alert IDs (composite IDs) | string | `crowdstrike alert id` |
**status** | required | Status to set the alerts to | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.alert_ids | string | `crowdstrike alert id` | |
action_result.parameter.status | string | | |
action_result.data.\*.meta.writes.resources_affected | numeric | | |
action_result.summary.alerts_affected | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'run admin command'

Execute an RTR administrator command on a single host

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | Device ID to run command on | string | `crowdstrike device id` |
**session_id** | required | RTR Session ID | string | `crowdstrike rtr session id` |
**command** | required | RTR admin command to run | string | |
**data** | optional | Additional data/parameters for the command | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.device_id | string | `crowdstrike device id` | |
action_result.parameter.session_id | string | `crowdstrike rtr session id` | |
action_result.parameter.command | string | | |
action_result.parameter.data | string | | |
action_result.data.\*.resources.\*.base_command | string | | |
action_result.data.\*.resources.\*.complete | boolean | | True False |
action_result.data.\*.resources.\*.session_id | string | `crowdstrike rtr session id` | |
action_result.data.\*.resources.\*.stderr | string | | |
action_result.data.\*.resources.\*.stdout | string | | |
action_result.data.\*.resources.\*.task_id | string | | |
action_result.summary.cloud_request_id | string | `crowdstrike cloud request id` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'run command'

Execute an RTR command on a single host

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | Device ID to run command on | string | `md5` `crowdstrike device id` |
**session_id** | required | RTR Session ID | string | `crowdstrike rtr session id` |
**command** | required | RTR command to run | string | |
**data** | optional | Additional data/parameters for the command | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.device_id | string | `md5` `crowdstrike device id` | |
action_result.parameter.session_id | string | `crowdstrike rtr session id` | |
action_result.parameter.command | string | | |
action_result.parameter.data | string | | |
action_result.data.\*.resources.\*.base_command | string | | |
action_result.data.\*.resources.\*.complete | boolean | | True False |
action_result.data.\*.resources.\*.session_id | string | `crowdstrike rtr session id` | |
action_result.data.\*.resources.\*.stderr | string | | |
action_result.data.\*.resources.\*.stdout | string | | |
action_result.data.\*.resources.\*.task_id | string | | |
action_result.summary.cloud_request_id | string | `crowdstrike cloud request id` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'run query'

Run a generic query against a CrowdStrike API query endpoint

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**endpoint** | required | API endpoint path in the format: /<service>/queries/<resource>/<version> (ex: /devices/queries/devices/v1) | string | |
**limit** | optional | Maximum number of results to return | numeric | |
**filter** | optional | Filter expression (FQL Syntax) (ex: last_seen: >'2020-01-01') | string | |
**sort** | optional | Property to sort by | string | |
**offset** | optional | Starting index for results | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.endpoint | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.filter | string | | |
action_result.parameter.sort | string | | |
action_result.parameter.offset | numeric | | |
action_result.data.\*.resource_id | string | | |
action_result.summary.total_objects | numeric | | |
action_result.summary.total_count | numeric | | |
action_result.summary.query_time | numeric | | |
action_result.summary.powered_by | string | | |
action_result.summary.trace_id | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'unquarantine device'

This action lifts containment on the host, which returns its network communications to normal.

Type: **correct** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | optional | Comma-separated list of device IDs | string | `crowdstrike device id` |
**hostname** | optional | Comma-separated list of hostnames | string | `host name` |
**cid** | optional | A single, specific tenant id to search. By default, will search asset main tenant and all listed subtenants; to search only main tenant (even if you have subtenants) use 'main' | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.device_id | string | `crowdstrike device id` | |
action_result.parameter.hostname | string | `host name` | |
action_result.parameter.cid | string | | |
action_result.data.\*.id | string | `crowdstrike device id` | |
action_result.data.\*.path | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'url reputation'

Queries CrowdStrike for the URL reputation info

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to get the reputation of | string | `url` |
**limit** | optional | Maximum reports to be fetched | numeric | |
**sort** | optional | Property to sort by | string | |
**offset** | optional | Starting index of overall result set | numeric | |
**detail_report** | optional | Provide a detailed report of the URL | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.url | string | `url` | |
action_result.parameter.limit | numeric | | |
action_result.parameter.sort | string | | |
action_result.parameter.offset | numeric | | |
action_result.parameter.detail_report | boolean | | |
action_result.data.\*.cid | string | | |
action_result.data.\*.created_timestamp | string | `date` | |
action_result.data.\*.id | string | `crowdstrike resource id` | |
action_result.data.\*.ioc_report_broad_csv_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_broad_json_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_broad_maec_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_broad_stix_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_strict_csv_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_strict_json_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_strict_maec_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.ioc_report_strict_stix_artifact_id | string | `crowdstrike artifact id` | |
action_result.data.\*.origin | string | | |
action_result.data.\*.user_id | string | | |
action_result.data.\*.user_name | string | | |
action_result.data.\*.user_uuid | string | | |
action_result.data.\*.user_tags | string | | |
action_result.data.\*.verdict | string | | |
action_result.summary.verdict | string | | |
action_result.summary.total_reports | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update epp alerts'

Update the given EPP alerts

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_ids** | required | Comma-separated list of alert IDs (composite IDs) | string | `crowdstrike alert id` |
**comment** | optional | Comment to append to the alerts | string | |
**assigned_to_user** | optional | User to assign the alerts to (email, UUID, or name) | string | |
**unassign** | optional | Unassign the alerts | string | |
**show_in_ui** | optional | Whether the alerts should be displayed in the UI | boolean | |
**status** | optional | Status to set the alerts to | string | |
**add_tags** | optional | Comma-separated list of tags to add | string | |
**remove_tags** | optional | Comma-separated list of tags to remove | string | |
**remove_tags_by_prefix** | optional | Remove all tags matching the given prefix | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.alert_ids | string | `crowdstrike alert id` | |
action_result.parameter.comment | string | | |
action_result.parameter.assigned_to_user | string | | |
action_result.parameter.unassign | string | | |
action_result.parameter.show_in_ui | boolean | | |
action_result.parameter.status | string | | |
action_result.parameter.add_tags | string | | |
action_result.parameter.remove_tags | string | | |
action_result.parameter.remove_tags_by_prefix | string | | |
action_result.data.\*.meta.writes.resources_affected | numeric | | |
action_result.summary.alerts_affected | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update indicator'

Update an IOC

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** | required | The IOC to update | string | `ip` `md5` `sha256` `domain` |
**action** | optional | Action to take when a host observes the IOC | string | `crowdstrike indicator action` |
**platforms** | optional | Comma-separated list of platforms the IOC applies to | string | `crowdstrike indicator platforms` |
**expiration** | optional | Number of days after which the IOC expires | numeric | |
**source** | optional | The source of the IOC | string | |
**description** | optional | Description of the IOC | string | |
**tags** | optional | Comma-separated list of tags to apply to the IOC | string | |
**severity** | optional | The severity of the IOC | string | `severity` |
**host_groups** | optional | Comma-separated list of host group IDs the IOC applies to. Use 'all' to apply globally | string | `crowdstrike host group id` |
**filename** | optional | The filename metadata of the IOC | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ioc | string | `ip` `md5` `sha256` `domain` | |
action_result.parameter.action | string | `crowdstrike indicator action` | |
action_result.parameter.platforms | string | `crowdstrike indicator platforms` | |
action_result.parameter.expiration | numeric | | |
action_result.parameter.source | string | | |
action_result.parameter.description | string | | |
action_result.parameter.tags | string | | |
action_result.parameter.severity | string | `severity` | |
action_result.parameter.host_groups | string | `crowdstrike host group id` | |
action_result.parameter.filename | string | | |
action_result.data.\*.ioc | string | | |
action_result.data.\*.ioc_type | string | | |
action_result.data.\*.action | string | | |
action_result.data.\*.source | string | | |
action_result.data.\*.description | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update ioa rule'

Update an existing IOA rule

Type: **contain** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**rule_group_id** | required | ID of the rule group | string | `crowdstrike ioa rule group id` |
**rule_group_version** | required | Version of the rule group | numeric | |
**rule_id** | required | ID of the rule to update | string | `crowdstrike ioa rule id` |
**rule_version** | required | Version of the rule | numeric | |
**name** | required | Name of the rule | string | |
**description** | required | Description of the rule | string | |
**severity** | required | Severity of the rule | string | |
**disposition_id** | required | Disposition ID | numeric | |
**field_values** | required | JSON list of field values for the rule | string | |
**comment** | optional | Comment for the rule | string | |
**enabled** | optional | Whether the rule is enabled | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.rule_group_id | string | `crowdstrike ioa rule group id` | |
action_result.parameter.rule_group_version | numeric | | |
action_result.parameter.rule_id | string | `crowdstrike ioa rule id` | |
action_result.parameter.rule_version | numeric | | |
action_result.parameter.name | string | | |
action_result.parameter.description | string | | |
action_result.parameter.severity | string | | |
action_result.parameter.disposition_id | numeric | | |
action_result.parameter.field_values | string | | |
action_result.parameter.comment | string | | |
action_result.parameter.enabled | boolean | | |
action_result.data.\*.resources.\*.id | string | `crowdstrike ioa rule group id` | |
action_result.data.\*.resources.\*.name | string | | |
action_result.data.\*.resources.\*.rules.\*.name | string | | |
action_result.data.\*.resources.\*.rules.\*.comment | string | | |
action_result.data.\*.resources.\*.rules.\*.deleted | boolean | | True False |
action_result.data.\*.resources.\*.rules.\*.enabled | boolean | | True False |
action_result.data.\*.resources.\*.rules.\*.created_by | string | `crowdstrike unique user id` | |
action_result.data.\*.resources.\*.rules.\*.created_on | string | `date` | |
action_result.data.\*.resources.\*.rules.\*.pattern_id | string | | |
action_result.data.\*.resources.\*.rules.\*.customer_id | string | `crowdstrike customer id` | |
action_result.data.\*.resources.\*.rules.\*.description | string | | |
action_result.data.\*.resources.\*.rules.\*.modified_by | string | `crowdstrike unique user id` | |
action_result.data.\*.resources.\*.rules.\*.modified_on | string | `date` | |
action_result.data.\*.resources.\*.rules.\*.ruletype_id | string | | |
action_result.data.\*.resources.\*.rules.\*.committed_on | string | `date` | |
action_result.data.\*.resources.\*.rules.\*.field_values.\*.name | string | | |
action_result.data.\*.resources.\*.rules.\*.field_values.\*.value | string | | |
action_result.data.\*.resources.\*.rules.\*.field_values.\*.label | string | | |
action_result.data.\*.resources.\*.rules.\*.field_values.\*.type | string | | |
action_result.data.\*.resources.\*.rules.\*.field_values.\*.values.\*.label | string | | |
action_result.data.\*.resources.\*.rules.\*.field_values.\*.values.\*.value | string | | |
action_result.data.\*.resources.\*.rules.\*.field_values.\*.final_value | string | | |
action_result.data.\*.resources.\*.rules.\*.magic_cookie | numeric | | |
action_result.data.\*.resources.\*.rules.\*.rulegroup_id | string | `crowdstrike ioa rule group id` | |
action_result.data.\*.resources.\*.rules.\*.ruletype_name | string | | |
action_result.data.\*.resources.\*.rules.\*.disposition_id | numeric | | |
action_result.data.\*.resources.\*.rules.\*.instance_id | string | `crowdstrike ioa rule id` | |
action_result.data.\*.resources.\*.rules.\*.instance_version | numeric | | |
action_result.data.\*.resources.\*.rules.\*.pattern_severity | string | | |
action_result.data.\*.resources.\*.rules.\*.action_label | string | | |
action_result.data.\*.resources.\*.comment | string | | |
action_result.data.\*.resources.\*.enabled | boolean | | True False |
action_result.data.\*.resources.\*.deleted | boolean | | True False |
action_result.data.\*.resources.\*.version | numeric | | |
action_result.data.\*.resources.\*.platform | string | | |
action_result.data.\*.resources.\*.rule_ids.\* | string | `crowdstrike ioa rule id` | |
action_result.data.\*.resources.\*.created_by | string | `crowdstrike unique user id` | |
action_result.data.\*.resources.\*.created_on | string | `date` | |
action_result.data.\*.resources.\*.customer_id | string | `crowdstrike customer id` | |
action_result.data.\*.resources.\*.description | string | | |
action_result.data.\*.resources.\*.modified_by | string | `crowdstrike unique user id` | |
action_result.data.\*.resources.\*.modified_on | string | `date` | |
action_result.data.\*.resources.\*.committed_on | string | `date` | |
action_result.summary.rule_group_id | string | `crowdstrike ioa rule group id` | |
action_result.summary.rule_group_version | numeric | | |
action_result.summary.rule_id | string | `crowdstrike ioa rule id` | |
action_result.summary.rule_version | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update ioa rule group'

Update an existing IOA rule group

Type: **contain** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | ID of the rule group to update | string | `crowdstrike ioa rule group id` |
**version** | required | Version of the rule group | numeric | |
**name** | required | Name of the rule group | string | |
**description** | required | Description of the rule group | string | |
**enabled** | optional | Whether the rule group is enabled | boolean | |
**comment** | required | Comment for the update | string | |
**assign_policy_id** | optional | Comma-separated list of prevention policy IDs to attach | string | `crowdstrike prevention policy id` |
**remove_policy_id** | optional | Comma-separated list of prevention policy IDs to remove | string | `crowdstrike prevention policy id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.id | string | `crowdstrike ioa rule group id` | |
action_result.parameter.version | numeric | | |
action_result.parameter.name | string | | |
action_result.parameter.description | string | | |
action_result.parameter.enabled | boolean | | |
action_result.parameter.comment | string | | |
action_result.parameter.assign_policy_id | string | `crowdstrike prevention policy id` | |
action_result.parameter.remove_policy_id | string | `crowdstrike prevention policy id` | |
action_result.data.\*.resources.\*.id | string | `crowdstrike ioa rule group id` | |
action_result.data.\*.resources.\*.customer_id | string | `crowdstrike customer id` | |
action_result.data.\*.resources.\*.enabled | boolean | | True False |
action_result.data.\*.resources.\*.name | string | | |
action_result.data.\*.resources.\*.description | string | | |
action_result.data.\*.resources.\*.platform | string | | |
action_result.data.\*.resources.\*.deleted | boolean | | True False |
action_result.data.\*.resources.\*.rule_ids.\* | string | `crowdstrike ioa rule id` | |
action_result.data.\*.resources.\*.comment | string | | |
action_result.data.\*.resources.\*.version | numeric | | |
action_result.data.\*.resources.\*.created_by | string | `crowdstrike user id` | |
action_result.data.\*.resources.\*.created_on | string | | |
action_result.data.\*.resources.\*.modified_by | string | `crowdstrike user id` | |
action_result.data.\*.resources.\*.modified_on | string | | |
action_result.data.\*.resources.\*.committed_on | string | | |
action_result.data.\*.resources.\*.assigned_policy_ids.\* | string | `crowdstrike prevention policy id` | |
action_result.data.\*.resources.\*.removed_policy_ids.\* | string | `crowdstrike prevention policy id` | |
action_result.summary.rule_group_id | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'upload indicator'

Upload an IOC

Type: **contain** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** | required | The IOC to upload | string | `sha256` `md5` `domain` `ip` `ipv6` |
**action** | required | Action to take when a host observes the IOC | string | `crowdstrike indicator action` |
**platforms** | required | Comma-separated list of platforms the IOC applies to | string | `crowdstrike indicator platforms` |
**expiration** | optional | Number of days after which the IOC expires | numeric | |
**source** | optional | The source of the IOC | string | |
**description** | optional | Description of the IOC | string | |
**tags** | optional | Comma-separated list of tags to apply to the IOC | string | |
**severity** | optional | The severity of the IOC | string | `severity` |
**host_groups** | optional | Comma-separated list of host group IDs the IOC applies to | string | `crowdstrike host group id` |
**filename** | optional | The filename metadata of the IOC | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ioc | string | `sha256` `md5` `domain` `ip` `ipv6` | |
action_result.parameter.action | string | `crowdstrike indicator action` | |
action_result.parameter.platforms | string | `crowdstrike indicator platforms` | |
action_result.parameter.expiration | numeric | | |
action_result.parameter.source | string | | |
action_result.parameter.description | string | | |
action_result.parameter.tags | string | | |
action_result.parameter.severity | string | `severity` | |
action_result.parameter.host_groups | string | `crowdstrike host group id` | |
action_result.parameter.filename | string | | |
action_result.data.\*.action | string | `crowdstrike indicator action` | |
action_result.data.\*.applied_globally | boolean | | True False |
action_result.data.\*.created_by | string | | |
action_result.data.\*.created_on | string | `date` | |
action_result.data.\*.created_timestamp | string | `date` | |
action_result.data.\*.deleted | boolean | | True False |
action_result.data.\*.description | string | | |
action_result.data.\*.expiration | string | `date` | |
action_result.data.\*.expiration_timestamp | string | `date` | |
action_result.data.\*.expired | boolean | | True False |
action_result.data.\*.from_parent | boolean | | True False |
action_result.data.\*.host_groups.\* | string | `crowdstrike host group id` | |
action_result.data.\*.id | string | `crowdstrike indicator id` | |
action_result.data.\*.metadata.av_hits | numeric | | |
action_result.data.\*.metadata.filename | string | | |
action_result.data.\*.metadata.signed | boolean | | True False |
action_result.data.\*.modified_by | string | | |
action_result.data.\*.modified_on | string | | |
action_result.data.\*.modified_timestamp | string | `date` | |
action_result.data.\*.platforms.\* | string | `crowdstrike indicator platforms` | |
action_result.data.\*.severity | string | `severity` | |
action_result.data.\*.source | string | | |
action_result.data.\*.tags.\* | string | | |
action_result.data.\*.type | string | `crowdstrike indicator type` | |
action_result.data.\*.value | string | `ip` `ipv6` `md5` `sha256` `domain` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'upload put file'

Upload a new put-file to use for the RTR `put` command

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | required | Vault ID of file to upload | string | `vault id` |
**description** | required | File description | string | |
**file_name** | optional | Filename to use (if different than actual file name) | string | `filename` |
**comment** | optional | Comment for the audit log | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.vault_id | string | `vault id` | |
action_result.parameter.description | string | | |
action_result.parameter.file_name | string | `filename` | |
action_result.parameter.comment | string | | |
action_result.data.\*.meta.powered_by | string | | |
action_result.data.\*.meta.query_time | numeric | | |
action_result.data.\*.meta.trace_id | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
