# CrowdStrike OAuth API

Publisher: Splunk \
Connector Version: 5.0.0 \
Product Vendor: CrowdStrike \
Product Name: CrowdStrike \
Minimum Product Version: 6.3.0

This app integrates with CrowdStrike OAuth2 authentication standard to implement querying of endpoint security data

## Steps to create API clients and key

- In Falcon UI, Go to menubar on the left, From **Support and resources** section, Select **API clients and keys**.
- Click on **Create API client**.
- Add **Client name**, **Description(optional)** and [Scopes](#minimal-required-scopes-to-run-all-actions) (defined below).
- Click on **Create** to obtain the **Client ID** and **Client secret**.

## Minimal required scope(s) (Action wise)

| **Action** | **Required Scope(s)** | **Read** | **Write** |
|-------------------------------------------------------------|--------------------------------|----------------------|----------------------|
| [test connectivity](#action-test-connectivity) | Hosts | ✓ | ✗ |
| [run query](#action-run-query) | Hosts | ✓ | ✗ |
| [query device](#action-query-device) | Hosts | ✓ | ✗ |
| [list groups](#action-list-groups) | Host Groups | ✓ | ✗ |
| [quarantine device](#action-quarantine-device) | Hosts | ✓ | ✓ |
| [unquarantine device](#action-unquarantine-device) | Hosts | ✓ | ✓ |
| [assign hosts](#action-assign-hosts) | Hosts <br> Hosts Group | ✓ <br> ✗ | ✗ <br> ✓ |
| [remove hosts](#action-remove-hosts) | Hosts <br> Hosts Group | ✓ <br> ✗ | ✗ <br> ✓ |
| [create session](#action-create-session) | Real time response(RTR) | ✓ | ✗ |
| [delete session](#action-delete-session) | Real time response(RTR) | ✓ | ✗ |
| [list detections](#action-list-detections) | Detections | ✓ | ✗ |
| [get detections details](#action-get-detections-details) | Detections | ✓ | ✗ |
| [update detections](#action-update-detections) | Detections | ✗ | ✓ |
| [list alerts](#action-list-alerts) | Alerts | ✓ | ✗ |
| [list epp alerts](#action-list-epp-alerts) | Alerts | ✓ | ✗ |
| [get epp details](#action-get-epp-details) | Alerts | ✓ | ✗ |
| [update epp alerts](#action-update-epp-alerts) | Alerts | ✗ | ✓ |
| [resolve epp alerts](#action-resolve-epp-alerts) | Alerts | ✗ | ✓ |
| [list sessions](#action-list-sessions) | Real time response(RTR) | ✓ | ✗ |
| [run command](#action-run-command) | Real time response(RTR) | ✓ | ✗ |
| [run admin command](#action-run-admin-command) | Real time response(admin) | ✗ | ✓ |
| [get command details](#action-get-command-details) | Real time response(RTR) | ✗ | ✓ |
| [list session files](#action-list-session-files) | Real time response(RTR) | ✗ | ✓ |
| [get incident behaviors](#action-get-incident-behaviors) | Incidents | ✓ | ✗ |
| [update incident](#action-update-incident) | Incidents | ✗ | ✓ |
| [list users](#action-list-users) | User Management | ✓ | ✗ |
| [get user roles](#action-get-user-roles) | User Management | ✓ | ✗ |
| [list roles](#action-list-roles) | User Management | ✓ | ✗ |
| [get role](#action-get-role) | User Management | ✓ | ✗ |
| [list crowdscores](#action-list-crowdscores) | Incidents | ✓ | ✗ |
| [get incident details](#action-get-incident-details) | Incidents | ✓ | ✗ |
| [list incident behaviors](#action-list-incident-behaviors) | Incidents | ✓ | ✗ |
| [list incidents](#action-list-incidents) | Incidents | ✓ | ✗ |
| [get session file](#action-get-session-file) | Real time response(RTR) | ✗ | ✓ |
| [set status](#action-set-status) | Detections | ✗ | ✓ |
| [get system info](#action-get-system-info) | Hosts | ✓ | ✗ |
| [get process detail](#action-get-process-detail) | IOCs(Indicators of Compromise) | ✓ | ✗ |
| [hunt file](#action-hunt-file) | IOCs(Indicators of Compromise) | ✓ | ✗ |
| [hunt domain](#action-hunt-domain) | IOCs(Indicators of Compromise) | ✓ | ✗ |
| [hunt ip](#action-hunt-ip) | IOCs(Indicators of Compromise) | ✓ | ✗ |
| [upload put file](#action-upload-put-file) | Real time response | ✗ | ✓ |
| [get indicator](#action-get-indicator) | IOC Management | ✓ | ✗ |
| [list custom indicators](#action-list-custom-indicators) | IOC Management | ✓ | ✗ |
| [list put files](#action-list-put-files) | Real time response(admin) | ✗ | ✓ |
| [on poll](#action-on-poll) | Event Stream | ✓ | ✗ |
| [list processes](#action-list-processes) | IOCs | ✓ | ✗ |
| [upload indicator](#action-upload-indicator) | IOC Management | ✗ | ✓ |
| [delete indicator](#action-delete-indicator) | IOC Management | ✓ | ✓ |
| [update indicator](#action-update-indicator) | IOC Management | ✗ | ✓ |
| [file reputation](#action-file-reputation) | Sandbox(Falcon Intelligence) | ✓ | ✗ |
| [url reputation](#action-url-reputation) | Sandbox(Falcon Intelligence) | ✓ | ✗ |
| [download report](#action-download-report) | Sandbox(Falcon Intelligence) | ✓ | ✗ |
| [detonate file](#action-detonate-file) | Sandbox(Falcon Intelligence) | ✓ | ✗ |
| [detonate url](#action-detonate-url) | Sandbox(Falcon Intelligence) | ✓ | ✗ |
| [check status](#action-check-status) | Sandbox(Falcon Intelligence) | ✓ | ✗ |
| [get device scroll](#action-get-device-scroll) | Hosts | ✓ | ✗ |
| [get zta data](#action-get-zta-data) | Zero Trust Assessment | ✓ | ✗ |

## Preprocess Script

The user can add a script file in the configuration parameter \[ **Script with functions to
preprocess containers and artifacts** \]. The script must contain a function with the name
**preprocess_container** (to pre-process the containers and the artifacts) or else, it will throw an
error.

## App ID

- Optionally, you can specify an **App ID** to be used with the Crowdstrike OAuth API used in the
  on poll action. If one isn't set, it will default to the asset ID.
- It is recommended to have a unique **App ID** for each connection to the Crowdstrike OAuth API.
  That is to say, if you are planning on having multiple assets using the Crowdstrike OAuth API at
  once, you should give them unique App IDs.

## On Poll

- Common points for both manual and scheduled interval polling
  - Default parameters of the On Poll action are ignored in the app. i.e. start_time, end_time,
    container_count, artifact_count
  - The app will fetch all the events based on the value specified in the configuration
    parameters [Maximum events to get while POLL NOW] (default 2000 if not specified) and
    [Maximum events to get while scheduled and interval polling] (default 10,000 if not
    specified). For ingestion, the events are fetched after filtering them based on the event
    types - **DetectionSummaryEvent** and **EppDetectionSummaryEvent**. The app will exit from the polling cycle in the
    below-mentioned 2 cases whichever is earlier.
    - If the total events fetched equals the value provided in the \[Maximum
      events to get while POLL NOW\] (for manual polling) or \[Maximum events to get while
      scheduled and interval polling\] (for scheduled | interval polling) parameters
    - If the total number of continuous blank lines encountered while streaming the data
      equals the value provided in the [Maximum allowed continuous blank lines] (default 50
      if not specified) asset configuration parameter
  - The default behavior of the app is that each event will be placed in its container. By
    checking the configuration parameter [Merge containers for Hostname and Eventname] as well
    as specifying an interval in the configuration parameter \[Merge same containers within
    specified seconds\], all events which are of the same type and on the same host will be put
    into one container, as long as the time between those two events is less than the interval.
  - The [Maximum allowed continuous blank lines] asset configuration parameter will be used to
    indicate the allowed number of continuous blank lines while fetching events. For example, if some events exist after 100 continuous blank lines and you've
    set the [Maximum allowed continues blank lines] parameter value to 500, it will keep on
    ingesting all events until the code gets 500 continuous blank lines
    and hence, it will be able to cover the events successfully even after the
    100 blank lines. If you set it to 50, it will break after the 50th blank line is
    encountered. Hence, it won't be able to ingest the events which exist after the 100
    continuous blank lines because the code considers that after the configured value in the
    [Maximum allowed continuous blank lines] configuration parameter (here 50), there is no
    data available.
- Manual Polling
  - During manual poll now, the app starts from the first event that it can query up to the
    value configured in the configuration parameter [Maximum events to get while POLL NOW] and
    creates artifacts for all the fetched DetectionSummaryEvents. The last queried event's
    offset ID will not be remembered in Manual POLL NOW and it fetches everything every time
    from the beginning.
- Scheduled | Interval Polling
  - During scheduled | interval polling, the app starts from the first event that it can query
    up to the value configured in the configuration parameter \[Maximum events to get while
    scheduled and interval polling\] and creates artifacts for all the fetched
    DetectionSummaryEvents. Then, it remembers the last event's offset ID and stores it in the
    state file against the key [last_offset_id]. In the next scheduled poll run, it will start
    from the stored offset ID in the state file and will fetch the maximum events as configured
    in the [Maximum events to get while scheduled and interval polling] parameter.

The **DetectionSummaryEvent** is parsed to extract the following values into an Artifact.

| **Artifact Field** | **Event Field** |
|--------------------|-----------------|
| cef.sourceUserName | UserName |
| cef.fileName | FileName |
| cef.filePath | FilePath |
| cef.sourceHostName | ComputerName |
| cef.sourceNtDomain | MachineDomain |
| cef.hash | MD5String |
| cef.hash | SHA1String |
| cef.hash | SHA256STring |
| cef.cs1 | cmdLine |

The **EppDetectionSummaryEvent** is parsed to extract the following values into an Artifact.

| **Artifact Field** | **Event Field** |
|--------------------|------------------|
| cef.sourceUserName | UserName |
| cef.fileName | FileName |
| cef.filePath | FilePath |
| cef.sourceHostName | Hostname |
| cef.sourceNtDomain | LogonDomain |
| cef.hash | MD5String |
| cef.hash | SHA1String |
| cef.hash | SHA256String |
| cef.cs1 | cmdLine |

The app also parses the following **sub-events** into their own artifacts.

- Documents Accessed
- Executables Written
- Network Access
- Scan Result
- Quarantine Files
- DNS Requests

Each of the sub-events has a CEF key called **parentSdi** which stands for Parent Source Data
Identifier. This is the value of the SDI of the main event that the sub-events were generated from.

## Falcon X Sandbox Actions

**This is different from Falcon Sandbox.**

- **Action -** File Reputation, Url reputation

<!-- -->

- Report of the resource will be fetched if it has been detonated previously on the CrowdStrike
  Server otherwise no data found message will be displayed to the user.

<!-- -->

- **Action -** Download Report

<!-- -->

- This action will download the resource report based on the provided artifact ID. Currently, we
  support the following Strict IOC CSV, Strict IOC JSON, Strict IOC STIX2.1, Strict IOC MAEC5.0,
  Broad IOC CSV, Broad IOC JSON, Broad IOC STIX2.1, Broad IOC MAEC5.0, Memory Strings, Icon,
  Screenshot artifact IDs.

<!-- -->

- **Action -** Detonate File

<!-- -->

- This action will upload the given file to the CrowdStrike sandbox and will submit it for
  analysis with the entered environment details. If the report of the given file is already
  present with the same environment, it will fetch the result and the file won't be submitted
  again.
- If the analysis is in progress and reaches the time entered in the detonate_timeout parameter,
  then this action will return the resource_id of the submitted file using which the submission
  status can be checked.
- If the submitted file will be analyzed within the entered time in the detonate_timeout
  parameter, its report will be fetched. Currently, these file types are supported .exe, .scr,
  .pif, .dll, .com, .cpl, etc., .doc, .docx, .ppt, .pps, .pptx, .ppsx, .xls, .xlsx, .rtf, .pub,
  .pdf, Executable JAR, .sct, .lnk, .chm, .hta, .wsf, .js, .vbs, .vbe, .swf, pl, .ps1, .psd1,
  .psm1, .svg, .py, Linux ELF executables, .eml, .msg.

<!-- -->

- **Action -** Detonate Url

<!-- -->

- This action will submit the given URL for analysis with the entered environment details. If the
  report of the given URL is already present with the same environment, it will fetch the result
  and the url won't be submitted again.
- If the analysis is in progress and it reaches the time entered in the detonate_timeout
  parameter, then this action will return the resource_id of the submitted URL using which the
  status of the submission can be checked. If the analysis status is running then do not re-run
  the detonate URL action, otherwise, the URL will be again submitted for the analysis.
- If the submitted URL will be analyzed within the entered time in the detonate_timeout parameter,
  its report will be fetched. Currently, 3 domains of URL are supported http, https, and ftp.

<!-- -->

- **Action -** Check Status

<!-- -->

- This action will return the status of the given resource_id in case of timeout in detonate file
  and detonate URL actions.

## Notes

- **Action -** List Alerts

<!-- -->

- The filter parameter values follow the [FQL
  Syntax](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-fql-reference)
  .

- The sort parameter value has to be provided in the format property_name.asc for ascending and
  property_name.desc for descending order.

- The `include_hidden` parameter has been added to the action as it's behavior in the API has changed. In the
  prior API version, the default behavior of the `include_hidden` parameter was either not supported or defaulted
  to `false`. The latest version of the API now defaults `include_hidden` to `true` if it is not included in
  the API call. Therefore, we have included this parameter in the action configuration and set it to `false` by
  default in order to keep the action behavior consistent with the previous app version. Hidden alerts can be
  identified by the `show_in_ui` field of an alert object.

  If you experience any `list alerts` action failures in an existing playbook that passed in the previous version
  of the app, you may need to edit the action in the playbook and then save. This will then add the `include_hidden`
  field to the playbook action.

- **Action -** List Groups

<!-- -->

- The filter parameter values follow the [FQL
  Syntax](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-fql-reference)
  .

- The sort parameter value has to be provided in the format property_name.asc for ascending and
  property_name.desc for descending order.

- **Action -** Query Device

<!-- -->

- Both the filter and sort parameters follow the same concepts as mentioned above for the list
  groups action.

- **Action -** Assign Hosts, Remove Hosts, Quarantine Device, and Unquarantine Device

<!-- -->

- The devices will be fetched based on the values provided in both the device_id and hostname
  parameters.
- If an incorrect value is provided in both the device_id and hostname parameters each, then, the
  action will fail with an appropriate error message.

<!-- -->

- **Action -** List Session Files, Get Session File

<!-- -->

- To add [session id] to the action parameters of these actions, a session with the Create
  Session action needs to be created. Also, the user can delete the session using the Delete
  Session action.

- **Action -** Run Command

<!-- -->

- This action can run the below-mentioned RTR commands on the host:
  - cat
  - cd
  - env
  - eventlog
  - filehash
  - getsid
  - ipconfig
  - ls
  - mount
  - netstat
  - ps
  - reg query
- To add [session id] to the action parameters of these actions, a session with the Create
  Session action needs to be created. Also, the user can delete the session using the Delete
  Session action.
- Example action run: If "cd C:\\some_directory" command needs to be run using this action, valid
  [device_id] and [session_id] parameters should be provided by the user. The user should
  select "cd" from the [command] dropdown parameter and provide "C:\\some_directory" input in
  the [data] parameter.

<!-- -->

- **Action -** Run Admin Command

<!-- -->

- This action can run the below-mentioned RTR administrator commands on the host:
  - cat
  - cd
  - cp
  - encrypt
  - env
  - eventlog
  - filehash
  - get
  - getsid
  - ipconfig
  - kill
  - ls
  - map
  - memdump
  - mkdir
  - mount
  - mv
  - netstat
  - ps
  - put
  - reg query
  - reg set
  - reg delete
  - reg load
  - reg unload
  - restart
  - rm
  - run
  - runscript
  - shutdown
  - unmap
  - xmemdump
  - zip
- To add [session id] to the action parameters of these actions, a session with the Create
  Session action needs to be created. Also, the user can delete the session using the Delete
  Session action.
- Example action run: If "cd C:\\some_directory" command needs to be run using this action, valid
  [device_id] and [session_id] parameters should be provided by the user. The user should
  select "cd" from the [command] dropdown parameter and provide "C:\\some_directory" input in
  the [data] parameter.

## Port Information

The app uses HTTP/HTTPS protocol for communicating with the Crowdstrike Server. Below are the
default ports used by Splunk SOAR.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http | tcp | 80 |
| https | tcp | 443 |

## Playbook Backward Compatibility

- The output data-paths have been updated in the below-existing action. Hence, it is requested to
  update existing playbooks created in the earlier versions of the app by re-inserting |
  modifying | deleting the corresponding action blocks.

  - list users - Below output data-paths have been updated.

    - Updated name from 'customer' to 'cid'
    - Updated name from 'firstName' to 'first_name'
    - Updated name from 'lastName' to 'last_name'

### Configuration variables

This table lists the configuration variables required to operate CrowdStrike OAuth API. These variables are specified when configuring a CrowdStrike asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** | required | string | Base URL |
**client_id** | required | password | Client ID |
**client_secret** | required | password | Client Secret |
**app_id** | optional | string | App ID |
**max_events** | optional | numeric | Maximum events to get for scheduled and interval polling |
**max_events_poll_now** | optional | numeric | Maximum events to get while POLL NOW |
**max_incidents** | optional | numeric | Maximum incidents to get for scheduled and interval polling |
**max_incidents_poll_now** | optional | numeric | Maximum incidents to get while POLL NOW |
**ingest_incidents** | optional | boolean | Should ingest incidents during polling |
**collate** | optional | boolean | Merge containers for hostname and eventname |
**merge_time_interval** | optional | numeric | Merge same containers within specified seconds |
**max_crlf** | optional | numeric | Maximum allowed continuous blank lines |
**preprocess_script** | optional | file | Script with functions to preprocess containers and artifacts |
**detonate_timeout** | optional | numeric | Timeout for detonation result in minutes (Default: 15 minutes) |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity. This action logs into the site to check the connection and credentials \
[run query](#action-run-query) - Run a query against CrowdStrike API \
[query device](#action-query-device) - Fetch the device details based on the provided query \
[list groups](#action-list-groups) - Fetch the details of the host groups \
[quarantine device](#action-quarantine-device) - Block the device \
[unquarantine device](#action-unquarantine-device) - Unblock the device \
[assign hosts](#action-assign-hosts) - Assign one or more hosts to the static host group \
[remove hosts](#action-remove-hosts) - Remove one or more hosts from the static host group \
[create session](#action-create-session) - Initialize a new session with the Real Time Response cloud \
[delete session](#action-delete-session) - Deletes a Real Time Response session \
[list detections](#action-list-detections) - Get a list of detections \*The action uses legacy Detects API being deprecated. Please use the 'list epp alerts' action instead\* \
[list epp alerts](#action-list-epp-alerts) - Get a list of epp alerts, replaces legacy Detects API \
[get detections details](#action-get-detections-details) - Get a list of detections details by providing detection IDs \*The action uses legacy Detects API being deprecated. Please use the 'get epp details' action instead\* \
[get epp details](#action-get-epp-details) - Get list of alert details for EPP alerts by providing composite IDs, replaces legacy Detects API \
[update detections](#action-update-detections) - Update detections in crowdstrike host \*The action uses legacy Detects API being deprecated. Please use the 'update epp alerts' action instead\* \
[update epp alerts](#action-update-epp-alerts) - Update EPP alerts in CrowdStrike, replaces legacy Detects API \
[list alerts](#action-list-alerts) - Get a list of alerts \
[list sessions](#action-list-sessions) - Lists Real Time Response sessions \
[run command](#action-run-command) - Execute an active responder command on a single host \
[run admin command](#action-run-admin-command) - Execute an RTR Admin command on a single host \
[get command details](#action-get-command-details) - Retrieve results of an active responder command executed on a single host \
[list session files](#action-list-session-files) - Get a list of files for the specified RTR session \
[get incident behaviors](#action-get-incident-behaviors) - Get details on behaviors by providing behavior IDs \
[update incident](#action-update-incident) - Perform a set of actions on one or more incidents, such as adding tags or comments or updating the incident name or description \
[list users](#action-list-users) - Get information about all users in your Customer ID \
[get user roles](#action-get-user-roles) - Gets the roles that are assigned to the user \
[list roles](#action-list-roles) - Get information about all user roles from your Customer ID \
[get role](#action-get-role) - Get information about all user roles from your Customer ID \
[list crowdscores](#action-list-crowdscores) - Query environment wide CrowdScore and return the entity data \
[get incident details](#action-get-incident-details) - Get details on incidents by providing incident IDs \
[list incident behaviors](#action-list-incident-behaviors) - Search for behaviors by providing an FQL filter, sorting, and paging details \
[list incidents](#action-list-incidents) - Search for incidents by providing an FQL filter, sorting, and paging details \
[get session file](#action-get-session-file) - Get RTR extracted file contents for the specified session and sha256 and add it to the vault \
[set status](#action-set-status) - Set the state of a detection in Crowdstrike Host \*The action uses legacy Detects API being deprecated. Please use the 'resolve epp alerts' action instead\* \
[resolve epp alerts](#action-resolve-epp-alerts) - Update the status of an EPP alert in CrowdStrike, replaces legacy Detects API \
[get system info](#action-get-system-info) - Get details of a device, given the device ID \
[get process detail](#action-get-process-detail) - Retrieve the details of a process that is running or that previously ran, given a process ID \
[hunt file](#action-hunt-file) - Hunt for a file on the network by querying for the hash \
[hunt domain](#action-hunt-domain) - Get a list of device IDs on which the domain was matched \
[hunt ip](#action-hunt-ip) - Get a list of device IDs on which the ip was matched \
[upload put file](#action-upload-put-file) - Upload a new put-file to use for the RTR `put` command \
[get indicator](#action-get-indicator) - Get the full definition of one or more indicators that are being watched \
[list custom indicators](#action-list-custom-indicators) - Queries for custom indicators in your customer account \
[list put files](#action-list-put-files) - Queries for files uploaded to Crowdstrike for use with the RTR `put` command \
[on poll](#action-on-poll) - Callback action for the on_poll ingest functionality \
[list processes](#action-list-processes) - List processes that have recently used the IOC on a particular device \
[upload indicator](#action-upload-indicator) - Upload indicator that you want CrowdStrike to watch \
[delete indicator](#action-delete-indicator) - Delete an indicator that is being watched \
[update indicator](#action-update-indicator) - Update an indicator that has been uploaded \
[file reputation](#action-file-reputation) - Queries CrowdStrike for the file info given a vault ID or a SHA256 hash, vault ID has higher priority than SHA256 hash if both are provided \
[url reputation](#action-url-reputation) - Queries CrowdStrike for the url info \
[download report](#action-download-report) - To download the report of the provided artifact id \
[detonate file](#action-detonate-file) - Upload a file to CrowdStrike and retrieve the analysis results \
[detonate url](#action-detonate-url) - Upload an url to CrowdStrike and retrieve the analysis results \
[check status](#action-check-status) - To check detonation status of the provided resource id \
[get device scroll](#action-get-device-scroll) - Search for hosts in your environment by platform, hostname, IP, and other criteria with continuous pagination capability (based on offset pointer which expires after 2 minutes with no maximum limit) \
[get zta data](#action-get-zta-data) - Get Zero Trust Assessment data for one or more hosts by providing agent IDs (AID) \
[create ioa rule group](#action-create-ioa-rule-group) - Create an empty IOA Rule Group \
[update ioa rule group](#action-update-ioa-rule-group) - Modify an existing IOA Rule Group \
[delete ioa rule group](#action-delete-ioa-rule-group) - Delete an existing IOA Rule Group \
[list ioa platforms](#action-list-ioa-platforms) - List valid platforms for IOA Rule Groups \
[list ioa rule groups](#action-list-ioa-rule-groups) - List IOA Rule Groups \
[list ioa severities](#action-list-ioa-severities) - List valid severity values for IOA rules \
[list ioa types](#action-list-ioa-types) - List valid types of IOA rules \
[create ioa rule](#action-create-ioa-rule) - Create a new IOA Rule \
[update ioa rule](#action-update-ioa-rule) - Update an existing IOA Rule \
[delete ioa rule](#action-delete-ioa-rule) - Delete an existing IOA Rule

## action: 'test connectivity'

Validate the asset configuration for connectivity. This action logs into the site to check the connection and credentials

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'run query'

Run a query against CrowdStrike API

Type: **investigate** \
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
action_result.status | string | | |
action_result.parameter.endpoint | string | | |
action_result.parameter.limit | numeric | | |
action_result.parameter.filter | string | | |
action_result.parameter.sort | string | | |
action_result.parameter.offset | numeric | | |
action_result.data.\*.resource_id | string | | |
action_result.summary.total_objects | numeric | | |
action_result.summary.total_count | numeric | | |
action_result.summary.offset | numeric | | |
action_result.summary.limit | numeric | | |
action_result.summary.query_time | numeric | | |
action_result.summary.powered_by | string | | |
action_result.summary.trace_id | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.message | string | | |

## action: 'query device'

Fetch the device details based on the provided query

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** | optional | Maximum devices to be fetched | numeric | |
**offset** | optional | Starting index of overall result set from which to return ids. (Defaults to 0) | numeric | |
**filter** | optional | Filter expression used to limit the fetched devices (FQL Syntax) | string | |
**sort** | optional | Property to sort by | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.filter | string | | hostname: 'E\*' platform_name:'Windows' |
action_result.parameter.limit | numeric | | 120 |
action_result.parameter.offset | numeric | | 10 |
action_result.parameter.sort | string | | hostname.desc |
action_result.data.\*.agent_load_flags | string | | 1 |
action_result.data.\*.agent_local_time | string | | 2019-06-13T10:46:11.024Z |
action_result.data.\*.agent_version | string | | 5.10.9106.0 |
action_result.data.\*.bios_manufacturer | string | | XYZ Technologies LTD |
action_result.data.\*.bios_version | string | | 6.00 |
action_result.data.\*.build_number | string | | 17134 |
action_result.data.\*.cid | string | `md5` | 3061c7ff3b634e22b38274d4b586558e |
action_result.data.\*.config_id_base | string | | 65994753 |
action_result.data.\*.config_id_build | string | | 9106 |
action_result.data.\*.config_id_platform | string | | 3 |
action_result.data.\*.connection_ip | string | `ip` | 10.1.18.205 |
action_result.data.\*.connection_mac_address | string | | 00-50-56-12-34-56 |
action_result.data.\*.cpu_signature | string | | 329300 |
action_result.data.\*.default_gateway_ip | string | `ip` | 10.1.16.1 |
action_result.data.\*.device_id | string | `crowdstrike device id` | 07c312fabcb8473454d0a16f118928ab |
action_result.data.\*.device_policies.device_control.applied | boolean | | True False |
action_result.data.\*.device_policies.device_control.applied_date | string | | 2019-04-18T13:16:17.246147089Z |
action_result.data.\*.device_policies.device_control.assigned_date | string | | 2019-04-18T13:09:53.221767635Z |
action_result.data.\*.device_policies.device_control.policy_id | string | `md5` | cb4babb273274f79a91e8a0e84164916 |
action_result.data.\*.device_policies.device_control.policy_type | string | | device-control |
action_result.data.\*.device_policies.firewall.applied | boolean | | True False |
action_result.data.\*.device_policies.firewall.applied_date | string | | 2020-07-08T03:12:30.212194872Z |
action_result.data.\*.device_policies.firewall.assigned_date | string | | 2020-07-08T03:07:38.48127371Z |
action_result.data.\*.device_policies.firewall.policy_id | string | | 2018f9894359493cb756bfa7dd3357a6 |
action_result.data.\*.device_policies.firewall.policy_type | string | | firewall |
action_result.data.\*.device_policies.firewall.rule_set_id | string | | 2018f9894359493cb756bfa7dd3357a6 |
action_result.data.\*.device_policies.global_config.applied | boolean | | True False |
action_result.data.\*.device_policies.global_config.applied_date | string | | 2019-06-03T23:31:25.402021685Z |
action_result.data.\*.device_policies.global_config.assigned_date | string | | 2019-06-03T23:27:22.325516295Z |
action_result.data.\*.device_policies.global_config.policy_id | string | `md5` | 49ee9efc99164562ad89640955f372ce |
action_result.data.\*.device_policies.global_config.policy_type | string | | globalconfig |
action_result.data.\*.device_policies.global_config.settings_hash | string | | a75911b0 |
action_result.data.\*.device_policies.jumpcloud.applied | numeric | | True |
action_result.data.\*.device_policies.jumpcloud.applied_date | string | | 2022-07-13T17:41:16.271074445Z |
action_result.data.\*.device_policies.jumpcloud.assigned_date | string | | 2022-07-13T17:40:53.552991354Z |
action_result.data.\*.device_policies.jumpcloud.policy_id | string | `md5` | 234766dcce654217babcbaa247ca31f0 |
action_result.data.\*.device_policies.jumpcloud.policy_type | string | | jumpcloud |
action_result.data.\*.device_policies.jumpcloud.settings_hash | string | `sha256` | 0aec295a677907c6e4de672edf1f172d2cefcc5ca96ed2b5e56f4d6745289694 |
action_result.data.\*.device_policies.prevention.applied | boolean | | True False |
action_result.data.\*.device_policies.prevention.applied_date | string | | 2019-04-03T23:57:05.493184498Z |
action_result.data.\*.device_policies.prevention.assigned_date | string | | 2019-04-03T23:53:41.614339193Z |
action_result.data.\*.device_policies.prevention.policy_id | string | `md5` | ad0dad6639454b4d8bbfc963bf9510c9 |
action_result.data.\*.device_policies.prevention.policy_type | string | | prevention |
action_result.data.\*.device_policies.prevention.settings_hash | string | | 4aa96e52 |
action_result.data.\*.device_policies.remote_response.applied | boolean | | True False |
action_result.data.\*.device_policies.remote_response.applied_date | string | | 2019-02-08T02:39:21.726331953Z |
action_result.data.\*.device_policies.remote_response.assigned_date | string | | 2019-02-08T02:36:05.073298048Z |
action_result.data.\*.device_policies.remote_response.policy_id | string | `md5` | 6c74313d6c864180bd759c3235dbd550 |
action_result.data.\*.device_policies.remote_response.policy_type | string | | remote-response |
action_result.data.\*.device_policies.remote_response.settings_hash | string | | f472bd8e |
action_result.data.\*.device_policies.sensor_update.applied | boolean | | True False |
action_result.data.\*.device_policies.sensor_update.applied_date | string | | 2019-05-30T23:21:58.956282211Z |
action_result.data.\*.device_policies.sensor_update.assigned_date | string | | 2019-05-30T23:02:19.540591355Z |
action_result.data.\*.device_policies.sensor_update.policy_id | string | `md5` | 226d7067a47b4ea7a3369f7e9114b180 |
action_result.data.\*.device_policies.sensor_update.policy_type | string | | sensor-update |
action_result.data.\*.device_policies.sensor_update.settings_hash | string | | 65994753|3|2|automatic;101 |
action_result.data.\*.device_policies.sensor_update.uninstall_protection | string | | ENABLED |
action_result.data.\*.external_ip | string | `ip` | 204.107.141.240 |
action_result.data.\*.first_seen | string | | 2018-04-19T19:10:14Z |
action_result.data.\*.group_hash | string | `sha256` | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
action_result.data.\*.groups | string | `md5` | 4493ec18e3c942078b7c0bd4248d3f5e |
action_result.data.\*.hostname | string | `host name` | CB-TEST-01 |
action_result.data.\*.instance_id | string | | i-058fca45cda978e00 |
action_result.data.\*.kernel_version | string | | 10.0.19044.1766 |
action_result.data.\*.last_seen | string | | 2019-06-20T14:01:26Z |
action_result.data.\*.local_ip | string | `ip` | 10.1.18.49 |
action_result.data.\*.mac_address | string | | 00-0c-29-a0-10-27 |
action_result.data.\*.machine_domain | string | `domain` | corp.xyz.com |
action_result.data.\*.major_version | string | | 10 |
action_result.data.\*.meta.version | string | | 59509 |
action_result.data.\*.minor_version | string | | 0 |
action_result.data.\*.modified_timestamp | string | | 2019-06-20T14:04:12Z |
action_result.data.\*.os_build | string | | 19044 |
action_result.data.\*.os_version | string | | Windows 10 |
action_result.data.\*.ou | string | | Domain Controllers |
action_result.data.\*.platform_id | string | | 0 |
action_result.data.\*.platform_name | string | | Windows |
action_result.data.\*.pointer_size | string | | 8 |
action_result.data.\*.policies.\*.applied | boolean | | True False |
action_result.data.\*.policies.\*.applied_date | string | | 2019-04-03T23:57:05.493184498Z |
action_result.data.\*.policies.\*.assigned_date | string | | 2019-04-03T23:53:41.614339193Z |
action_result.data.\*.policies.\*.policy_id | string | `md5` | ad0dad6639454b4d8bbfc963bf9510c9 |
action_result.data.\*.policies.\*.policy_type | string | | prevention |
action_result.data.\*.policies.\*.settings_hash | string | | 4aa96e52 |
action_result.data.\*.product_type | string | | 1 |
action_result.data.\*.product_type_desc | string | | Server |
action_result.data.\*.provision_status | string | | Provisioned |
action_result.data.\*.reduced_functionality_mode | string | | no |
action_result.data.\*.serial_number | string | | VMware-56 4d c8 00 40 ed 10 1a-e5 4d 5b d5 e1 a0 10 27 |
action_result.data.\*.service_pack_major | string | | 0 |
action_result.data.\*.service_pack_minor | string | | 0 |
action_result.data.\*.service_provider | string | | test |
action_result.data.\*.service_provider_account_id | string | | 427749959855 |
action_result.data.\*.site_name | string | | Default-First-Site-Name |
action_result.data.\*.slow_changing_modified_timestamp | string | | 2019-06-17T16:08:07Z |
action_result.data.\*.status | string | | contained |
action_result.data.\*.system_manufacturer | string | | XYZ, Inc. |
action_result.data.\*.system_product_name | string | | VM Platform |
action_result.data.\*.zone_group | string | | us-east-1a |
action_result.summary.total_devices | numeric | | 2 |
action_result.message | string | | Total devices: 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list groups'

Fetch the details of the host groups

Type: **investigate** \
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
action_result.status | string | | success failed |
action_result.parameter.filter | string | | modified_timestamp:\<='2019-06-14T10:22:02.02236652Z' |
action_result.parameter.limit | numeric | | 120 |
action_result.parameter.sort | string | | created_timestamp.asc |
action_result.data.\*.assignment_rule | string | | device_id:[''],hostname:['','EC2AMAZ-K5LEL73'] |
action_result.data.\*.created_by | string | `email` | first.last@xyz.com |
action_result.data.\*.created_timestamp | string | | 2019-05-28T22:51:01.124782712Z |
action_result.data.\*.description | string | | This is a sample test group |
action_result.data.\*.group_type | string | | static |
action_result.data.\*.id | string | `crowdstrike host group id` | b5098f79716c4beb8f9c2aebff609075 |
action_result.data.\*.modified_by | string | `email` | test.user@example.us |
action_result.data.\*.modified_timestamp | string | | 2019-05-28T22:51:01.124782712Z |
action_result.data.\*.name | string | | super secure group |
action_result.summary.total_host_group | numeric | | 529 |
action_result.summary.total_host_groups | numeric | | 1 |
action_result.message | string | | Total host groups: 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'quarantine device'

Block the device

Type: **contain** \
Read only: **False**

This action contains the host, which stops any network communications to locations other than the CrowdStrike cloud and IPs specified in the user's containment policy.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | optional | Comma-separated list of device IDs | string | `crowdstrike device id` |
**hostname** | optional | Comma-separated list of hostnames | string | `host name` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.device_id | string | `crowdstrike device id` | c70bbe8334aa47bd61046603eb27b15a |
action_result.parameter.hostname | string | `host name` | CB-TEST-01 |
action_result.data.\*.id | string | `crowdstrike device id` | c70bbe8334aa47bd61046603eb27b15a |
action_result.data.\*.path | string | | /devices/entities/devices/v1 |
action_result.summary.total_quarantined_device | numeric | | 1 |
action_result.message | string | | Device quarantined successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'unquarantine device'

Unblock the device

Type: **correct** \
Read only: **False**

This action lifts containment on the host, which returns its network communications to normal.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | optional | Comma-separated list of device IDs | string | `crowdstrike device id` |
**hostname** | optional | Comma-separated list of hostnames | string | `host name` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.device_id | string | `crowdstrike device id` | c70bbe8334aa47bd61046603eb27b15a |
action_result.parameter.hostname | string | `host name` | CB-TEST-01 |
action_result.data.\*.id | string | `crowdstrike device id` | c70bbe8334aa47bd61046603eb27b15a |
action_result.data.\*.path | string | | /devices/entities/devices/v1 |
action_result.summary.total_unquarantined_device | numeric | | 1 |
action_result.message | string | | Device unquarantined successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'assign hosts'

Assign one or more hosts to the static host group

Type: **correct** \
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
action_result.status | string | | success failed |
action_result.parameter.device_id | string | `crowdstrike device id` | 07c312fabcb8473454d0a16f118928ab |
action_result.parameter.host_group_id | string | `crowdstrike host group id` | 5c3203cee6934edd894c0c02d5a7d2ad |
action_result.parameter.hostname | string | `host name` | CB-TEST-01 |
action_result.data.\*.assignment_rule | string | | device_id:[''],hostname:['CB-TEST-01'] |
action_result.data.\*.created_by | string | | api-client-id:ae1690074e144336ae1de4de9dc1bd93 |
action_result.data.\*.created_timestamp | string | | 2019-06-18T06:43:48.348572725Z |
action_result.data.\*.description | string | | test 6 |
action_result.data.\*.group_type | string | | static |
action_result.data.\*.id | string | `crowdstrike host group id` | 5c3203cee6934edd894c0c02d5a7d2ad |
action_result.data.\*.modified_by | string | | api-client-id:ae1690074e144336ae1de4de9dc1bd93 |
action_result.data.\*.modified_timestamp | string | | 2019-06-18T06:43:48.348572725Z |
action_result.data.\*.name | string | | test 7 |
action_result.summary.total_assigned_device | numeric | | 1 |
action_result.message | string | | Host added successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'remove hosts'

Remove one or more hosts from the static host group

Type: **contain** \
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
action_result.status | string | | success failed |
action_result.parameter.device_id | string | `crowdstrike device id` | 07c312fabcb8473454d0a16f118928ab |
action_result.parameter.host_group_id | string | `crowdstrike host group id` | 5c3203cee6934edd894c0c02d5a7d2ad |
action_result.parameter.hostname | string | `host name` | CB-TEST-01 |
action_result.data.\*.assignment_rule | string | | device_id:[''],hostname:[''] |
action_result.data.\*.created_by | string | | api-client-id:ae1690074e144336ae1de4de9dc1bd93 |
action_result.data.\*.created_timestamp | string | | 2019-06-18T06:43:48.348572725Z |
action_result.data.\*.description | string | | test 6 |
action_result.data.\*.group_type | string | | static |
action_result.data.\*.id | string | `crowdstrike host group id` | 5c3203cee6934edd894c0c02d5a7d2ad |
action_result.data.\*.modified_by | string | | api-client-id:ae1690074e144336ae1de4de9dc1bd93 |
action_result.data.\*.modified_timestamp | string | | 2019-06-18T06:43:48.348572725Z |
action_result.data.\*.name | string | | test 7 |
action_result.summary.total_removed_device | numeric | | 1 |
action_result.message | string | | Host removed successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create session'

Initialize a new session with the Real Time Response cloud

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | Device ID for session to be created | string | `crowdstrike device id` |
**queue_offline** | optional | Queue commands for offline devices, will execute when system comes back online | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.device_id | string | `crowdstrike device id` | 07c312fabcb8473454d0a16f118928ab |
action_result.parameter.queue_offline | boolean | | |
action_result.data.\*.errors | string | | |
action_result.data.\*.meta.powered_by | string | | empower-api |
action_result.data.\*.meta.query_time | numeric | | 5.917429897 |
action_result.data.\*.meta.trace_id | string | | 6b7c63e1-0ebd-4121-90f3-cd53451be245 |
action_result.data.\*.resources.\*.created_at | string | | 2019-09-24T20:52:08.595772499Z |
action_result.data.\*.resources.\*.existing_aid_sessions | numeric | | 1 |
action_result.data.\*.resources.\*.offline_queued | boolean | | True False |
action_result.data.\*.resources.\*.pwd | string | `file path` | C:\\ |
action_result.data.\*.resources.\*.scripts.\*.args.\*.arg_name | string | | Path |
action_result.data.\*.resources.\*.scripts.\*.args.\*.arg_type | string | | arg |
action_result.data.\*.resources.\*.scripts.\*.args.\*.command_level | string | | non-destructive |
action_result.data.\*.resources.\*.scripts.\*.args.\*.created_at | string | | 2019-06-25T23:48:59Z |
action_result.data.\*.resources.\*.scripts.\*.args.\*.data_type | string | | string |
action_result.data.\*.resources.\*.scripts.\*.args.\*.default_value | string | | |
action_result.data.\*.resources.\*.scripts.\*.args.\*.description | string | | File to concatenate |
action_result.data.\*.resources.\*.scripts.\*.args.\*.encoding | string | | |
action_result.data.\*.resources.\*.scripts.\*.args.\*.id | numeric | | 7 |
action_result.data.\*.resources.\*.scripts.\*.args.\*.options | string | | |
action_result.data.\*.resources.\*.scripts.\*.args.\*.required | boolean | | True False |
action_result.data.\*.resources.\*.scripts.\*.args.\*.requires_value | boolean | | True False |
action_result.data.\*.resources.\*.scripts.\*.args.\*.script_id | numeric | | 6 |
action_result.data.\*.resources.\*.scripts.\*.args.\*.sequence | numeric | | 1 |
action_result.data.\*.resources.\*.scripts.\*.args.\*.updated_at | string | | 2019-06-25T23:48:59Z |
action_result.data.\*.resources.\*.scripts.\*.command | string | | cat |
action_result.data.\*.resources.\*.scripts.\*.description | string | | Read a file from disk and display as ASCII or hex |
action_result.data.\*.resources.\*.scripts.\*.examples | string | `file path` | C:\\> cat c:\\mytextfile.txt<br> Display the contents of the text file (ASCII encoding)<br> C:\\> cat c:\\windows\\system32\\cmd.exe 100 -ShowHex<br> Display the first 100 hexadecimal characters for cmd.exe |
action_result.data.\*.resources.\*.scripts.\*.internal_only | boolean | | True False |
action_result.data.\*.resources.\*.scripts.\*.runnable | boolean | | True False |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.args.\*.arg_name | string | | Name |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.args.\*.arg_type | string | | arg |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.args.\*.command_level | string | | non-destructive |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.args.\*.created_at | string | | 2018-05-01T19:38:30Z |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.args.\*.data_type | string | | string |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.args.\*.default_value | string | | |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.args.\*.description | string | | Name of the event log, for example "Application", "System" |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.args.\*.encoding | string | | |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.args.\*.id | numeric | | 35 |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.args.\*.options | string | | |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.args.\*.required | boolean | | True False |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.args.\*.requires_value | boolean | | True False |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.args.\*.script_id | numeric | | 25 |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.args.\*.sequence | numeric | | 1 |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.args.\*.updated_at | string | | 2018-05-01T19:38:30Z |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.command | string | | view |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.description | string | | View most recent N events in a given event log |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.examples | string | | C:\\> eventlog view Application 5<br> Displays the 5 most recent event log entries in the "Application" event source log |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.internal_only | boolean | | True False |
action_result.data.\*.resources.\*.scripts.\*.sub_commands.\*.runnable | boolean | | True False |
action_result.data.\*.resources.\*.session_id | string | `crowdstrike rtr session id` | c0ab8e89-edb0-485f-a8ee-b52d73453a4b |
action_result.summary.session_id | string | `crowdstrike rtr session id` | b2403653-1294-488e-be81-7aadb69b52f1 |
action_result.message | string | | Session created successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'delete session'

Deletes a Real Time Response session

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**session_id** | required | RTR Session ID | string | `crowdstrike rtr session id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.session_id | string | `crowdstrike rtr session id` | cdc3b485-6d71-4417-b091-939336154e83 |
action_result.data | string | | |
action_result.summary.results | string | | Successfully removed session: b2403653-1294-488e-be81-7aadb69b52f1 |
action_result.message | string | | Session ended successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list detections'

Get a list of detections \*The action uses legacy Detects API being deprecated. Please use the 'list epp alerts' action instead\*

Type: **investigate** \
Read only: **True**

This action supports filtering in order to retrieve a particular set of detections.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** | optional | Maximum detections to be fetched | numeric | |
**filter** | optional | Filter expression used to limit the fetched detections (FQL Syntax) | string | |
**sort** | optional | Property to sort by | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.filter | string | | modified_timestamp:\<='2019-06-14T10:22:02.02236652Z' |
action_result.parameter.limit | numeric | | 120 |
action_result.parameter.sort | string | | created_timestamp.asc |
action_result.data | string | | |
action_result.data.\*.behaviors.\*.alleged_filetype | string | | exe |
action_result.data.\*.behaviors.\*.behavior_id | string | | 10354 |
action_result.data.\*.behaviors.\*.cmdline | string | | |
action_result.data.\*.behaviors.\*.confidence | numeric | | 80 |
action_result.data.\*.behaviors.\*.control_graph_id | string | | ctg:46592f3d661a469eb2503d72a29afd3a:309255693652 |
action_result.data.\*.behaviors.\*.description | string | | |
action_result.data.\*.behaviors.\*.device_id | string | `md5` `crowdstrike device id` | 46592f3d661a469eb2503d72a29afd3a |
action_result.data.\*.behaviors.\*.display_name | string | | CredentialsInFilesCredentialAccess |
action_result.data.\*.behaviors.\*.filename | string | | powershell.exe |
action_result.data.\*.behaviors.\*.filepath | string | | \\Device\\HarddiskVolume2\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe |
action_result.data.\*.behaviors.\*.ioc_description | string | | \\Device\\HarddiskVolume2\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe |
action_result.data.\*.behaviors.\*.ioc_source | string | | library_load |
action_result.data.\*.behaviors.\*.ioc_type | string | | hash_sha256 |
action_result.data.\*.behaviors.\*.ioc_value | string | | 9f914d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccd9f |
action_result.data.\*.behaviors.\*.md5 | string | | 04029e121a0cfa5991749937dd22a1d9 |
action_result.data.\*.behaviors.\*.objective | string | | Gain Access |
action_result.data.\*.behaviors.\*.parent_details.parent_cmdline | string | | "C:\\WINDOWS\\system32\\cmd.exe" |
action_result.data.\*.behaviors.\*.parent_details.parent_md5 | string | | 8a2122e8162dbef04694b9c3e0b6cdee |
action_result.data.\*.behaviors.\*.parent_details.parent_process_graph_id | string | | pid:46592f3d661a469eb2503d72a29afd3a:740512001748 |
action_result.data.\*.behaviors.\*.parent_details.parent_sha256 | string | | b99d61d874728edc0918ca0eb10eab93d381e7367e377406e65963366c874450 |
action_result.data.\*.behaviors.\*.pattern_disposition | numeric | | 2048 |
action_result.data.\*.behaviors.\*.pattern_disposition_details.blocking_unsupported_or_disabled | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.bootup_safeguard_enabled | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.critical_process_disabled | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.detect | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.fs_operation_blocked | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.handle_operation_downgraded | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.inddet_mask | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.indicator | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.kill_action_failed | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.kill_parent | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.kill_process | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.kill_subprocess | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.operation_blocked | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.policy_disabled | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.process_blocked | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.quarantine_file | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.quarantine_machine | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.registry_operation_blocked | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.rooting | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.sensor_only | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.suspend_parent | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.suspend_process | boolean | | False True |
action_result.data.\*.behaviors.\*.scenario | string | | suspicious_activity |
action_result.data.\*.behaviors.\*.severity | numeric | | 70 |
action_result.data.\*.behaviors.\*.sha256 | string | | 9f914d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccd9f |
action_result.data.\*.behaviors.\*.tactic | string | | Credential Access |
action_result.data.\*.behaviors.\*.tactic_id | string | | TA0006 |
action_result.data.\*.behaviors.\*.technique | string | | Credentials In Files |
action_result.data.\*.behaviors.\*.technique_id | string | | T1552.001 |
action_result.data.\*.behaviors.\*.template_instance_id | string | | 2649 |
action_result.data.\*.behaviors.\*.timestamp | string | | 2022-09-26T11:30:26Z |
action_result.data.\*.behaviors.\*.triggering_process_graph_id | string | | pid:46592f3d661a469eb2503d72a29afd3a:743690872884 |
action_result.data.\*.behaviors.\*.user_id | string | | S-1-5-21-3607613384-2395287924-1763154957-1001 |
action_result.data.\*.behaviors.\*.user_name | string | | testuser |
action_result.data.\*.cid | string | `md5` | 3061c7ff3b634e22b38274d4b586558e |
action_result.data.\*.created_timestamp | string | | 2022-09-26T11:30:42.246972793Z |
action_result.data.\*.date_updated | string | | 2022-09-26T11:45:46Z |
action_result.data.\*.detection_id | string | `crowdstrike detection id` | ldt:46592f3d661a469eb2503d72a29afd3a:309255693652 |
action_result.data.\*.device.agent_load_flags | string | | 0 |
action_result.data.\*.device.agent_local_time | string | | 2022-08-22T15:45:16.195Z |
action_result.data.\*.device.agent_version | string | | 6.44.15806.0 |
action_result.data.\*.device.bios_manufacturer | string | | Phoenix Technologies LTD |
action_result.data.\*.device.bios_version | string | | 6.00 |
action_result.data.\*.device.cid | string | | 3061c7ff3b634e22b38274d4b586558e |
action_result.data.\*.device.config_id_base | string | | 65994753 |
action_result.data.\*.device.config_id_build | string | | 15806 |
action_result.data.\*.device.config_id_platform | string | | 3 |
action_result.data.\*.device.device_id | string | `md5` `crowdstrike device id` | 46592f3d661a469eb2503d72a29afd3a |
action_result.data.\*.device.external_ip | string | | 204.107.141.240 |
action_result.data.\*.device.first_seen | string | | 2020-08-13T23:45:59Z |
action_result.data.\*.device.hostname | string | | CB-TEST-02 |
action_result.data.\*.device.last_seen | string | | 2022-09-26T11:21:40Z |
action_result.data.\*.device.local_ip | string | | 10.1.18.205 |
action_result.data.\*.device.mac_address | string | | 00-50-56-12-34-56 |
action_result.data.\*.device.machine_domain | string | | sql19.local |
action_result.data.\*.device.major_version | string | | 10 |
action_result.data.\*.device.minor_version | string | | 0 |
action_result.data.\*.device.modified_timestamp | string | | 2022-09-26T11:27:43Z |
action_result.data.\*.device.os_version | string | | Windows 10 |
action_result.data.\*.device.platform_id | string | | 0 |
action_result.data.\*.device.platform_name | string | | Windows |
action_result.data.\*.device.product_type | string | | 1 |
action_result.data.\*.device.product_type_desc | string | | Workstation |
action_result.data.\*.device.site_name | string | | Default-First-Site-Name |
action_result.data.\*.device.status | string | | normal |
action_result.data.\*.device.system_manufacturer | string | | VMware, Inc. |
action_result.data.\*.device.system_product_name | string | | VMware Virtual Platform |
action_result.data.\*.email_sent | boolean | | False |
action_result.data.\*.first_behavior | string | | 2022-09-26T11:30:26Z |
action_result.data.\*.hostinfo.domain | string | | |
action_result.data.\*.last_behavior | string | | 2022-09-26T11:30:26Z |
action_result.data.\*.max_confidence | numeric | | 80 |
action_result.data.\*.max_severity | numeric | | 70 |
action_result.data.\*.max_severity_displayname | string | | High |
action_result.data.\*.seconds_to_resolved | numeric | | 0 |
action_result.data.\*.seconds_to_triaged | numeric | | 0 |
action_result.data.\*.show_in_ui | boolean | | True |
action_result.data.\*.status | string | | new |
action_result.summary.total_detections | numeric | | 44 |
action_result.message | string | | Total detections: 44 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list epp alerts'

Get a list of epp alerts, replaces legacy Detects API

Type: **investigate** \
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
action_result.parameter.filter | string | | |
action_result.parameter.sort | string | | |
action_result.data.\*.agent_id | string | | 9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c |
action_result.data.\*.aggregate_id | string | | aggind:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx6384 |
action_result.data.\*.alleged_filetype | string | | exe |
action_result.data.\*.charlotte.can_triage | boolean | | False |
action_result.data.\*.charlotte.triage_status | string | | open |
action_result.data.\*.child_process_ids.\* | string | | pid:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx2640 |
action_result.data.\*.cid | string | | d615xxxxxxxx2158 |
action_result.data.\*.cmdline | string | | cmd /c echo MZ>log1.txt && cmd /c copy /b log1.txt+fabc.scr abc.scr && cmd /c abc.scr && cmd /c del log1.txt && cmd /c del fabc.scr |
action_result.data.\*.composite_id | string | `crowdstrike alert id` | d615xxxxxxxx2158:ind:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx1294-32-7878xxxxxxxxxxx1122 |
action_result.data.\*.confidence | numeric | | 50 |
action_result.data.\*.context_timestamp | string | | 2024-08-22T18:30:03Z |
action_result.data.\*.control_graph_id | string | | ctg:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx6384 |
action_result.data.\*.crawled_timestamp | string | | 2024-08-22T18:35:06.103126166Z |
action_result.data.\*.created_timestamp | string | | 2024-08-22T18:31:04.705194419Z |
action_result.data.\*.data_domains.\* | string | | Endpoint |
action_result.data.\*.description | string | | A productivity app launched a process from an executable stack. |
action_result.data.\*.device.agent_load_flags | string | | 3 |
action_result.data.\*.device.agent_local_time | string | | 2016-04-28T14:33:47.302Z |
action_result.data.\*.device.agent_version | string | | 5.25.10701.0 |
action_result.data.\*.device.bios_manufacturer | string | | Phoenix Technologies LTD |
action_result.data.\*.device.bios_version | string | | 6.00 |
action_result.data.\*.device.cid | string | | d615xxxxxxxx2158 |
action_result.data.\*.device.config_id_base | string | | 65994755 |
action_result.data.\*.device.config_id_build | string | | 10701 |
action_result.data.\*.device.config_id_platform | string | | 3 |
action_result.data.\*.device.device_id | string | `crowdstrike device id` | 9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c |
action_result.data.\*.device.external_ip | string | | 4x.xxx.xxx.xxx |
action_result.data.\*.device.first_seen | string | | 2024-08-22T18:30:04Z |
action_result.data.\*.device.hostname | string | | example-host |
action_result.data.\*.device.last_seen | string | | 2024-08-22T18:30:03Z |
action_result.data.\*.device.major_version | string | | 6 |
action_result.data.\*.device.minor_version | string | | 1 |
action_result.data.\*.device.modified_timestamp | string | | 2024-08-22T18:30:13Z |
action_result.data.\*.device.os_version | string | | Windows 7 |
action_result.data.\*.device.platform_id | string | | 0 |
action_result.data.\*.device.platform_name | string | | Windows |
action_result.data.\*.device.product_type | string | | 1 |
action_result.data.\*.device.product_type_desc | string | | Workstation |
action_result.data.\*.device.status | string | | normal |
action_result.data.\*.device.system_manufacturer | string | | VMware, Inc. |
action_result.data.\*.device.system_product_name | string | | VMware Virtual Platform |
action_result.data.\*.display_name | string | | SpearPhishExecutableStack |
action_result.data.\*.email_sent | boolean | | True |
action_result.data.\*.external | boolean | | False |
action_result.data.\*.falcon_host_link | string | | https://falcon.crowdstrike.com/activity-v2/detections/d615xxxxxxxx2158:ind:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx1294-32-7878xxxxxxxxxxx1122?\_cid=g01000co2vxxxxxxxxxxxxu5f72jzjfu |
action_result.data.\*.filename | string | | cmd.exe |
action_result.data.\*.filepath | string | | \\Device\\HarddiskVolume1\\Windows\\SysWOW64\\cmd.exe |
action_result.data.\*.global_prevalence | string | | common |
action_result.data.\*.grandparent_details.cmdline | string | | C:\\Windows\\Explorer.EXE |
action_result.data.\*.grandparent_details.filename | string | | explorer.exe |
action_result.data.\*.grandparent_details.filepath | string | | \\Device\\HarddiskVolume1\\Windows\\explorer.exe |
action_result.data.\*.grandparent_details.local_process_id | string | | 1260 |
action_result.data.\*.grandparent_details.md5 | string | | ac4c51eb24aaxxxxxxxxxxb159189e24 |
action_result.data.\*.grandparent_details.process_graph_id | string | | pid:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx0581 |
action_result.data.\*.grandparent_details.process_id | string | | 1336xxxxxxxxxx0581 |
action_result.data.\*.grandparent_details.sha256 | string | | 6a67xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx576a |
action_result.data.\*.grandparent_details.timestamp | string | | 2024-08-22T18:30:03.000Z |
action_result.data.\*.grandparent_details.user_graph_id | string | | uid:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:S-1-5-21-246xxxx873-120xxxx372-215xxxx746-1000 |
action_result.data.\*.grandparent_details.user_id | string | | S-1-5-21-246xxxx873-120xxxx372-215xxxx746-1000 |
action_result.data.\*.grandparent_details.user_name | string | | testusername |
action_result.data.\*.id | string | | ind:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx1294-32-7878xxxxxxxxxxx1122 |
action_result.data.\*.incident.created | string | | 2024-08-22T18:30:03Z |
action_result.data.\*.incident.end | string | | 2024-08-22T18:30:03Z |
action_result.data.\*.incident.id | string | | inc:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:7e90xxxxxxxxxxxxxxxxxxxxxxxx399c |
action_result.data.\*.incident.score | string | | 77.2905584547083 |
action_result.data.\*.incident.start | string | | 2024-08-22T18:30:03Z |
action_result.data.\*.indicator_id | string | | ind:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx1294-32-7878xxxxxxxxxxx1122 |
action_result.data.\*.ioc_context.\* | string | | [] |
action_result.data.\*.ioc_values.\* | string | | [] |
action_result.data.\*.local_prevalence | string | | common |
action_result.data.\*.local_process_id | string | | 2956 |
action_result.data.\*.logon_domain | string | | WIN-ABCDEFG |
action_result.data.\*.md5 | string | | ad7b9c14xxxxxxxxxxxxxxxxxxxx2b98 |
action_result.data.\*.name | string | | SpearPhishExecutableStack |
action_result.data.\*.objective | string | | Follow Through |
action_result.data.\*.parent_details.cmdline | string | | "C:\\Program Files (x86)\\Microsoft Office\\OFFICE11\\WINWORD.EXE" /n /dde |
action_result.data.\*.parent_details.filename | string | | WINWORD.EXE |
action_result.data.\*.parent_details.filepath | string | | \\Device\\HarddiskVolume1\\Program Files (x86)\\Microsoft Office\\OFFICE11\\WINWORD.EXE |
action_result.data.\*.parent_details.local_process_id | string | | 2756 |
action_result.data.\*.parent_details.md5 | string | | 10ff86bcxxxxxxxxxxxxxxxxxxxxfd507 |
action_result.data.\*.parent_details.process_graph_id | string | | pid:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx4664 |
action_result.data.\*.parent_details.process_id | string | | 1336xxxxxxxxxx4664 |
action_result.data.\*.parent_details.sha256 | string | | b38bxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx958d |
action_result.data.\*.parent_details.timestamp | string | | 2024-08-22T18:30:03Z |
action_result.data.\*.parent_details.user_graph_id | string | | uid:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:S-1-5-21-246xxxx873-120xxxx372-215xxxx746-1000 |
action_result.data.\*.parent_details.user_id | string | | S-1-5-21-246xxxx873-120xxxx372-215xxxx746-1000 |
action_result.data.\*.parent_details.user_name | string | | testusername |
action_result.data.\*.parent_process_id | string | | 1336xxxxxxxxxx4664 |
action_result.data.\*.pattern_disposition | numeric | | 0 |
action_result.data.\*.pattern_disposition_description | string | | Detection, standard detection. |
action_result.data.\*.pattern_disposition_details.blocking_unsupported_or_disabled | boolean | | False |
action_result.data.\*.pattern_disposition_details.bootup_safeguard_enabled | boolean | | False |
action_result.data.\*.pattern_disposition_details.containment_file_system | boolean | | False |
action_result.data.\*.pattern_disposition_details.critical_process_disabled | boolean | | False |
action_result.data.\*.pattern_disposition_details.detect | boolean | | False |
action_result.data.\*.pattern_disposition_details.fs_operation_blocked | boolean | | False |
action_result.data.\*.pattern_disposition_details.handle_operation_downgraded | boolean | | False |
action_result.data.\*.pattern_disposition_details.inddet_mask | boolean | | False |
action_result.data.\*.pattern_disposition_details.indicator | boolean | | False |
action_result.data.\*.pattern_disposition_details.kill_action_failed | boolean | | False |
action_result.data.\*.pattern_disposition_details.kill_parent | boolean | | False |
action_result.data.\*.pattern_disposition_details.kill_process | boolean | | False |
action_result.data.\*.pattern_disposition_details.kill_subprocess | boolean | | False |
action_result.data.\*.pattern_disposition_details.mfa_required | boolean | | False |
action_result.data.\*.pattern_disposition_details.operation_blocked | boolean | | False |
action_result.data.\*.pattern_disposition_details.policy_disabled | boolean | | False |
action_result.data.\*.pattern_disposition_details.prevention_provisioning_enabled | boolean | | False |
action_result.data.\*.pattern_disposition_details.process_blocked | boolean | | False |
action_result.data.\*.pattern_disposition_details.quarantine_file | boolean | | False |
action_result.data.\*.pattern_disposition_details.quarantine_machine | boolean | | False |
action_result.data.\*.pattern_disposition_details.registry_operation_blocked | boolean | | False |
action_result.data.\*.pattern_disposition_details.response_action_already_applied | boolean | | False |
action_result.data.\*.pattern_disposition_details.response_action_failed | boolean | | False |
action_result.data.\*.pattern_disposition_details.response_action_triggered | boolean | | False |
action_result.data.\*.pattern_disposition_details.rooting | boolean | | False |
action_result.data.\*.pattern_disposition_details.sensor_only | boolean | | False |
action_result.data.\*.pattern_disposition_details.suspend_parent | boolean | | False |
action_result.data.\*.pattern_disposition_details.suspend_process | boolean | | False |
action_result.data.\*.pattern_id | numeric | | 32 |
action_result.data.\*.platform | string | | Windows |
action_result.data.\*.process_end_time | string | | 1724351403 |
action_result.data.\*.process_id | string | | 1336xxxxxxxxxx1294 |
action_result.data.\*.process_start_time | string | | 1724351403 |
action_result.data.\*.product | string | | epp |
action_result.data.\*.scenario | string | | malicious_document |
action_result.data.\*.seconds_to_resolved | numeric | | 0 |
action_result.data.\*.seconds_to_triaged | numeric | | 0 |
action_result.data.\*.severity | numeric | | 50 |
action_result.data.\*.severity_name | string | | Medium |
action_result.data.\*.sha1 | string | | ee8cxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx20b5 |
action_result.data.\*.sha256 | string | | 17f7xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx02ae |
action_result.data.\*.show_in_ui | boolean | | True |
action_result.data.\*.source_products.\* | string | | Falcon Insight |
action_result.data.\*.source_vendors.\* | string | | CrowdStrike |
action_result.data.\*.status | string | | in_progress |
action_result.data.\*.tactic | string | | Execution |
action_result.data.\*.tactic_id | string | | TA0002 |
action_result.data.\*.technique | string | | Exploitation for Client Execution |
action_result.data.\*.technique_id | string | | T1203 |
action_result.data.\*.timestamp | string | | 2024-08-22T18:30:03.238Z |
action_result.data.\*.tree_id | string | | 1336xxxxxxxxxx6384 |
action_result.data.\*.tree_root | string | | 1336xxxxxxxxxx4664 |
action_result.data.\*.triggering_process_graph_id | string | | pid:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx1294 |
action_result.data.\*.type | string | | ldt |
action_result.data.\*.updated_timestamp | string | | 2024-08-22T18:35:06.102982431Z |
action_result.data.\*.user_id | string | | S-1-5-21-246xxxx873-120xxxx372-215xxxx746-1000 |
action_result.data.\*.user_name | string | | testusername |
action_result.message | string | | Success |
action_result.status | string | | success |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get detections details'

Get a list of detections details by providing detection IDs \*The action uses legacy Detects API being deprecated. Please use the 'get epp details' action instead\*

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**detection_ids** | required | List of detection IDs. Comma-separated list allowed | string | `crowdstrike detection id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.detection_ids | string | `crowdstrike detection id` | |
action_result.data | string | | |
action_result.data.\*.assigned_to_name | string | | test user |
action_result.data.\*.assigned_to_uid | string | | usertest@gmail.com |
action_result.data.\*.behaviors.\*.alleged_filetype | string | | exe |
action_result.data.\*.behaviors.\*.behavior_id | string | | 10354 |
action_result.data.\*.behaviors.\*.cmdline | string | | |
action_result.data.\*.behaviors.\*.confidence | numeric | | 80 |
action_result.data.\*.behaviors.\*.control_graph_id | string | | ctg:46592f3d661a469eb2503d72a29afd3a:309255693652 |
action_result.data.\*.behaviors.\*.description | string | | |
action_result.data.\*.behaviors.\*.device_id | string | `md5` `crowdstrike device id` | 46592f3d661a469eb2503d72a29afd3a |
action_result.data.\*.behaviors.\*.display_name | string | | CredentialsInFilesCredentialAccess |
action_result.data.\*.behaviors.\*.filename | string | | powershell.exe |
action_result.data.\*.behaviors.\*.filepath | string | | \\Device\\HarddiskVolume2\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe |
action_result.data.\*.behaviors.\*.ioc_description | string | | \\Device\\HarddiskVolume2\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe |
action_result.data.\*.behaviors.\*.ioc_source | string | | library_load |
action_result.data.\*.behaviors.\*.ioc_type | string | | hash_sha256 |
action_result.data.\*.behaviors.\*.ioc_value | string | | 9f914d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccd9f |
action_result.data.\*.behaviors.\*.md5 | string | | 04029e121a0cfa5991749937dd22a1d9 |
action_result.data.\*.behaviors.\*.objective | string | | Gain Access |
action_result.data.\*.behaviors.\*.parent_details.parent_cmdline | string | | "C:\\WINDOWS\\system32\\cmd.exe" |
action_result.data.\*.behaviors.\*.parent_details.parent_md5 | string | | 8a2122e8162dbef04694b9c3e0b6cdee |
action_result.data.\*.behaviors.\*.parent_details.parent_process_graph_id | string | | pid:46592f3d661a469eb2503d72a29afd3a:740512001748 |
action_result.data.\*.behaviors.\*.parent_details.parent_sha256 | string | | b99d61d874728edc0918ca0eb10eab93d381e7367e377406e65963366c874450 |
action_result.data.\*.behaviors.\*.pattern_disposition | numeric | | 2048 |
action_result.data.\*.behaviors.\*.pattern_disposition_details.blocking_unsupported_or_disabled | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.bootup_safeguard_enabled | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.critical_process_disabled | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.detect | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.fs_operation_blocked | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.handle_operation_downgraded | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.inddet_mask | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.indicator | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.kill_action_failed | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.kill_parent | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.kill_process | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.kill_subprocess | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.operation_blocked | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.policy_disabled | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.process_blocked | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.quarantine_file | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.quarantine_machine | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.registry_operation_blocked | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.rooting | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.sensor_only | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.suspend_parent | boolean | | False True |
action_result.data.\*.behaviors.\*.pattern_disposition_details.suspend_process | boolean | | False True |
action_result.data.\*.behaviors.\*.scenario | string | | suspicious_activity |
action_result.data.\*.behaviors.\*.severity | numeric | | 70 |
action_result.data.\*.behaviors.\*.sha256 | string | | 9f914d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccd9f |
action_result.data.\*.behaviors.\*.tactic | string | | Credential Access |
action_result.data.\*.behaviors.\*.tactic_id | string | | TA0006 |
action_result.data.\*.behaviors.\*.technique | string | | Credentials In Files |
action_result.data.\*.behaviors.\*.technique_id | string | | T1552.001 |
action_result.data.\*.behaviors.\*.template_instance_id | string | | 2649 |
action_result.data.\*.behaviors.\*.timestamp | string | | 2022-09-26T11:30:26Z |
action_result.data.\*.behaviors.\*.triggering_process_graph_id | string | | pid:46592f3d661a469eb2503d72a29afd3a:743690872884 |
action_result.data.\*.behaviors.\*.user_id | string | | S-1-5-21-3607613384-2395287924-1763154957-1001 |
action_result.data.\*.behaviors.\*.user_name | string | | testuser |
action_result.data.\*.cid | string | `md5` | 3061c7ff3b634e22b38274d4b586558e |
action_result.data.\*.created_timestamp | string | | 2022-09-26T11:30:42.246972793Z |
action_result.data.\*.date_updated | string | | 2022-09-26T11:45:46Z |
action_result.data.\*.detection_id | string | `crowdstrike detection id` | ldt:46592f3d661a469eb2503d72a29afd3a:309255693652 |
action_result.data.\*.device.agent_load_flags | string | | 0 |
action_result.data.\*.device.agent_local_time | string | | 2022-08-22T15:45:16.195Z |
action_result.data.\*.device.agent_version | string | | 6.44.15806.0 |
action_result.data.\*.device.bios_manufacturer | string | | Phoenix Technologies LTD |
action_result.data.\*.device.bios_version | string | | 6.00 |
action_result.data.\*.device.cid | string | | 3061c7ff3b634e22b38274d4b586558e |
action_result.data.\*.device.config_id_base | string | | 65994753 |
action_result.data.\*.device.config_id_build | string | | 15806 |
action_result.data.\*.device.config_id_platform | string | | 3 |
action_result.data.\*.device.device_id | string | `md5` `crowdstrike device id` | 46592f3d661a469eb2503d72a29afd3a |
action_result.data.\*.device.external_ip | string | | 204.107.141.240 |
action_result.data.\*.device.first_seen | string | | 2020-08-13T23:45:59Z |
action_result.data.\*.device.hostname | string | | CB-TEST-02 |
action_result.data.\*.device.last_seen | string | | 2022-09-26T11:21:40Z |
action_result.data.\*.device.local_ip | string | | 10.1.18.205 |
action_result.data.\*.device.mac_address | string | | 00-50-56-12-34-56 |
action_result.data.\*.device.machine_domain | string | | sql19.local |
action_result.data.\*.device.major_version | string | | 10 |
action_result.data.\*.device.minor_version | string | | 0 |
action_result.data.\*.device.modified_timestamp | string | | 2022-09-26T11:27:43Z |
action_result.data.\*.device.os_version | string | | Windows 10 |
action_result.data.\*.device.platform_id | string | | 0 |
action_result.data.\*.device.platform_name | string | | Windows |
action_result.data.\*.device.product_type | string | | 1 |
action_result.data.\*.device.product_type_desc | string | | Workstation |
action_result.data.\*.device.site_name | string | | Default-First-Site-Name |
action_result.data.\*.device.status | string | | normal |
action_result.data.\*.device.system_manufacturer | string | | VMware, Inc. |
action_result.data.\*.device.system_product_name | string | | VMware Virtual Platform |
action_result.data.\*.email_sent | boolean | | False |
action_result.data.\*.first_behavior | string | | 2022-09-26T11:30:26Z |
action_result.data.\*.hostinfo.domain | string | | |
action_result.data.\*.last_behavior | string | | 2022-09-26T11:30:26Z |
action_result.data.\*.max_confidence | numeric | | 80 |
action_result.data.\*.max_severity | numeric | | 70 |
action_result.data.\*.max_severity_displayname | string | | High |
action_result.data.\*.seconds_to_resolved | numeric | | 2 |
action_result.data.\*.seconds_to_triaged | numeric | | 1 |
action_result.data.\*.show_in_ui | boolean | | True |
action_result.data.\*.status | string | | new |
action_result.summary.total_detections | numeric | | 44 |
action_result.message | string | | Total detections: 44 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get epp details'

Get list of alert details for EPP alerts by providing composite IDs, replaces legacy Detects API

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_ids** | required | List of alert composite_ids. Comma-separated list allowed | string | `crowdstrike alert id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.alert_ids | string | `crowdstrike alert id` | |
action_result.data.\*.agent_id | string | | 9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c |
action_result.data.\*.aggregate_id | string | | aggind:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx6384 |
action_result.data.\*.alleged_filetype | string | | exe |
action_result.data.\*.charlotte.can_triage | boolean | | False |
action_result.data.\*.charlotte.triage_status | string | | open |
action_result.data.\*.child_process_ids.\* | string | | pid:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx2640 |
action_result.data.\*.cid | string | | d615xxxxxxxx2158 |
action_result.data.\*.cmdline | string | | cmd /c echo MZ>log1.txt && cmd /c copy /b log1.txt+fabc.scr abc.scr && cmd /c abc.scr && cmd /c del log1.txt && cmd /c del fabc.scr |
action_result.data.\*.composite_id | string | `crowdstrike alert id` | d615xxxxxxxx2158:ind:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx1294-32-7878xxxxxxxxxxx1122 |
action_result.data.\*.confidence | numeric | | 50 |
action_result.data.\*.context_timestamp | string | | 2024-08-22T18:30:03Z |
action_result.data.\*.control_graph_id | string | | ctg:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx6384 |
action_result.data.\*.crawled_timestamp | string | | 2024-08-22T18:35:06.103126166Z |
action_result.data.\*.created_timestamp | string | | 2024-08-22T18:31:04.705194419Z |
action_result.data.\*.data_domains.\* | string | | Endpoint |
action_result.data.\*.description | string | | A productivity app launched a process from an executable stack. |
action_result.data.\*.device.agent_load_flags | string | | 3 |
action_result.data.\*.device.agent_local_time | string | | 2016-04-28T14:33:47.302Z |
action_result.data.\*.device.agent_version | string | | 5.25.10701.0 |
action_result.data.\*.device.bios_manufacturer | string | | Phoenix Technologies LTD |
action_result.data.\*.device.bios_version | string | | 6.00 |
action_result.data.\*.device.cid | string | | d615xxxxxxxx2158 |
action_result.data.\*.device.config_id_base | string | | 65994755 |
action_result.data.\*.device.config_id_build | string | | 10701 |
action_result.data.\*.device.config_id_platform | string | | 3 |
action_result.data.\*.device.device_id | string | `crowdstrike device id` | 9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c |
action_result.data.\*.device.external_ip | string | | 4x.xxx.xxx.xxx |
action_result.data.\*.device.first_seen | string | | 2024-08-22T18:30:04Z |
action_result.data.\*.device.hostname | string | | example-host |
action_result.data.\*.device.last_seen | string | | 2024-08-22T18:30:03Z |
action_result.data.\*.device.major_version | string | | 6 |
action_result.data.\*.device.minor_version | string | | 1 |
action_result.data.\*.device.modified_timestamp | string | | 2024-08-22T18:30:13Z |
action_result.data.\*.device.os_version | string | | Windows 7 |
action_result.data.\*.device.platform_id | string | | 0 |
action_result.data.\*.device.platform_name | string | | Windows |
action_result.data.\*.device.product_type | string | | 1 |
action_result.data.\*.device.product_type_desc | string | | Workstation |
action_result.data.\*.device.status | string | | normal |
action_result.data.\*.device.system_manufacturer | string | | VMware, Inc. |
action_result.data.\*.device.system_product_name | string | | VMware Virtual Platform |
action_result.data.\*.display_name | string | | SpearPhishExecutableStack |
action_result.data.\*.email_sent | boolean | | True |
action_result.data.\*.external | boolean | | False |
action_result.data.\*.falcon_host_link | string | | https://falcon.crowdstrike.com/activity-v2/detections/d615xxxxxxxx2158:ind:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx1294-32-7878xxxxxxxxxxx1122?\_cid=g01000co2vxxxxxxxxxxxxu5f72jzjfu |
action_result.data.\*.filename | string | | cmd.exe |
action_result.data.\*.filepath | string | | \\Device\\HarddiskVolume1\\Windows\\SysWOW64\\cmd.exe |
action_result.data.\*.global_prevalence | string | | common |
action_result.data.\*.grandparent_details.cmdline | string | | C:\\Windows\\Explorer.EXE |
action_result.data.\*.grandparent_details.filename | string | | explorer.exe |
action_result.data.\*.grandparent_details.filepath | string | | \\Device\\HarddiskVolume1\\Windows\\explorer.exe |
action_result.data.\*.grandparent_details.local_process_id | string | | 1260 |
action_result.data.\*.grandparent_details.md5 | string | | ac4c51eb24aaxxxxxxxxxxb159189e24 |
action_result.data.\*.grandparent_details.process_graph_id | string | | pid:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx0581 |
action_result.data.\*.grandparent_details.process_id | string | | 1336xxxxxxxxxx0581 |
action_result.data.\*.grandparent_details.sha256 | string | | 6a67xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx576a |
action_result.data.\*.grandparent_details.timestamp | string | | 2024-08-22T18:30:03.000Z |
action_result.data.\*.grandparent_details.user_graph_id | string | | uid:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:S-1-5-21-246xxxx873-120xxxx372-215xxxx746-1000 |
action_result.data.\*.grandparent_details.user_id | string | | S-1-5-21-246xxxx873-120xxxx372-215xxxx746-1000 |
action_result.data.\*.grandparent_details.user_name | string | | testusername |
action_result.data.\*.id | string | | ind:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx1294-32-7878xxxxxxxxxxx1122 |
action_result.data.\*.incident.created | string | | 2024-08-22T18:30:03Z |
action_result.data.\*.incident.end | string | | 2024-08-22T18:30:03Z |
action_result.data.\*.incident.id | string | | inc:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:7e90xxxxxxxxxxxxxxxxxxxxxxxx399c |
action_result.data.\*.incident.score | string | | 77.2905584547083 |
action_result.data.\*.incident.start | string | | 2024-08-22T18:30:03Z |
action_result.data.\*.indicator_id | string | | ind:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx1294-32-7878xxxxxxxxxxx1122 |
action_result.data.\*.ioc_context.\* | string | | [] |
action_result.data.\*.ioc_values.\* | string | | [] |
action_result.data.\*.local_prevalence | string | | common |
action_result.data.\*.local_process_id | string | | 2956 |
action_result.data.\*.logon_domain | string | | WIN-ABCDEFG |
action_result.data.\*.md5 | string | | ad7b9c14xxxxxxxxxxxxxxxxxxxx2b98 |
action_result.data.\*.name | string | | SpearPhishExecutableStack |
action_result.data.\*.objective | string | | Follow Through |
action_result.data.\*.parent_details.cmdline | string | | "C:\\Program Files (x86)\\Microsoft Office\\OFFICE11\\WINWORD.EXE" /n /dde |
action_result.data.\*.parent_details.filename | string | | WINWORD.EXE |
action_result.data.\*.parent_details.filepath | string | | \\Device\\HarddiskVolume1\\Program Files (x86)\\Microsoft Office\\OFFICE11\\WINWORD.EXE |
action_result.data.\*.parent_details.local_process_id | string | | 2756 |
action_result.data.\*.parent_details.md5 | string | | 10ff86bcxxxxxxxxxxxxxxxxxxxxfd507 |
action_result.data.\*.parent_details.process_graph_id | string | | pid:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx4664 |
action_result.data.\*.parent_details.process_id | string | | 1336xxxxxxxxxx4664 |
action_result.data.\*.parent_details.sha256 | string | | b38bxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx958d |
action_result.data.\*.parent_details.timestamp | string | | 2024-08-22T18:30:03Z |
action_result.data.\*.parent_details.user_graph_id | string | | uid:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:S-1-5-21-246xxxx873-120xxxx372-215xxxx746-1000 |
action_result.data.\*.parent_details.user_id | string | | S-1-5-21-246xxxx873-120xxxx372-215xxxx746-1000 |
action_result.data.\*.parent_details.user_name | string | | testusername |
action_result.data.\*.parent_process_id | string | | 1336xxxxxxxxxx4664 |
action_result.data.\*.pattern_disposition | numeric | | 0 |
action_result.data.\*.pattern_disposition_description | string | | Detection, standard detection. |
action_result.data.\*.pattern_disposition_details.blocking_unsupported_or_disabled | boolean | | False |
action_result.data.\*.pattern_disposition_details.bootup_safeguard_enabled | boolean | | False |
action_result.data.\*.pattern_disposition_details.containment_file_system | boolean | | False |
action_result.data.\*.pattern_disposition_details.critical_process_disabled | boolean | | False |
action_result.data.\*.pattern_disposition_details.detect | boolean | | False |
action_result.data.\*.pattern_disposition_details.fs_operation_blocked | boolean | | False |
action_result.data.\*.pattern_disposition_details.handle_operation_downgraded | boolean | | False |
action_result.data.\*.pattern_disposition_details.inddet_mask | boolean | | False |
action_result.data.\*.pattern_disposition_details.indicator | boolean | | False |
action_result.data.\*.pattern_disposition_details.kill_action_failed | boolean | | False |
action_result.data.\*.pattern_disposition_details.kill_parent | boolean | | False |
action_result.data.\*.pattern_disposition_details.kill_process | boolean | | False |
action_result.data.\*.pattern_disposition_details.kill_subprocess | boolean | | False |
action_result.data.\*.pattern_disposition_details.mfa_required | boolean | | False |
action_result.data.\*.pattern_disposition_details.operation_blocked | boolean | | False |
action_result.data.\*.pattern_disposition_details.policy_disabled | boolean | | False |
action_result.data.\*.pattern_disposition_details.prevention_provisioning_enabled | boolean | | False |
action_result.data.\*.pattern_disposition_details.process_blocked | boolean | | False |
action_result.data.\*.pattern_disposition_details.quarantine_file | boolean | | False |
action_result.data.\*.pattern_disposition_details.quarantine_machine | boolean | | False |
action_result.data.\*.pattern_disposition_details.registry_operation_blocked | boolean | | False |
action_result.data.\*.pattern_disposition_details.response_action_already_applied | boolean | | False |
action_result.data.\*.pattern_disposition_details.response_action_failed | boolean | | False |
action_result.data.\*.pattern_disposition_details.response_action_triggered | boolean | | False |
action_result.data.\*.pattern_disposition_details.rooting | boolean | | False |
action_result.data.\*.pattern_disposition_details.sensor_only | boolean | | False |
action_result.data.\*.pattern_disposition_details.suspend_parent | boolean | | False |
action_result.data.\*.pattern_disposition_details.suspend_process | boolean | | False |
action_result.data.\*.pattern_id | numeric | | 32 |
action_result.data.\*.platform | string | | Windows |
action_result.data.\*.process_end_time | string | | 1724351403 |
action_result.data.\*.process_id | string | | 1336xxxxxxxxxx1294 |
action_result.data.\*.process_start_time | string | | 1724351403 |
action_result.data.\*.product | string | | epp |
action_result.data.\*.scenario | string | | malicious_document |
action_result.data.\*.seconds_to_resolved | numeric | | 0 |
action_result.data.\*.seconds_to_triaged | numeric | | 0 |
action_result.data.\*.severity | numeric | | 50 |
action_result.data.\*.severity_name | string | | Medium |
action_result.data.\*.sha1 | string | | ee8cxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx20b5 |
action_result.data.\*.sha256 | string | | 17f7xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx02ae |
action_result.data.\*.show_in_ui | boolean | | True |
action_result.data.\*.source_products.\* | string | | Falcon Insight |
action_result.data.\*.source_vendors.\* | string | | CrowdStrike |
action_result.data.\*.status | string | | in_progress |
action_result.data.\*.tactic | string | | Execution |
action_result.data.\*.tactic_id | string | | TA0002 |
action_result.data.\*.technique | string | | Exploitation for Client Execution |
action_result.data.\*.technique_id | string | | T1203 |
action_result.data.\*.timestamp | string | | 2024-08-22T18:30:03.238Z |
action_result.data.\*.tree_id | string | | 1336xxxxxxxxxx6384 |
action_result.data.\*.tree_root | string | | 1336xxxxxxxxxx4664 |
action_result.data.\*.triggering_process_graph_id | string | | pid:9a8d0d2fe0xxxxxxxxxxxxxxxxxxc74c:1336xxxxxxxxxx1294 |
action_result.data.\*.type | string | | ldt |
action_result.data.\*.updated_timestamp | string | | 2024-08-22T18:35:06.102982431Z |
action_result.data.\*.user_id | string | | S-1-5-21-246xxxx873-120xxxx372-215xxxx746-1000 |
action_result.data.\*.user_name | string | | testusername |
action_result.message | string | | Success |
action_result.status | string | | success |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update detections'

Update detections in crowdstrike host \*The action uses legacy Detects API being deprecated. Please use the 'update epp alerts' action instead\*

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**detection_ids** | required | List of Detection IDs to update, Comma-separated list allowed | string | `crowdstrike detection id` |
**comment** | optional | Comment to add to the detection (Maximum 2048 bytes) | string | |
**assigned_to_user** | optional | User ID to assign | string | `crowdstrike unique user id` |
**show_in_ui** | optional | This detection is displayed or not in falcon UI | boolean | |
**status** | optional | Status to set | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.assigned_to_user | string | `crowdstrike unique user id` | |
action_result.parameter.comment | string | | update status of detection |
action_result.parameter.detection_ids | string | `crowdstrike detection id` | ldt:07c312fabcb8473454d0a16f118928fg:10548439893999 |
action_result.parameter.show_in_ui | boolean | | True False |
action_result.parameter.status | string | | in_progress |
action_result.data.\*.meta.powered_by | string | | legacy-detects |
action_result.data.\*.meta.query_time | numeric | | 0 |
action_result.data.\*.meta.trace_id | string | | a30c7b54-ae00-4a87-8324-0a575ba7dcb4 |
action_result.data.\*.meta.writes.resources_affected | numeric | | 2 |
action_result.summary | string | | |
action_result.summary.detections_affected | numeric | | 1 |
action_result.message | string | | Detections affected: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update epp alerts'

Update EPP alerts in CrowdStrike, replaces legacy Detects API

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_ids** | required | List of alert composite_ids to update, Comma-separated list allowed | string | `crowdstrike alert id` |
**comment** | optional | Comment to add to the alert (Maximum 2048 bytes) | string | |
**assigned_to_user** | optional | User to assign (can be email, UUID, or username) | string | `crowdstrike user id` `email` |
**unassign** | optional | If there are any users currently assigned to specified alerts, unassign them | string | |
**show_in_ui** | optional | Control whether this alert is displayed in Falcon UI | boolean | |
**status** | optional | Status to set | string | |
**add_tags** | optional | Tags to add to the alert, Comma-separated list allowed | string | |
**remove_tags** | optional | Tags to remove from the alert, Comma-separated list allowed | string | |
**remove_tags_by_prefix** | optional | Remove all tags with this prefix | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.alert_ids | string | `crowdstrike alert id` | |
action_result.parameter.assigned_to_user | string | `crowdstrike user id` `email` | |
action_result.parameter.unassign | string | | |
action_result.parameter.show_in_ui | boolean | | |
action_result.parameter.status | string | | |
action_result.parameter.add_tags | string | | |
action_result.parameter.remove_tags | string | | |
action_result.parameter.remove_tags_by_prefix | string | | |
action_result.data.\*.errors.\* | string | | [] |
action_result.data.\*.meta.pagination.limit | numeric | | 5 |
action_result.data.\*.meta.pagination.offset | numeric | | 0 |
action_result.data.\*.meta.pagination.total | numeric | | 10000 |
action_result.data.\*.meta.powered_by | string | | detectsapi |
action_result.data.\*.meta.query_time | numeric | | 0.044395707 |
action_result.data.\*.meta.trace_id | string | | f755297a-e287-4012-b5e3-ff88691e95e9 |
action_result.data.\*.meta.writes.resources_affected | numeric | | 0 |
action_result.data.\*.resources.\* | string | | d615xxxxxxxx2158:ind:9a8dxxxxxxxxc74c:1336xxxxxxxx1294-32-7878xxxxxxxx1122 |
action_result.message | string | | Success |
action_result.status | string | | success |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list alerts'

Get a list of alerts

Type: **investigate** \
Read only: **True**

This action supports filtering in order to retrieve a particular set of alerts.

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
action_result.status | string | | success failed |
action_result.parameter.filter | string | | modified_timestamp:\<='2019-06-14T10:22:02.02236652Z' |
action_result.parameter.limit | numeric | | 120 |
action_result.parameter.sort | string | | created_timestamp.asc |
action_result.data.\*.aggregate_id | string | | aggind:3061c7ff3b634e22b38274d4b586558e:3EC58D8F-599D-4CEC-8BB1-BFDE96477FB1 |
action_result.data.\*.cid | string | `md5` | 3061c7ff3b634e22b38274d4b586558e |
action_result.data.\*.composite_id | string | | 3061c7ff3b634e22b38274d4b586558e:ind:3061c7ff3b634e22b38274d4b586558e:3EC58D8F-599D-4CEC-8BB1-BFDE96477FB1 |
action_result.data.\*.confidence | numeric | | 20 |
action_result.data.\*.context_timestamp | string | | 2022-11-16T09:42:26.413Z |
action_result.data.\*.crawled_timestamp | string | | 2022-11-16T09:47:26.563805668Z |
action_result.data.\*.created_timestamp | string | | 2022-11-16T09:43:26.560807901Z |
action_result.data.\*.description | string | | A user received new privileges |
action_result.data.\*.display_name | string | | Privilege escalation (user) |
action_result.data.\*.end_time | string | | 2022-11-16T09:42:26.413Z |
action_result.data.\*.falcon_host_link | string | | https://falcon.crowdstrike.com/identity-protection/detections/3061c7ff3b634e22b38274d4b586558e:ind:3061c7ff3b634e22b38274d4b586558e:3EC58D8F-599D-4CEC-8BB1-BFDE96477FB1?cid=3061c7ff3b634e22b38274d4b586558e |
action_result.data.\*.id | string | | ind:3061c7ff3b634e22b38274d4b586558e:3EC58D8F-599D-4CEC-8BB1-BFDE96477FB1 |
action_result.data.\*.name | string | | IdpEntityPrivilegeEscalationUser |
action_result.data.\*.objective | string | | Gain Access |
action_result.data.\*.pattern_id | numeric | | 51113 |
action_result.data.\*.previous_privileges | string | | 0 |
action_result.data.\*.privileges | string | | 8321 |
action_result.data.\*.product | string | | idp |
action_result.data.\*.scenario | string | | privilege_escalation |
action_result.data.\*.severity | numeric | | 2 |
action_result.data.\*.show_in_ui | boolean | | True |
action_result.data.\*.source_account_domain | string | | IDENTITY.TEST |
action_result.data.\*.source_account_name | string | | test1 |
action_result.data.\*.source_account_object_sid | string | | S-1-5-21-14850137-2860523753-2226348357-1103 |
action_result.data.\*.start_time | string | | 2022-11-16T09:42:26.413Z |
action_result.data.\*.status | string | | new |
action_result.data.\*.tactic | string | | Privilege Escalation |
action_result.data.\*.tactic_id | string | | TA0004 |
action_result.data.\*.technique | string | | Valid Accounts |
action_result.data.\*.technique_id | string | | T1078 |
action_result.data.\*.timestamp | string | | 2022-11-16T09:42:26.56Z |
action_result.data.\*.type | string | | idp-user-endpoint-app-info |
action_result.data.\*.updated_timestamp | string | | 2022-11-16T09:47:26.561192951Z |
action_result.summary.total_alerts | numeric | | 50 |
action_result.message | string | | Total alerts: 50 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |
action_result.parameter.include_hidden | numeric | | True |

## action: 'list sessions'

Lists Real Time Response sessions

Type: **investigate** \
Read only: **True**

This action supports filtering in order to retrieve a particular session.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** | optional | Maximum RTR sessions to be fetched | numeric | |
**filter** | optional | Filter expression used to limit the fetched RTR sessions (FQL Syntax) | string | |
**sort** | optional | Property to sort by | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.filter | string | | modified_timestamp:\<='2019-06-14T10:22:02.02236652Z' |
action_result.parameter.limit | numeric | | 120 |
action_result.parameter.sort | string | | created_timestamp.asc |
action_result.data.\*.cid | string | `md5` | 3061c7ff3b634e22b38274d4b586558e |
action_result.data.\*.cloud_request_ids | string | | 06f052a0-d7a6-431b-987f-4afd92925a19 |
action_result.data.\*.commands | string | | |
action_result.data.\*.commands_queued | boolean | | True False |
action_result.data.\*.created_at | string | | 2019-09-24T20:52:08Z |
action_result.data.\*.deleted_at | string | | 2019-09-24T20:54:04Z |
action_result.data.\*.device_details | string | | |
action_result.data.\*.device_id | string | `md5` `crowdstrike device id` | 07c312fabcb8473454d0a16f118928ab |
action_result.data.\*.duration | numeric | | 0 |
action_result.data.\*.hostname | string | `host name` | CB-TEST-01 |
action_result.data.\*.id | string | `crowdstrike rtr session id` | c0ab8e89-edb0-485f-a8ee-b52d73453a4b |
action_result.data.\*.logs.\*.base_command | string | | pwd |
action_result.data.\*.logs.\*.cloud_request_id | string | | 06f052a0-d7a6-431b-987f-4afd92925a19 |
action_result.data.\*.logs.\*.command_string | string | | pwd |
action_result.data.\*.logs.\*.created_at | string | | 2019-09-24T20:52:08Z |
action_result.data.\*.logs.\*.current_directory | string | | C:\\ |
action_result.data.\*.logs.\*.id | numeric | | 2522218 |
action_result.data.\*.logs.\*.session_id | string | | c0ab8e89-edb0-485f-a8ee-b52d73453a4b |
action_result.data.\*.logs.\*.updated_at | string | | 2019-09-24T20:52:08Z |
action_result.data.\*.offline_queued | boolean | | True False |
action_result.data.\*.origin | string | | source:hosts,deviceId:07c312fabcb8473454d0a16f118928ab |
action_result.data.\*.platform_id | numeric | | 0 |
action_result.data.\*.platform_name | string | | |
action_result.data.\*.pwd | string | | |
action_result.data.\*.updated_at | string | | 2019-09-24T20:52:14Z |
action_result.data.\*.user_id | string | | api-client-05dbdf165b474db597007c6f88780e39 |
action_result.data.\*.user_uuid | string | | 05dbdf16-5b47-4db5-9700-7c6f88780e39 |
action_result.summary.total_sessions | numeric | | 1 |
action_result.message | string | | Total sessions: 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'run command'

Execute an active responder command on a single host

Type: **generic** \
Read only: **False**

The API works by first creating a cloud request to execute the command, then the results need to be retrieved using a GET with the cloud_request_id. The action will attempt to retrieve the results, but in the event that a timeout occurs, execute a 'get command details' action.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | Device ID | string | `md5` `crowdstrike device id` |
**session_id** | required | RTR Session ID | string | `crowdstrike rtr session id` |
**command** | required | RTR command to execute on host | string | |
**data** | optional | Data/Arguments for the command | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.command | string | | get ls |
action_result.parameter.data | string | | C:\\Users\\testuser\\go\\src\\simulate\\DLL_KEYLOG.dll |
action_result.parameter.device_id | string | `md5` `crowdstrike device id` | 07c312fabcb8473454d0a16f118928ab |
action_result.parameter.session_id | string | `crowdstrike rtr session id` | 90981f4c-f6c1-4437-b191-beae115c4929 |
action_result.data.\*.meta.powered_by | string | | empower-api |
action_result.data.\*.meta.query_time | numeric | | 0.038770347 |
action_result.data.\*.meta.trace_id | string | | f983d1ab-97d7-4af7-8bd7-1a6b8de0c05d |
action_result.data.\*.resources.\*.base_command | string | | ls |
action_result.data.\*.resources.\*.complete | boolean | | True False |
action_result.data.\*.resources.\*.session_id | string | | 9705111a-9928-4c10-b385-eefda32f9575 |
action_result.data.\*.resources.\*.stderr | string | | Check your filename. Couldn't find 'some_file.txt' |
action_result.data.\*.resources.\*.stdout | string | | Directory listing for C:\\ - <br>Name |
action_result.data.\*.resources.\*.task_id | string | | d901dbea-f556-4f32-921b-056bbc00b4e0 |
action_result.summary.cloud_request_id | string | `crowdstrike cloud request id` | 4b185028-39a3-4452-8e96-6da3729095fa |
action_result.message | string | | Cloud request id: d901dbea-f556-4f32-921b-056bbc00b4e0 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'run admin command'

Execute an RTR Admin command on a single host

Type: **generic** \
Read only: **False**

This action requires a token with RTR Admin permissions.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device_id** | required | Device ID | string | `crowdstrike device id` |
**session_id** | required | RTR Session ID | string | `crowdstrike rtr session id` |
**command** | required | RTR Admin command to execute on host | string | |
**data** | optional | Data/Arguments for the command | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.command | string | | get ls |
action_result.parameter.data | string | | C:\\Users\\testuser\\go\\src\\simulate\\DLL_KEYLOG.dll |
action_result.parameter.device_id | string | `crowdstrike device id` | 07c312fabcb8473454d0a16f118928ab |
action_result.parameter.session_id | string | `crowdstrike rtr session id` | 90981f4c-f6c1-4437-b191-beae115c4929 |
action_result.data.\*.meta.powered_by | string | | empower-api |
action_result.data.\*.meta.query_time | numeric | | 0.038770347 |
action_result.data.\*.meta.trace_id | string | | f983d1ab-97d7-4af7-8bd7-1a6b8de0c05d |
action_result.data.\*.resources.\*.base_command | string | | ls |
action_result.data.\*.resources.\*.complete | boolean | | True False |
action_result.data.\*.resources.\*.session_id | string | | 9705111a-9928-4c10-b385-eefda32f9575 |
action_result.data.\*.resources.\*.stderr | string | | Check your filename. Couldn't find 'some_file.txt' |
action_result.data.\*.resources.\*.stdout | string | | Directory listing for C:\\ - <br>Name |
action_result.data.\*.resources.\*.task_id | string | | d901dbea-f556-4f32-921b-056bbc00b4e0 |
action_result.summary.cloud_request_id | string | `crowdstrike cloud request id` | 4b185028-39a3-4452-8e96-6da3729095fa |
action_result.message | string | | Cloud request id: d901dbea-f556-4f32-921b-056bbc00b4e0 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get command details'

Retrieve results of an active responder command executed on a single host

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**cloud_request_id** | required | Cloud Request ID for Command | string | `crowdstrike cloud request id` |
**timeout_seconds** | optional | Time (in seconds; default is 60) to wait before timing out poll for results | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.cloud_request_id | string | `crowdstrike cloud request id` | 4b185028-39a3-4452-8e96-6da3729095fa |
action_result.parameter.timeout_seconds | numeric | | 60 |
action_result.data.\*.meta.powered_by | string | | empower-api |
action_result.data.\*.meta.query_time | numeric | | 0.038770347 |
action_result.data.\*.meta.trace_id | string | | f983d1ab-97d7-4af7-8bd7-1a6b8de0c05d |
action_result.data.\*.resources.\*.base_command | string | | ls |
action_result.data.\*.resources.\*.complete | boolean | | True False |
action_result.data.\*.resources.\*.session_id | string | | 9705111a-9928-4c10-b385-eefda32f9575 |
action_result.data.\*.resources.\*.stderr | string | | Check your filename. Couldn't find 'some_file.txt' |
action_result.data.\*.resources.\*.stdout | string | | Directory listing for C:\\ - <br>Name |
action_result.data.\*.resources.\*.task_id | string | | d901dbea-f556-4f32-921b-056bbc00b4e0 |
action_result.summary.results | string | | Successfully executed command |
action_result.message | string | | Results: Successfully executed command |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list session files'

Get a list of files for the specified RTR session

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**session_id** | required | RTR Session ID | string | `crowdstrike rtr session id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.session_id | string | `crowdstrike rtr session id` | 0bf3c91f-1267-4a6d-a694-d225aeac65eb |
action_result.data.\*.meta.powered_by | string | | empower-api |
action_result.data.\*.meta.query_time | numeric | | 0.060876276 |
action_result.data.\*.meta.trace_id | string | | ccb8edf2-fd5b-4221-81c8-0e80de3e66a6 |
action_result.data.\*.resources.\*.cloud_request_id | string | | 292efe5f-a755-45f8-a95a-72138d21b8db |
action_result.data.\*.resources.\*.created_at | string | | 2019-10-08T20:12:14Z |
action_result.data.\*.resources.\*.deleted_at | string | | |
action_result.data.\*.resources.\*.id | numeric | | 104874 |
action_result.data.\*.resources.\*.name | string | `file name` | \\Device\\HarddiskVolume2\\Users\\testuser\\go\\src\\simulate\\DLL_KEYLOG.dll |
action_result.data.\*.resources.\*.session_id | string | `crowdstrike rtr session id` | 0bf3c91f-1267-4a6d-a694-d225aeac65eb |
action_result.data.\*.resources.\*.sha256 | string | `sha256` | 53d84902e0a25be8706df19506f78799deab0082149b926b4117270f9c8673ad |
action_result.data.\*.resources.\*.size | numeric | | 0 |
action_result.data.\*.resources.\*.updated_at | string | | 2019-10-08T20:12:14Z |
action_result.summary.total_files | numeric | | 1 |
action_result.message | string | | Session files listed successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get incident behaviors'

Get details on behaviors by providing behavior IDs

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ids** | required | List of behavior IDs. Comma separated list allowed | string | `crowdstrike incidentbehavior id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ids | string | `crowdstrike incidentbehavior id` | ind:9e262c00000a46916beeaef04e45bc6a:dc8e3b1300004da2a6e7b20656e3276d |
action_result.data.\*.aid | string | | w6h79wgbzy4ofsa093dp2s808qe8gswr |
action_result.data.\*.behavior_id | string | `crowdstrike incidentbehavior id` | ind:9e262c00000a46916beeaef04e45bc6a:dc8e3b1300004da2a6e7b20656e3276d |
action_result.data.\*.cid | string | | e6m35yiizlefbv6o4az6b46sgjipx6lg |
action_result.data.\*.cmdline | string | | |
action_result.data.\*.compound_tto | string | | |
action_result.data.\*.detection_ids | string | `crowdstrike detection id` | ldt:07c312fabcb8473454d0a16f118928ab:10548439893000 |
action_result.data.\*.display_name | string | | SampleTemplateDetection |
action_result.data.\*.domain | string | | CB-TEST-02 |
action_result.data.\*.errors.\*.code | numeric | | 400 |
action_result.data.\*.errors.\*.message | string | | invalid behavior id=test |
action_result.data.\*.filepath | string | | C:\\user\\somefile.txt |
action_result.data.\*.incident_id | string | `crowdstrike incident id` | inc:9e262c70027a46916beeaef04e45bc6a:dc8e3b1325634da2a6e7b20656e3276d |
action_result.data.\*.meta.powered_by | string | | incident-api |
action_result.data.\*.meta.query_time | numeric | | 0.000305451 |
action_result.data.\*.meta.trace_id | string | | ebb97943-be70-4acc-a2dd-c663b59761fa |
action_result.data.\*.objective | string | | Keep Access |
action_result.data.\*.pattern_disposition | numeric | | 2048 |
action_result.data.\*.pattern_disposition_details.blocking_unsupported_or_disabled | boolean | | False |
action_result.data.\*.pattern_disposition_details.bootup_safeguard_enabled | boolean | | True False |
action_result.data.\*.pattern_disposition_details.critical_process_disabled | boolean | | True False |
action_result.data.\*.pattern_disposition_details.detect | boolean | | True False |
action_result.data.\*.pattern_disposition_details.fs_operation_blocked | boolean | | True False |
action_result.data.\*.pattern_disposition_details.handle_operation_downgraded | boolean | | True False |
action_result.data.\*.pattern_disposition_details.inddet_mask | boolean | | True False |
action_result.data.\*.pattern_disposition_details.indicator | boolean | | True False |
action_result.data.\*.pattern_disposition_details.kill_action_failed | boolean | | False |
action_result.data.\*.pattern_disposition_details.kill_parent | boolean | | True False |
action_result.data.\*.pattern_disposition_details.kill_process | boolean | | True False |
action_result.data.\*.pattern_disposition_details.kill_subprocess | boolean | | True False |
action_result.data.\*.pattern_disposition_details.operation_blocked | boolean | | True False |
action_result.data.\*.pattern_disposition_details.policy_disabled | boolean | | True False |
action_result.data.\*.pattern_disposition_details.process_blocked | boolean | | True False |
action_result.data.\*.pattern_disposition_details.quarantine_file | boolean | | True False |
action_result.data.\*.pattern_disposition_details.quarantine_machine | boolean | | True False |
action_result.data.\*.pattern_disposition_details.registry_operation_blocked | boolean | | True False |
action_result.data.\*.pattern_disposition_details.rooting | boolean | | True False |
action_result.data.\*.pattern_disposition_details.sensor_only | boolean | | True False |
action_result.data.\*.pattern_disposition_details.suspend_parent | boolean | | False |
action_result.data.\*.pattern_disposition_details.suspend_process | boolean | | False |
action_result.data.\*.pattern_id | numeric | | 1024 |
action_result.data.\*.sha256 | string | | ln3g11yf8r40be90ups2q1435ybhzdopbkt103wce5ligiuhww2b4l1f7tmp1vhi |
action_result.data.\*.tactic | string | | Persistance |
action_result.data.\*.tactic_id | string | | CSTA0001 |
action_result.data.\*.technique | string | | Hidden Files and Directories |
action_result.data.\*.technique_id | string | | CST0001 |
action_result.data.\*.template_instance_id | numeric | | 102 |
action_result.data.\*.timestamp | string | | 2020-03-04T10:00:00Z |
action_result.data.\*.user_name | string | | testuser |
action_result.summary | string | | |
action_result.message | string | | Incident behavior fetched successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update incident'

Perform a set of actions on one or more incidents, such as adding tags or comments or updating the incident name or description

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ids** | required | List of incident IDs. Comma separated list allowed | string | `crowdstrike incident id` |
**add_tag** | optional | Adds the associated tag to all the incident(s) of the ids list. See example values for the defined list | string | |
**delete_tag** | optional | Deletes the matching tag from all the incident(s) in the ids list. See example values for the defined list | string | |
**update_name** | optional | Updates the name of all the incident(s) in the ids list | string | |
**update_description** | optional | Updates the description of all the incident(s) listed in the ids | string | |
**update_status** | optional | Updates the status of all the incident(s) in the ids list | string | |
**add_comment** | optional | Adds a comment for all the incident(s) in the ids list | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.add_comment | string | | Minor Incident |
action_result.parameter.add_tag | string | | test1 |
action_result.parameter.delete_tag | string | | test2 |
action_result.parameter.ids | string | `crowdstrike incident id` | inc:9e262c70027a46916beeaef04e45bc6a:dc8e3b1325634da2a6e7b20656e3276d |
action_result.parameter.update_description | string | | IOC found at 2020-07-22T23:54:41Z |
action_result.parameter.update_name | string | | IOC at 2020-07-22T23:54:41Z |
action_result.parameter.update_status | string | | New |
action_result.data.\*.meta.powered_by | string | | incident-api |
action_result.data.\*.meta.query_time | numeric | | 0.026572641 |
action_result.data.\*.meta.trace_id | string | | 50f7477e-587f-4175-ad0d-bdbbd8d3b1ec |
action_result.summary | string | | |
action_result.message | string | | Incident updated successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list users'

Get information about all users in your Customer ID

Type: **investigate** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data.\*.meta.powered_by | string | | csam |
action_result.data.\*.meta.query_time | numeric | | 0.267336826 |
action_result.data.\*.meta.trace_id | string | | b4e1392e-68ad-4738-93f9-d95cee1cfe9f |
action_result.data.\*.resources.\*.cid | string | `crowdstrike customer id` | 4061c7ff3b634e22b38274d4b586554r |
action_result.data.\*.resources.\*.first_name | string | | Test |
action_result.data.\*.resources.\*.last_name | string | | Name |
action_result.data.\*.resources.\*.uid | string | `crowdstrike user id` | test@user.com |
action_result.data.\*.resources.\*.uuid | string | `crowdstrike unique user id` | bb777249-c782-4434-b57a-f15ac742926c |
action_result.summary | string | | |
action_result.message | string | | Users listed successfully |
action_result.summary.total_users | numeric | | 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get user roles'

Gets the roles that are assigned to the user

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_uuid** | required | Users Unqiue ID to get the roles for | string | `crowdstrike unique user id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.user_uuid | string | `crowdstrike unique user id` | bb777249-c782-4434-b57a-f15ac742926c |
action_result.data.\*.cid | string | | 3061c7ff3b634e22b38274d4b586558e |
action_result.data.\*.grant_type | string | | direct |
action_result.data.\*.role_id | string | | custom_ioas_manager |
action_result.data.\*.role_name | string | | Custom IOAs Manager |
action_result.data.\*.uuid | string | | b6330292-28e6-4198-994d-96f327c5b5bd |
action_result.summary | string | | |
action_result.message | string | | User roles fetched successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list roles'

Get information about all user roles from your Customer ID

Type: **investigate** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data.\*.meta.powered_by | string | | csam |
action_result.data.\*.meta.query_time | numeric | | 0.011271861 |
action_result.data.\*.meta.trace_id | string | | 48a46c11-ca36-4a1e-84f6-9a5b1137b7d3 |
action_result.data.\*.resources.\*.description | string | | Custom IOAs Manager |
action_result.data.\*.resources.\*.display_name | string | | Custom IOAs Manager |
action_result.data.\*.resources.\*.id | string | `crowdstrike user role id` | custom_ioas_manager |
action_result.data.\*.resources.\*.is_global | boolean | | True False |
action_result.summary | string | | |
action_result.message | string | | Roles listed successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get role'

Get information about all user roles from your Customer ID

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**role_id** | required | Role ID to get information about. Comma separated list allowed | string | `crowdstrike user role id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.role_id | string | `crowdstrike user role id` | dashboard_admin |
action_result.data.\*.description | string | | Can manage, create, update, and delete dashboards |
action_result.data.\*.display_name | string | | Dashboard Admin |
action_result.data.\*.errors.\*.code | numeric | | 404 |
action_result.data.\*.errors.\*.message | string | | Role ID ' custom_ioas_manager' not found |
action_result.data.\*.id | string | `crowdstrike user role id` | dashboard_admin |
action_result.data.\*.is_global | boolean | | True False |
action_result.data.\*.meta.powered_by | string | | csam |
action_result.data.\*.meta.query_time | numeric | | 0.000467839 |
action_result.data.\*.meta.trace_id | string | | 82983d79-59d2-49e1-a471-4f1833f80c46 |
action_result.summary | string | | |
action_result.message | string | | Role fetched successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list crowdscores'

Query environment wide CrowdScore and return the entity data

Type: **investigate** \
Read only: **True**

This action fetches crowdscores using pagination logic.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** | optional | Optional filter and sort criteria in the form of an FQL query | string | |
**sort** | optional | Sort the results by a specific field and direction. (Example: assigned_to.asc) | string | |
**offset** | optional | Starting index of overall result set from which to return ids. (Defaults to 0) | numeric | |
**limit** | optional | Limit the number of results to return. (Defaults to 50, Max 500) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.filter | string | | score: 0 |
action_result.parameter.limit | numeric | | 5 |
action_result.parameter.offset | numeric | | 100 |
action_result.parameter.sort | string | | assigned_to.asc |
action_result.data.\*.adjusted_score | numeric | | 3 |
action_result.data.\*.cid | string | | 3061d7ff3b634e22b38274d64798 |
action_result.data.\*.errors.\*.code | numeric | | 400 |
action_result.data.\*.errors.\*.message | string | | test is an invalid behavior sort parameter |
action_result.data.\*.id | string | `crowdstrike crowdscore id` | 99ff72e8c9c14955ba33cbcbd4112345_2020-05-18 07:38:05.219 +0000 UTC |
action_result.data.\*.meta.pagination.limit | numeric | | 500 |
action_result.data.\*.meta.pagination.offset | numeric | | 0 |
action_result.data.\*.meta.pagination.total | numeric | | 12960 |
action_result.data.\*.meta.powered_by | string | | incident-api |
action_result.data.\*.meta.query_time | numeric | | 0.096319664 |
action_result.data.\*.meta.trace_id | string | | 38f293ce-587e-4ff5-8231-4e738178468a |
action_result.data.\*.pagination.\*.limit | numeric | | |
action_result.data.\*.pagination.\*.offset | numeric | | |
action_result.data.\*.pagination.\*.total | numeric | | |
action_result.data.\*.resources.\*.cid | string | | 3061c7ff3b634e22b38274d4b5865500 |
action_result.data.\*.score | numeric | | 0 |
action_result.data.\*.timestamp | string | | 2020-03-04T10:00:00Z |
action_result.summary.total_crowdscores | numeric | | 2 |
action_result.message | string | | Total crowdscores: 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get incident details'

Get details on incidents by providing incident IDs

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ids** | required | List of incident IDs. Comma separated list allowed | string | `crowdstrike incident id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ids | string | `crowdstrike incident id` | inc:9e262c70027a46916beeaef04e45bc6a:dc8e3b1325634da2a6e7b20656e3276d |
action_result.data.\*.assigned_to | string | | b6330292-28e6-4198-994d-96f327c5b5cc |
action_result.data.\*.assigned_to_name | string | | Testname |
action_result.data.\*.cid | string | | ctw6caruad3lkbnnt22qzeyoxgf38zap |
action_result.data.\*.created | string | | 2020-03-04T10:00:00Z |
action_result.data.\*.description | string | | |
action_result.data.\*.end | string | | 2020-03-04T10:00:00Z |
action_result.data.\*.errors.\*.code | numeric | | 400 |
action_result.data.\*.errors.\*.message | string | | invalid incident id=fyughg |
action_result.data.\*.fine_score | numeric | | 1 |
action_result.data.\*.host_ids | string | `crowdstrike device id` | c9vnt7jbugw32626p9qsq3f9dx13sdnn |
action_result.data.\*.hosts.\*.agent_load_flags | string | | 1 |
action_result.data.\*.hosts.\*.agent_local_time | string | | 2020-03-04T10:00:00Z |
action_result.data.\*.hosts.\*.agent_version | string | | 5.23.10503.0 |
action_result.data.\*.hosts.\*.bios_manufacturer | string | | Phoenix Technologies LTD |
action_result.data.\*.hosts.\*.bios_version | string | | 6.00 |
action_result.data.\*.hosts.\*.cid | string | | ctw6caruad3lkbnnt22qzeyoxgf38zap |
action_result.data.\*.hosts.\*.config_id_base | string | | 65994753 |
action_result.data.\*.hosts.\*.config_id_build | string | | 10503 |
action_result.data.\*.hosts.\*.config_id_platform | string | | 3 |
action_result.data.\*.hosts.\*.device_id | string | `crowdstrike device id` | c9vnt7jbugw32626p9qsq3f9dx13sdnn |
action_result.data.\*.hosts.\*.external_ip | string | | 1.1.1.1 |
action_result.data.\*.hosts.\*.first_seen | string | | 2020-03-04T10:00:00Z |
action_result.data.\*.hosts.\*.hostname | string | | Sever01 |
action_result.data.\*.hosts.\*.last_seen | string | | 2020-03-04T10:00:00Z |
action_result.data.\*.hosts.\*.local_ip | string | | 192.168.0.0 |
action_result.data.\*.hosts.\*.mac_address | string | | 00-00-00-00-00-00 |
action_result.data.\*.hosts.\*.machine_domain | string | | domain.local |
action_result.data.\*.hosts.\*.major_version | string | | 10 |
action_result.data.\*.hosts.\*.minor_version | string | | 0 |
action_result.data.\*.hosts.\*.modified_timestamp | string | | 2020-03-04T10:00:00Z |
action_result.data.\*.hosts.\*.os_version | string | | Windows 7 |
action_result.data.\*.hosts.\*.ou | string | | DOMAIN LOCAL |
action_result.data.\*.hosts.\*.platform_id | string | | 0 |
action_result.data.\*.hosts.\*.platform_name | string | | Windows |
action_result.data.\*.hosts.\*.product_type | string | | 1 |
action_result.data.\*.hosts.\*.product_type_desc | string | | Workstation |
action_result.data.\*.hosts.\*.site_name | string | | |
action_result.data.\*.hosts.\*.status | string | | noraml |
action_result.data.\*.hosts.\*.system_manufacturer | string | | VMware, Inc. |
action_result.data.\*.hosts.\*.system_product_name | string | | VMware Virtual Platform |
action_result.data.\*.incident_id | string | `crowdstrike incident id` | inc:9e262c70027a46916beeaef04e45bc6a:dc8e3b1325634da2a6e7b20656e3276d |
action_result.data.\*.incident_type | numeric | | 1 |
action_result.data.\*.meta.powered_by | string | | incident-api |
action_result.data.\*.meta.query_time | numeric | | 0.000258709 |
action_result.data.\*.meta.trace_id | string | | b991aeb7-912f-45b2-abce-3759217a690c |
action_result.data.\*.modified_timestamp | string | | 2020-08-17T09:35:50.888512834Z |
action_result.data.\*.name | string | | |
action_result.data.\*.start | string | | 2020-03-04T10:00:00Z |
action_result.data.\*.state | string | | open closed |
action_result.data.\*.status | numeric | | 20 |
action_result.data.\*.tags | string | | |
action_result.data.\*.users | string | | |
action_result.summary.total_incidents | numeric | | 1 |
action_result.message | string | | Incident fetched: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list incident behaviors'

Search for behaviors by providing an FQL filter, sorting, and paging details

Type: **investigate** \
Read only: **True**

This action fetches incident behaviors using pagination logic.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** | optional | Optional filter and sort criteria in the form of an FQL query | string | |
**sort** | optional | Sort the results by a specific field and direction. (Example: assigned_to.asc) | string | |
**offset** | optional | Starting index of overall result set from which to return ids. (Defaults to 0) | numeric | |
**limit** | optional | Limit the number of results to return. (Defaults to 50, Max 500) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.filter | string | | incident_ids:['inc:9e262c70027a46916beeaef04e45bc6a:dc8e3b1325634da2a6e7b20656e3276d'] |
action_result.parameter.limit | numeric | | 5 |
action_result.parameter.offset | numeric | | 100 |
action_result.parameter.sort | string | | assigned_to.asc |
action_result.data.\* | string | `crowdstrike incidentbehavior id` | ind:9e262c70027a46916beeaef04e45bc6a:45890386125841-10264-352683776 |
action_result.data.\*.errors.\*.code | numeric | | 400 |
action_result.data.\*.errors.\*.message | string | | test is an invalid behavior sort parameter |
action_result.data.\*.meta.pagination.limit | numeric | | 50 |
action_result.data.\*.meta.pagination.offset | numeric | | 0 |
action_result.data.\*.meta.pagination.total | numeric | | 0 |
action_result.data.\*.meta.powered_by | string | | incident-api |
action_result.data.\*.meta.query_time | numeric | | 0.002429479 |
action_result.data.\*.meta.trace_id | string | | 202a0a0c-bcc1-4919-8932-2097213f903a |
action_result.data.\*.pagination.\*.limit | numeric | | |
action_result.data.\*.pagination.\*.offset | numeric | | |
action_result.data.\*.pagination.\*.total | numeric | | |
action_result.summary.total_incident_behaviors | numeric | | 2 |
action_result.message | string | | Total incident behaviors: 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list incidents'

Search for incidents by providing an FQL filter, sorting, and paging details

Type: **investigate** \
Read only: **True**

This action fetches incidents using pagination logic.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** | optional | Optional filter and sort criteria in the form of an FQL query | string | |
**sort** | optional | Sort the results by a specific field and direction. (Example: assigned_to.asc) | string | |
**offset** | optional | Starting index of overall result set from which to return ids. (Defaults to 0) | numeric | |
**limit** | optional | Limit the number of results to return. (Defaults to 50, Max 500) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.filter | string | | incident_ids:['inc:9e262c70027a46916beeaef04e45bc6a:dc8e3b1325634da2a6e7b20656e3276d'] |
action_result.parameter.limit | numeric | | 5 |
action_result.parameter.offset | numeric | | 100 |
action_result.parameter.sort | string | | assigned_to.asc |
action_result.data.\* | string | `crowdstrike incident id` | incident_ids:['inc:9e262c70027a46916beeaef04e45bc6a:dc8e3b1325634da2a6e7b20656e3276d'] |
action_result.data.\* | string | `crowdstrike incident id` | incident_ids:['inc:9e262c70027a46916beeaef04e45bc6a:dc8e3b1325634da2a6e7b20656e3276d'] |
action_result.data.\*.errors.\*.code | numeric | | 400 |
action_result.data.\*.errors.\*.message | string | | test is an invalid incident sort parameter |
action_result.data.\*.meta.pagination.limit | numeric | | 50 |
action_result.data.\*.meta.pagination.offset | numeric | | 0 |
action_result.data.\*.meta.pagination.total | numeric | | 0 |
action_result.data.\*.meta.powered_by | string | | incident-api |
action_result.data.\*.meta.query_time | numeric | | 0.003846595 |
action_result.data.\*.meta.trace_id | string | | bb02d451-d3a9-432c-b402-c08faa066264 |
action_result.data.\*.pagination.\*.limit | numeric | | |
action_result.data.\*.pagination.\*.offset | numeric | | |
action_result.data.\*.pagination.\*.total | numeric | | |
action_result.summary.total_incidents | numeric | | 2 |
action_result.message | string | | Total incidents: 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get session file'

Get RTR extracted file contents for the specified session and sha256 and add it to the vault

Type: **generic** \
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
action_result.status | string | | success failed |
action_result.parameter.file_hash | string | `sha256` | 53d84902e0a25be8706df19506f78799deab0082149b926b4117270f9c8673ad |
action_result.parameter.file_name | string | `filename` | test |
action_result.parameter.session_id | string | `crowdstrike rtr session id` | b2403653-1294-488e-be81-7aadb69b52f1 |
action_result.data.\*.container | string | | test_crowdstrike |
action_result.data.\*.container_id | numeric | | 2840 |
action_result.data.\*.create_time | string | | 0 minutes ago |
action_result.data.\*.created_via | string | | automation |
action_result.data.\*.hash | string | `sha1` | 30c5e524e975816fbce1d958150e394efc219772 |
action_result.data.\*.id | numeric | | 2 |
action_result.data.\*.metadata.md5 | string | | 16723c3d039bc94e1636c0bf0c23ec26 |
action_result.data.\*.metadata.sha1 | string | | d43b1c57023fab4e3040dd6f2970053d690b0fab |
action_result.data.\*.metadata.sha256 | string | | 8a050bf93fe354d6ad03c6ba2b286f2649fb1420ae80eefac773208e5a0b7c0d |
action_result.data.\*.mime_type | string | | application/x-7z-compressed |
action_result.data.\*.name | string | | test.7z |
action_result.data.\*.path | string | | |
action_result.data.\*.size | numeric | | 5122 |
action_result.data.\*.task | string | | |
action_result.data.\*.user | string | | admin |
action_result.data.\*.vault_document | numeric | | 556 |
action_result.data.\*.vault_id | string | `sha1` `vault id` | 30c5e524e975816fbce1d958150e394efc219772 |
action_result.summary.vault_id | string | `sha1` `vault id` | 30c5e524e975816fbce1d958150e394efc219772 |
action_result.message | string | | Session file fetched successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'set status'

Set the state of a detection in Crowdstrike Host \*The action uses legacy Detects API being deprecated. Please use the 'resolve epp alerts' action instead\*

Type: **generic** \
Read only: **False**

The detection <b>id</b> can be obtained from the Crowdstrike UI and its state can be set.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | Detection ID to set the state of | string | `crowdstrike detection id` |
**state** | required | State to set | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.id | string | `crowdstrike detection id` | ldt:07c312fabcb8473454d0a16f118928fg:10548439893999 |
action_result.parameter.state | string | | in_progress |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | Status set successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'resolve epp alerts'

Update the status of an EPP alert in CrowdStrike, replaces legacy Detects API

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_ids** | required | List of alert composite_ids to update, Comma-separated list allowed | string | `crowdstrike alert id` |
**status** | required | Status to set | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.alert_ids | string | `crowdstrike alert id` | |
action_result.parameter.status | string | | |
action_result.data.\*.errors.\* | string | | [] |
action_result.data.\*.meta.pagination.limit | numeric | | 5 |
action_result.data.\*.meta.pagination.offset | numeric | | 0 |
action_result.data.\*.meta.pagination.total | numeric | | 10000 |
action_result.data.\*.meta.powered_by | string | | detectsapi |
action_result.data.\*.meta.query_time | numeric | | 0.044395707 |
action_result.data.\*.meta.trace_id | string | | f755297a-e287-4012-b5e3-ff88691e95e9 |
action_result.data.\*.meta.writes.resources_affected | numeric | | 0 |
action_result.data.\*.resources.\* | string | | d615xxxxxxxx2158:ind:9a8dxxxxxxxxc74c:1336xxxxxxxx1294-32-7878xxxxxxxx1122 |
action_result.message | string | | Success |
action_result.status | string | | success |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get system info'

Get details of a device, given the device ID

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | Device ID from previous Crowdstrike IOC search | string | `crowdstrike device id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.id | string | `crowdstrike device id` | 0498d1102b23481162ff846d0633e14c |
action_result.data.\*.agent_load_flags | string | | 3 |
action_result.data.\*.agent_local_time | string | | 2015-07-31T14:07:42.816Z |
action_result.data.\*.agent_version | string | | 2.0.0010.3005 |
action_result.data.\*.bios_manufacturer | string | | Phoenix Technologies LTD |
action_result.data.\*.bios_version | string | | 6.00 |
action_result.data.\*.build_number | string | | 17134 |
action_result.data.\*.cid | string | `md5` | 3f40c380adc74a3187c27252c0227cff |
action_result.data.\*.config_id_base | string | | 65994752 |
action_result.data.\*.config_id_build | string | | 3005 |
action_result.data.\*.config_id_platform | string | | 3 |
action_result.data.\*.connection_ip | string | `ip` | 10.1.18.205 |
action_result.data.\*.connection_mac_address | string | | 00-50-56-12-34-56 |
action_result.data.\*.cpu_signature | string | | 329455 |
action_result.data.\*.default_gateway_ip | string | `ip` | 10.1.16.1 |
action_result.data.\*.device_id | string | `crowdstrike device id` | 0498d1102b23481162ff846d0633e14c |
action_result.data.\*.device_policies.device_control.applied | boolean | | True False |
action_result.data.\*.device_policies.device_control.applied_date | string | | 2020-05-12T17:24:23.856260169Z |
action_result.data.\*.device_policies.device_control.assigned_date | string | | 2020-05-12T17:24:12.52970392Z |
action_result.data.\*.device_policies.device_control.policy_id | string | | cb4babb273274f79a91e8a0e84164916 |
action_result.data.\*.device_policies.device_control.policy_type | string | | device-control |
action_result.data.\*.device_policies.firewall.applied | boolean | | True False |
action_result.data.\*.device_policies.firewall.applied_date | string | | 2020-07-08T03:12:30.212194872Z |
action_result.data.\*.device_policies.firewall.assigned_date | string | | 2020-07-08T03:07:38.48127371Z |
action_result.data.\*.device_policies.firewall.policy_id | string | | 2018f9894359493cb756bfa7dd3357a6 |
action_result.data.\*.device_policies.firewall.policy_type | string | | firewall |
action_result.data.\*.device_policies.firewall.rule_set_id | string | | 2018f9894359493cb756bfa7dd3357a6 |
action_result.data.\*.device_policies.global_config.applied | boolean | | True False |
action_result.data.\*.device_policies.global_config.applied_date | string | | 2020-04-16T02:44:27.694202488Z |
action_result.data.\*.device_policies.global_config.assigned_date | string | | 2020-04-16T02:42:41.826629904Z |
action_result.data.\*.device_policies.global_config.policy_id | string | | 49ee9efc99164562ad89640955f372ce |
action_result.data.\*.device_policies.global_config.policy_type | string | | globalconfig |
action_result.data.\*.device_policies.global_config.settings_hash | string | | f48b1bd1 |
action_result.data.\*.device_policies.jumpcloud.applied | numeric | | True |
action_result.data.\*.device_policies.jumpcloud.applied_date | string | | 2022-07-13T17:41:16.271074445Z |
action_result.data.\*.device_policies.jumpcloud.assigned_date | string | | 2022-07-13T17:40:53.552991354Z |
action_result.data.\*.device_policies.jumpcloud.policy_id | string | `md5` | 234766dcce654217babcbaa247ca31f0 |
action_result.data.\*.device_policies.jumpcloud.policy_type | string | | jumpcloud |
action_result.data.\*.device_policies.jumpcloud.settings_hash | string | `sha256` | 0aec295a677907c6e4de672edf1f172d2cefcc5ca96ed2b5e56f4d6745289694 |
action_result.data.\*.device_policies.prevention.applied | boolean | | True |
action_result.data.\*.device_policies.prevention.applied_date | string | | 2021-12-02T07:35:26.551598833Z |
action_result.data.\*.device_policies.prevention.assigned_date | string | | 2018-03-10T15:39:31.220730539Z |
action_result.data.\*.device_policies.prevention.policy_id | string | `md5` | f81459e0d85b4bc7b3ad14ad40889042 |
action_result.data.\*.device_policies.prevention.policy_type | string | | prevention |
action_result.data.\*.device_policies.prevention.settings_hash | string | | 87cb8b2e |
action_result.data.\*.device_policies.remote_response.applied | boolean | | True False |
action_result.data.\*.device_policies.remote_response.applied_date | string | | 2019-02-08T02:39:21.726331953Z |
action_result.data.\*.device_policies.remote_response.assigned_date | string | | 2019-02-08T02:36:05.073298048Z |
action_result.data.\*.device_policies.remote_response.policy_id | string | | 6c74313d6c864180bd759c3235dbd550 |
action_result.data.\*.device_policies.remote_response.policy_type | string | | remote-response |
action_result.data.\*.device_policies.remote_response.settings_hash | string | | f472bd8e |
action_result.data.\*.device_policies.sensor_update.applied | boolean | | True False |
action_result.data.\*.device_policies.sensor_update.applied_date | string | | 2023-01-10T23:39:59.53209856Z |
action_result.data.\*.device_policies.sensor_update.assigned_date | string | | 2018-03-10T15:39:31.220769757Z |
action_result.data.\*.device_policies.sensor_update.policy_id | string | `md5` | 62a3908297584c52bdafaa7fdf3c3bdd |
action_result.data.\*.device_policies.sensor_update.policy_type | string | | sensor-update |
action_result.data.\*.device_policies.sensor_update.settings_hash | string | | 65994753|3|2|automatic |
action_result.data.\*.device_policies.sensor_update.uninstall_protection | string | | ENABLED |
action_result.data.\*.external_ip | string | `ip` | 50.18.218.205 |
action_result.data.\*.first_seen | string | | 2018-03-10T15:38:09Z |
action_result.data.\*.group_hash | string | `sha256` | e2a8b394c0e62960747ff5d64a335162b36ba4c5a54ee6499b438b94e5269ae8 |
action_result.data.\*.groups | string | `md5` | 873560309d1b4686a6cee666575e7a93 |
action_result.data.\*.hostname | string | `host name` | TheNarrowSea CentOS70 |
action_result.data.\*.instance_id | string | | i-019d8b2cc8e20bb8d |
action_result.data.\*.kernel_version | string | | 10.0.19044.1766 |
action_result.data.\*.last_seen | string | | 2018-03-10T15:39:34Z |
action_result.data.\*.local_ip | string | `ip` | 10.1.18.49 |
action_result.data.\*.mac_address | string | | 00-0c-29-a0-10-27 |
action_result.data.\*.machine_domain | string | `domain` | VICTIMNET.local |
action_result.data.\*.major_version | string | | 6 |
action_result.data.\*.meta.version | string | | 6 |
action_result.data.\*.minor_version | string | | 1 |
action_result.data.\*.modified_timestamp | string | | 2018-03-10T15:40:09Z |
action_result.data.\*.os_build | string | | 19044 |
action_result.data.\*.os_version | string | | Windows Server 2008 R2 |
action_result.data.\*.ou | string | | |
action_result.data.\*.platform_id | string | | 0 |
action_result.data.\*.platform_name | string | | Windows |
action_result.data.\*.pointer_size | string | | 8 |
action_result.data.\*.policies.\*.applied | boolean | | True |
action_result.data.\*.policies.\*.applied_date | string | | 2021-12-02T07:35:26.551598833Z |
action_result.data.\*.policies.\*.assigned_date | string | | 2018-03-10T15:39:31.220730539Z |
action_result.data.\*.policies.\*.policy_id | string | `md5` | f81459e0d85b4bc7b3ad14ad40889042 |
action_result.data.\*.policies.\*.policy_type | string | | prevention |
action_result.data.\*.policies.\*.settings_hash | string | | 87cb8b2e |
action_result.data.\*.product_type | string | | 3 |
action_result.data.\*.product_type_desc | string | | Server |
action_result.data.\*.provision_status | string | | Provisioned |
action_result.data.\*.reduced_functionality_mode | string | | no |
action_result.data.\*.release_group | string | | |
action_result.data.\*.serial_number | string | | VMware-56 4d d8 11 42 ab 12 1a-b5 3d 4a e5 d1 a0 12 25 |
action_result.data.\*.service_pack_major | string | | 0 |
action_result.data.\*.service_pack_minor | string | | 0 |
action_result.data.\*.service_provider | string | | Test provider |
action_result.data.\*.service_provider_account_id | string | | 149665393462 |
action_result.data.\*.site_name | string | | Default-First-Site-Name |
action_result.data.\*.slow_changing_modified_timestamp | string | | 2018-04-23T22:52:27Z |
action_result.data.\*.status | string | | normal |
action_result.data.\*.system_manufacturer | string | | VMware, Inc. |
action_result.data.\*.system_product_name | string | | VMware Virtual Platform |
action_result.data.\*.zone_group | string | | us-east-1a |
action_result.summary.hostname | string | `host name` | TheNarrowSea |
action_result.message | string | | Device details fetched successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get process detail'

Retrieve the details of a process that is running or that previously ran, given a process ID

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**falcon_process_id** | required | Process ID from previous Falcon IOC search | string | `falcon process id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.falcon_process_id | string | `falcon process id` | pid:07c312fabcb8473454d0a16f118928fg:16716090292999 |
action_result.data.\*.command_line | string | | C: est est.exe |
action_result.data.\*.device_id | string | `crowdstrike device id` | 07c312fabcb8473454d0a16f118928fg |
action_result.data.\*.file_name | string | `file name` | estdata est est est.exe |
action_result.data.\*.process_id | string | `pid` | pid:07c312fabcb8473454d0a16f118928fg:16716090292999 |
action_result.data.\*.process_id_local | string | `pid` | 16716090292999 |
action_result.data.\*.start_timestamp | string | | 2020-02-14T01:41:11Z |
action_result.data.\*.start_timestamp_raw | string | | 132261180718697221 |
action_result.data.\*.stop_timestamp | string | | |
action_result.data.\*.stop_timestamp_raw | string | | |
action_result.summary | string | | |
action_result.message | string | | Process details fetched successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'hunt file'

Hunt for a file on the network by querying for the hash

Type: **investigate** \
Read only: **True**

In case of count_only set to true, keep the limit value larger to fetch count of all the devices.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** | required | File hash to search | string | `hash` `sha256` `sha1` `md5` |
**count_only** | optional | Get endpoint count only | boolean | |
**limit** | optional | Maximum device IDs to be fetched (defaults to 100) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.count_only | boolean | | True False |
action_result.parameter.hash | string | `hash` `sha256` `sha1` `md5` | eeb27d04c5fb25f7459407c0e5394621f12100e301b22d04a6b8f78e2adbf44t |
action_result.parameter.limit | numeric | | 100 |
action_result.data.\*.device_id | string | `crowdstrike device id` | 07c312fabcb8473454d0a16f118928fg |
action_result.summary.device_count | numeric | | 1 |
action_result.message | string | | Device count: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'hunt domain'

Get a list of device IDs on which the domain was matched

Type: **investigate** \
Read only: **True**

In case of count_only set to true, keep the limit value larger to fetch count of all the devices.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | Domain to search | string | `domain` |
**count_only** | optional | Get endpoint count only | boolean | |
**limit** | optional | Maximum device IDs to be fetched (defaults to 100) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.count_only | boolean | | True False |
action_result.parameter.domain | string | `domain` | www.example.com |
action_result.parameter.limit | numeric | | 100 |
action_result.data.\*.device_id | string | `crowdstrike device id` | 07c312fabcb8473454d0a16f118928fg |
action_result.summary.device_count | numeric | | 3 |
action_result.message | string | | Device count: 3 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'hunt ip'

Get a list of device IDs on which the ip was matched

Type: **investigate** \
Read only: **True**

In case of count_only set to true, keep the limit value larger to fetch count of all the devices.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP address to search | string | `ip` `ipv6` |
**count_only** | optional | Get endpoint count only | boolean | |
**limit** | optional | Maximum device IDs to be fetched (defaults to 100) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.count_only | boolean | | True False |
action_result.parameter.ip | string | `ip` `ipv6` | 8.8.8.8 2001:0db8:3c4d:0015:0000:0000:1a2f:1a2b |
action_result.parameter.limit | numeric | | 100 |
action_result.data.\*.device_id | string | `crowdstrike device id` | 07c312fabcb8473454d0a16f118928fg |
action_result.summary.device_count | numeric | | 1 |
action_result.message | string | | Device count: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'upload put file'

Upload a new put-file to use for the RTR `put` command

Type: **generic** \
Read only: **False**

This action requires a token with RTR Admin permissions.

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
action_result.status | string | | success failed |
action_result.parameter.comment | string | | Test comment |
action_result.parameter.description | string | | This is a test description |
action_result.parameter.file_name | string | `filename` | blank_file |
action_result.parameter.vault_id | string | `vault id` | 30c5e524e975816fbce1d958150e394efc219772 |
action_result.data.\*.meta.powered_by | string | | empower |
action_result.data.\*.meta.query_time | numeric | | 0.869312959 |
action_result.data.\*.meta.trace_id | string | | 1e30b813-04ce-4fa4-aca0-2802dfead2f9 |
action_result.data.\*.meta.writes.resources_affected | numeric | | 1 |
action_result.summary | string | | |
action_result.message | string | | Put file uploaded successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get indicator'

Get the full definition of one or more indicators that are being watched

Type: **investigate** \
Read only: **True**

In this action, either 'indicator_value' and 'indicator_type' or 'resource_id' should be provided. The priority of 'resource_id' is higher. If all the parameters are provided then the indicator will be fetched based on the 'resource_id'.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator_value** | optional | String representation of the indicator | string | `domain` `md5` `sha256` `ip` `ipv6` |
**indicator_type** | optional | The type of the indicator | string | `crowdstrike indicator type` |
**resource_id** | optional | The resource id of the indicator | string | `crowdstrike indicator id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.indicator_type | string | `crowdstrike indicator type` | domain |
action_result.parameter.indicator_value | string | `domain` `md5` `sha256` `ip` `ipv6` | xyz |
action_result.parameter.resource_id | string | `crowdstrike indicator id` | feaefb786fc648861779b9f906b1426b3d670ffe4c22ec7b7ff3d3e03e88dc43 |
action_result.data.\*.action | string | `crowdstrike indicator action` | none |
action_result.data.\*.applied_globally | boolean | | True False |
action_result.data.\*.created_by | string | | C16JJOUVVY125J3O50FF |
action_result.data.\*.created_on | string | `date` | 2021-09-09T08:51:04.131068458Z |
action_result.data.\*.created_timestamp | string | `date` | 2018-08-17T15:19:31Z |
action_result.data.\*.deleted | boolean | | True False |
action_result.data.\*.description | string | | test description |
action_result.data.\*.expiration | string | `date` | 2022-09-09T08:51:03Z |
action_result.data.\*.expiration_timestamp | string | `date` | 2018-09-16T00:00:00Z |
action_result.data.\*.expired | boolean | | True False |
action_result.data.\*.from_parent | boolean | | True False |
action_result.data.\*.host_groups.\* | string | `crowdstrike host group id` | 0491ecd214614b5ab3bca1037a15390b |
action_result.data.\*.id | string | `crowdstrike indicator id` | 99cd3772bf570aebea6e58059532ac902798583d6e75e6817364da70a062673a |
action_result.data.\*.metadata.av_hits | numeric | | -1 |
action_result.data.\*.metadata.company_name | string | | Carbon Black, Inc |
action_result.data.\*.metadata.file_description | string | | CarbonBlack Sensor |
action_result.data.\*.metadata.file_version | string | | 6.0.2.70329 |
action_result.data.\*.metadata.filename | string | | test_file_name |
action_result.data.\*.metadata.original_filename | string | | cb.exe |
action_result.data.\*.metadata.product_name | string | | CarbonBlack Sensor |
action_result.data.\*.metadata.product_version | string | | 6.0.2.70329 |
action_result.data.\*.metadata.signed | boolean | | False True |
action_result.data.\*.mobile_action | string | | no_action |
action_result.data.\*.modified_by | string | | ae2000074e144336ea1de4de9dc1bd39 |
action_result.data.\*.modified_on | string | | 2021-09-09T08:51:04.131068458Z |
action_result.data.\*.modified_timestamp | string | `date` | 2018-08-17T15:19:31Z |
action_result.data.\*.platforms.\* | string | `crowdstrike indicator platforms` | mac |
action_result.data.\*.severity | string | `severity` | medium |
action_result.data.\*.source | string | | test source |
action_result.data.\*.tags | string | | tag1 |
action_result.data.\*.type | string | `crowdstrike indicator type` | domain |
action_result.data.\*.value | string | `ip` `ipv6` `md5` `sha256` `domain` | xyz |
action_result.summary | string | | |
action_result.message | string | | Indicator fetched successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list custom indicators'

Queries for custom indicators in your customer account

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator_value** | optional | String representation of the indicator | string | `ip` `ipv6` `md5` `sha256` `domain` |
**indicator_type** | optional | The type of the indicator | string | `crowdstrike indicator type` |
**action** | optional | Enforcement policy | string | `crowdstrike indicator action` |
**source** | optional | The source of indicators | string | |
**from_expiration** | optional | The earliest indicator expiration date (RFC3339) | string | `date` |
**to_expiration** | optional | The latest indicator expiration date (RFC3339) | string | `date` |
**limit** | optional | The limit of indicator to be fetched (defaults to 100) | numeric | |
**sort** | optional | Property to sort by | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.action | string | `crowdstrike indicator action` | detect |
action_result.parameter.from_expiration | string | `date` | 2020-10-17T00:00:00Z |
action_result.parameter.indicator_type | string | `crowdstrike indicator type` | domain |
action_result.parameter.indicator_value | string | `ip` `ipv6` `md5` `sha256` `domain` | test |
action_result.parameter.limit | numeric | | 200 |
action_result.parameter.ph | string | | |
action_result.parameter.sort | string | | indicator_type |
action_result.parameter.source | string | | test |
action_result.parameter.to_expiration | string | `date` | 2020-10-17T00:00:00Z |
action_result.data.\*.domain | string | `domain` | |
action_result.data.\*.domain.\*.action | string | `crowdstrike indicator action` | no_action |
action_result.data.\*.domain.\*.applied_globally | boolean | | False |
action_result.data.\*.domain.\*.created_by | string | `md5` | ae1690074e144356ae2de5de8dc1bd93 |
action_result.data.\*.domain.\*.created_on | string | `date` | 2021-09-15T09:52:27.651770437Z |
action_result.data.\*.domain.\*.created_timestamp | string | `date` | 2018-08-17T15:19:31Z |
action_result.data.\*.domain.\*.deleted | boolean | | False |
action_result.data.\*.domain.\*.description | string | | Test description |
action_result.data.\*.domain.\*.expiration | string | `date` | 2021-09-25T09:52:27Z |
action_result.data.\*.domain.\*.expiration_timestamp | string | `date` | 2018-09-16T00:00:00Z |
action_result.data.\*.domain.\*.expired | boolean | | False |
action_result.data.\*.domain.\*.from_parent | boolean | | False |
action_result.data.\*.domain.\*.host_groups.\* | string | `crowdstrike host group id` | 0491ecd214614b5ab3bca1037a15390b |
action_result.data.\*.domain.\*.id | string | `crowdstrike indicator id` | 010114a181ac68f8712b28c288fc210e26c3d25029f3d1edeeb6b37c67293abb |
action_result.data.\*.domain.\*.metadata.filename | string | | EXAMPLEMETADATAvftcdrxcftvgybhhubsdgvfyuegwwiqeqTESTuifgwieugfhiugybhugvftcdrxcftvgbhubsdgvfyuegwwiqeqpdiheuifgEXAMPLE |
action_result.data.\*.domain.\*.mobile_action | string | | no_action |
action_result.data.\*.domain.\*.modified_by | string | `md5` | ae1690074e144356ae2de5de8dc1bd93 |
action_result.data.\*.domain.\*.modified_on | string | | 2021-09-15T09:52:27.651770437Z |
action_result.data.\*.domain.\*.modified_timestamp | string | `date` | 2018-08-17T15:19:31Z |
action_result.data.\*.domain.\*.platforms.\* | string | `crowdstrike indicator platforms` | mac |
action_result.data.\*.domain.\*.severity | string | `severity` | high |
action_result.data.\*.domain.\*.source | string | | Test source |
action_result.data.\*.domain.\*.tags | string | | test_tag |
action_result.data.\*.domain.\*.type | string | `crowdstrike indicator type` | domain |
action_result.data.\*.domain.\*.value | string | `domain` | test.domain |
action_result.data.\*.ipv4 | string | `ip` | |
action_result.data.\*.ipv4.\*.action | string | `crowdstrike indicator action` | no_action |
action_result.data.\*.ipv4.\*.applied_globally | boolean | | False |
action_result.data.\*.ipv4.\*.created_by | string | `md5` | ae1690074e144356ae2de5de8dc1bd93 |
action_result.data.\*.ipv4.\*.created_on | string | `date` | 2021-09-15T09:52:27.651770437Z |
action_result.data.\*.ipv4.\*.created_timestamp | string | `date` | 2018-08-17T15:19:31Z |
action_result.data.\*.ipv4.\*.deleted | boolean | | False |
action_result.data.\*.ipv4.\*.description | string | | Test description |
action_result.data.\*.ipv4.\*.expiration | string | `date` | 2021-09-25T09:52:27Z |
action_result.data.\*.ipv4.\*.expiration_timestamp | string | `date` | 2018-09-16T00:00:00Z |
action_result.data.\*.ipv4.\*.expired | boolean | | False |
action_result.data.\*.ipv4.\*.from_parent | boolean | | False |
action_result.data.\*.ipv4.\*.host_groups.\* | string | `crowdstrike host group id` | 0491ecd214614b5ab3bca1037a15390b |
action_result.data.\*.ipv4.\*.id | string | `crowdstrike indicator id` | 010114a181ac68f8712b28c288fc210e26c3d25029f3d1edeeb6b37c67293abb |
action_result.data.\*.ipv4.\*.metadata.filename | string | | test |
action_result.data.\*.ipv4.\*.mobile_action | string | | no_action |
action_result.data.\*.ipv4.\*.modified_by | string | `md5` | ae1690074e144356ae2de5de8dc1bd93 |
action_result.data.\*.ipv4.\*.modified_on | string | | 2021-09-15T09:52:27.651770437Z |
action_result.data.\*.ipv4.\*.modified_timestamp | string | `date` | 2018-08-17T15:19:31Z |
action_result.data.\*.ipv4.\*.platforms.\* | string | `crowdstrike indicator platforms` | mac |
action_result.data.\*.ipv4.\*.severity | string | `severity` | high |
action_result.data.\*.ipv4.\*.source | string | | Test source |
action_result.data.\*.ipv4.\*.tags | string | | test_tag |
action_result.data.\*.ipv4.\*.type | string | `crowdstrike indicator type` | ipv4 |
action_result.data.\*.ipv4.\*.value | string | `ip` | 8.8.8.8 |
action_result.data.\*.ipv6 | string | `ipv6` | |
action_result.data.\*.ipv6.\*.action | string | `crowdstrike indicator action` | no_action |
action_result.data.\*.ipv6.\*.applied_globally | boolean | | False |
action_result.data.\*.ipv6.\*.created_by | string | `md5` | ae1690074e144356ae2de5de8dc1bd93 |
action_result.data.\*.ipv6.\*.created_on | string | `date` | 2021-09-15T09:52:27.651770437Z |
action_result.data.\*.ipv6.\*.created_timestamp | string | `date` | 2018-08-17T15:19:31Z |
action_result.data.\*.ipv6.\*.deleted | boolean | | False |
action_result.data.\*.ipv6.\*.description | string | | Test description |
action_result.data.\*.ipv6.\*.expiration | string | `date` | 2021-09-25T09:52:27Z |
action_result.data.\*.ipv6.\*.expiration_timestamp | string | `date` | 2018-09-16T00:00:00Z |
action_result.data.\*.ipv6.\*.expired | boolean | | False |
action_result.data.\*.ipv6.\*.from_parent | boolean | | False |
action_result.data.\*.ipv6.\*.host_groups.\* | string | `crowdstrike host group id` | 0491ecd214614b5ab3bca1037a15390b |
action_result.data.\*.ipv6.\*.id | string | `crowdstrike indicator id` | 010114a181ac68f8712b28c288fc210e26c3d25029f3d1edeeb6b37c67293abb |
action_result.data.\*.ipv6.\*.metadata.filename | string | | test_file_name |
action_result.data.\*.ipv6.\*.modified_by | string | `md5` | ae1690074e144356ae2de5de8dc1bd93 |
action_result.data.\*.ipv6.\*.modified_on | string | | 2021-09-15T09:52:27.651770437Z |
action_result.data.\*.ipv6.\*.modified_timestamp | string | `date` | 2018-08-17T15:19:31Z |
action_result.data.\*.ipv6.\*.platforms.\* | string | `crowdstrike indicator platforms` | mac |
action_result.data.\*.ipv6.\*.severity | string | `severity` | high |
action_result.data.\*.ipv6.\*.source | string | | Test source |
action_result.data.\*.ipv6.\*.tags | string | | test_tag |
action_result.data.\*.ipv6.\*.type | string | `crowdstrike indicator type` | ipv6 |
action_result.data.\*.ipv6.\*.value | string | `ipv6` | 2001:db8:3333::6666:7777:8888 |
action_result.data.\*.md5 | string | `md5` | |
action_result.data.\*.md5.\*.action | string | `crowdstrike indicator action` | no_action |
action_result.data.\*.md5.\*.applied_globally | boolean | | False |
action_result.data.\*.md5.\*.created_by | string | `md5` | ae1690074e144356ae2de5de8dc1bd93 |
action_result.data.\*.md5.\*.created_on | string | `date` | 2021-09-15T09:52:27.651770437Z |
action_result.data.\*.md5.\*.created_timestamp | string | `date` | 2018-08-17T15:19:31Z |
action_result.data.\*.md5.\*.deleted | boolean | | False |
action_result.data.\*.md5.\*.description | string | | Test description |
action_result.data.\*.md5.\*.expiration | string | `date` | 2021-09-25T09:52:27Z |
action_result.data.\*.md5.\*.expiration_timestamp | string | `date` | 2018-09-16T00:00:00Z |
action_result.data.\*.md5.\*.expired | boolean | | False |
action_result.data.\*.md5.\*.from_parent | boolean | | False |
action_result.data.\*.md5.\*.host_groups.\* | string | `crowdstrike host group id` | 0491ecd214614b5ab3bca1037a15390b |
action_result.data.\*.md5.\*.id | string | `crowdstrike indicator id` | 010114a181ac68f8712b28c288fc210e26c3d25029f3d1edeeb6b37c67293abb |
action_result.data.\*.md5.\*.metadata.av_hits | numeric | | -1 |
action_result.data.\*.md5.\*.metadata.filename | string | | test_file_name |
action_result.data.\*.md5.\*.metadata.signed | boolean | | False True |
action_result.data.\*.md5.\*.mobile_action | string | | no_action |
action_result.data.\*.md5.\*.modified_by | string | `md5` | ae1690074e144356ae2de5de8dc1bd93 |
action_result.data.\*.md5.\*.modified_on | string | | 2021-09-15T09:52:27.651770437Z |
action_result.data.\*.md5.\*.modified_timestamp | string | `date` | 2018-08-17T15:19:31Z |
action_result.data.\*.md5.\*.platforms.\* | string | `crowdstrike indicator platforms` | mac |
action_result.data.\*.md5.\*.severity | string | `severity` | high |
action_result.data.\*.md5.\*.source | string | | Test source |
action_result.data.\*.md5.\*.tags | string | | test_tag |
action_result.data.\*.md5.\*.type | string | `crowdstrike indicator type` | md5 |
action_result.data.\*.md5.\*.value | string | `md5` | 098f6bcd4621d373cade4e832627b4f6 |
action_result.data.\*.sha256 | string | `sha256` | |
action_result.data.\*.sha256.\*.action | string | `crowdstrike indicator action` | no_action |
action_result.data.\*.sha256.\*.applied_globally | boolean | | False |
action_result.data.\*.sha256.\*.created_by | string | `md5` | ae1690074e144356ae2de5de8dc1bd93 |
action_result.data.\*.sha256.\*.created_on | string | `date` | 2021-09-15T09:52:27.651770437Z |
action_result.data.\*.sha256.\*.created_timestamp | string | `date` | 2018-08-17T15:19:31Z |
action_result.data.\*.sha256.\*.deleted | boolean | | False |
action_result.data.\*.sha256.\*.description | string | | Test description |
action_result.data.\*.sha256.\*.expiration | string | `date` | 2021-09-25T09:52:27Z |
action_result.data.\*.sha256.\*.expiration_timestamp | string | `date` | 2018-09-16T00:00:00Z |
action_result.data.\*.sha256.\*.expired | boolean | | False |
action_result.data.\*.sha256.\*.from_parent | boolean | | False |
action_result.data.\*.sha256.\*.host_groups.\* | string | `crowdstrike host group id` | 0491ecd214614b5ab3bca1037a15390b |
action_result.data.\*.sha256.\*.id | string | `crowdstrike indicator id` | 010114a181ac68f8712b28c288fc210e26c3d25029f3d1edeeb6b37c67293abb |
action_result.data.\*.sha256.\*.metadata.av_hits | numeric | | -1 |
action_result.data.\*.sha256.\*.metadata.company_name | string | | Test Corporation |
action_result.data.\*.sha256.\*.metadata.file_description | string | | Runtime Broker |
action_result.data.\*.sha256.\*.metadata.file_version | string | | 10.0.19041.746 (WinBuild.160101.0800) |
action_result.data.\*.sha256.\*.metadata.filename | string | | test_file_name |
action_result.data.\*.sha256.\*.metadata.original_filename | string | | RuntimeBroker.exe |
action_result.data.\*.sha256.\*.metadata.product_name | string | | Test® Windows® Operating System |
action_result.data.\*.sha256.\*.metadata.product_version | string | | 10.0.19041.746 |
action_result.data.\*.sha256.\*.metadata.signed | boolean | | False True |
action_result.data.\*.sha256.\*.mobile_action | string | | no_action |
action_result.data.\*.sha256.\*.modified_by | string | `md5` | ae1690074e144356ae2de5de8dc1bd93 |
action_result.data.\*.sha256.\*.modified_on | string | | 2021-09-15T09:52:27.651770437Z |
action_result.data.\*.sha256.\*.modified_timestamp | string | `date` | 2018-08-17T15:19:31Z |
action_result.data.\*.sha256.\*.platforms.\* | string | `crowdstrike indicator platforms` | mac |
action_result.data.\*.sha256.\*.severity | string | `severity` | high |
action_result.data.\*.sha256.\*.source | string | | Test source |
action_result.data.\*.sha256.\*.tags | string | | test_tag |
action_result.data.\*.sha256.\*.type | string | `crowdstrike indicator type` | sha256 |
action_result.data.\*.sha256.\*.value | string | `sha256` | 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 |
action_result.summary.alerts_found | numeric | | |
action_result.summary.total_domain | numeric | | |
action_result.summary.total_ipv4 | numeric | | |
action_result.summary.total_ipv6 | numeric | | |
action_result.summary.total_md5 | numeric | | |
action_result.summary.total_sha256 | numeric | | |
action_result.message | string | | Total ip: 20, Total domain: 26, Total sha1: 0, Total md5: 0, Total sha256: 1, Alerts found: 47 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list put files'

Queries for files uploaded to Crowdstrike for use with the RTR `put` command

Type: **investigate** \
Read only: **True**

For additional information on FQL syntax see: https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** | optional | FQL query to filter results | string | |
**offset** | optional | Starting index of overall result set | string | |
**limit** | optional | Number of files to return | numeric | |
**sort** | optional | Sort results | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.filter | string | | size: 292 |
action_result.parameter.limit | numeric | | 50 |
action_result.parameter.offset | string | | 10 |
action_result.parameter.sort | string | | size|asc |
action_result.data.\*.comments_for_audit_log | string | | test |
action_result.data.\*.created_by | string | | api-client-05dbdf165b474db597007c6f88780e39 |
action_result.data.\*.created_by_uuid | string | | 05dbdf16-5b47-4db5-9700-7c6f88780e39 |
action_result.data.\*.created_timestamp | string | | 2020-01-17T19:54:47.929163017Z |
action_result.data.\*.description | string | | This is a test description |
action_result.data.\*.file_type | string | | binary |
action_result.data.\*.id | string | | 37420b00396311eaa57e0662caec3daa_05dbdf165b474db597007c6f88780e39 |
action_result.data.\*.modified_by | string | | api-client-05d12ffasd65d12b597007c6f88780e39 |
action_result.data.\*.modified_timestamp | string | | 2020-01-17T19:54:47.929163507Z |
action_result.data.\*.name | string | | blank_file |
action_result.data.\*.permission_type | string | | none |
action_result.data.\*.run_attempt_count | numeric | | 0 |
action_result.data.\*.run_success_count | numeric | | 0 |
action_result.data.\*.sha256 | string | `sha256` | 9a9eaa1e83dbb19252ae1c0158eeefe8e4ce78736535d4e6d6a6bb5b039ff9a2 |
action_result.data.\*.size | numeric | | 88 |
action_result.summary.total_files | numeric | | 2 |
action_result.message | string | | Total files: 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'on poll'

Callback action for the on_poll ingest functionality

Type: **ingest** \
Read only: **True**

This action remembers the last event ID that was queried for. The next ingestion carried out will query for later event IDs. This way, the same events are not queried for in every run. However, in the case of 'POLL NOW' queried event IDs will not be remembered.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Parameter ignored in this app | numeric | |
**end_time** | optional | Parameter ignored in this app | numeric | |
**container_count** | optional | Parameter ignored in this app | numeric | |
**artifact_count** | optional | Parameter ignored in this app | numeric | |

#### Action Output

No Output

## action: 'list processes'

List processes that have recently used the IOC on a particular device

Type: **investigate** \
Read only: **True**

Given a file hash or domain, the action will list all the processes that have either recently connected to the domain or interacted with the file that matches the supplied hash. Use the <b>query device</b> actions to get the device id to run the action on.In case of count_only set to true, keep the limit value larger to fetch count of all the devices.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** | required | File Hash or Domain to use for searching | string | `hash` `sha256` `sha1` `md5` `domain` |
**id** | required | Crowdstrike Device ID to search on | string | `crowdstrike device id` |
**limit** | optional | Maximum processes to be fetched (defaults to 100) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.id | string | `crowdstrike device id` | 07c312fabcb8473454d0a16f118928ab |
action_result.parameter.ioc | string | `hash` `sha256` `sha1` `md5` `domain` | eeb27d04c5fb25f7459407c0e5394621f12100e301b22d04a6b8f78e2adbf33d |
action_result.parameter.limit | numeric | | 100 |
action_result.data.\*.falcon_process_id | string | `falcon process id` | pid:07c312fabcb8473454d0a16f118928fg:16716090292999 |
action_result.summary.process_count | numeric | | 1 |
action_result.message | string | | Process count: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'upload indicator'

Upload indicator that you want CrowdStrike to watch

Type: **contain** \
Read only: **False**

Valid values for the <b>action</b> parameter are:<ul><li>no_action<br> Save the indicator for future use, but take no action. No severity required.</li><li>allow<br> Applies to hashes only. Allow the indicator and do not detect it. Severity does not apply and should not be provided.</li><li>prevent_no_ui<br> Applies to hashes only. Block and detect the indicator, but hide it from <b>Activity > Detections</b>. Has a default severity value.</li><li>prevent<br> Applies to hashes only. Block the indicator and show it as a detection at the selected severity.</li><li>detect<br> Enable detections for the indicator at the selected severity.</li></ul>Valid values for the <b>host groups</b> parameter are:<ul><li>Comma separated host group IDs for specific groups</li><li>Leave it blank for all the host groups</li></ul>The <b>platforms</b> parameter is the list of platforms that the indicator applies to. You can enter multiple platform names, separated by commas. Valid values are: <b>mac, windows, and linux</b>.<br>The CrowdStrike API accepts the standard timestamp format in the <b>expiration</b> parameter. In this action, the number of days provided in the <b>expiration</b> parameter is internally converted into the timestamp format to match the API format.<br>If the indicator with the same type and value is created again, the action will fail as duplicate type-value combination is not allowed.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** | required | Input domain, ip, or hash ioc | string | `sha256` `md5` `domain` `ip` `ipv6` |
**action** | required | Action to take when a host observes the custom IOC | string | `crowdstrike indicator action` |
**platforms** | required | Comma separated list of platforms | string | `crowdstrike indicator platforms` |
**expiration** | optional | Alert lifetime in days | numeric | |
**source** | optional | Indicator originating source | string | |
**description** | optional | Indicator description | string | |
**tags** | optional | Comma separated list of tags | string | |
**severity** | optional | Severity level | string | `severity` |
**host_groups** | optional | Comma separated list of host group IDs | string | `crowdstrike host group id` |
**filename** | optional | Metadata filename | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.action | string | `crowdstrike indicator action` | detect |
action_result.parameter.description | string | | test description |
action_result.parameter.expiration | numeric | | 10 |
action_result.parameter.filename | string | | filename |
action_result.parameter.host_groups | string | `crowdstrike host group id` | 7f0d05b7b2fd4ddfb34069ab6e99db34 |
action_result.parameter.ioc | string | `sha256` `md5` `domain` `ip` `ipv6` | 8.8.8.8 |
action_result.parameter.platforms | string | `crowdstrike indicator platforms` | linux |
action_result.parameter.severity | string | `severity` | low |
action_result.parameter.source | string | | test source |
action_result.parameter.tags | string | | test_tag |
action_result.data.\*.action | string | `crowdstrike indicator action` | no_action |
action_result.data.\*.applied_globally | boolean | | False |
action_result.data.\*.created_by | string | `md5` | ae1690074e144356ae2de5de8dc1bd93 |
action_result.data.\*.created_on | string | `date` | 2021-09-15T09:52:27.651770437Z |
action_result.data.\*.created_timestamp | string | `date` | 2018-08-17T15:19:31Z |
action_result.data.\*.deleted | boolean | | False |
action_result.data.\*.description | string | | Test description |
action_result.data.\*.expiration | string | `date` | 2021-09-25T09:52:27Z |
action_result.data.\*.expiration_timestamp | string | `date` | 2018-09-16T00:00:00Z |
action_result.data.\*.expired | boolean | | False |
action_result.data.\*.from_parent | boolean | | False |
action_result.data.\*.host_groups.\* | string | `crowdstrike host group id` | 0491ecd214614b5ab3bca1037a15390b |
action_result.data.\*.id | string | `crowdstrike indicator id` | 010114a181ac68f8712b28c288fc210e26c3d25029f3d1edeeb6b37c67293abb |
action_result.data.\*.metadata.av_hits | numeric | | -1 |
action_result.data.\*.metadata.filename | string | | test_file_name |
action_result.data.\*.metadata.signed | boolean | | False True |
action_result.data.\*.modified_by | string | `md5` | ae1690074e144356ae2de5de8dc1bd93 |
action_result.data.\*.modified_on | string | | 2021-09-15T09:52:27.651770437Z |
action_result.data.\*.modified_timestamp | string | `date` | 2018-08-17T15:19:31Z |
action_result.data.\*.platforms.\* | string | `crowdstrike indicator platforms` | mac |
action_result.data.\*.severity | string | `severity` | high |
action_result.data.\*.source | string | | Test source |
action_result.data.\*.tags | string | | test_tag |
action_result.data.\*.type | string | `crowdstrike indicator type` | ipv4 |
action_result.data.\*.value | string | `ip` `ipv6` `md5` `sha256` `domain` | 8.8.8.8 |
action_result.summary | string | | |
action_result.message | string | | Indicator uploaded successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'delete indicator'

Delete an indicator that is being watched

Type: **correct** \
Read only: **False**

In this action, either 'ioc' or 'resource_id' should be provided. The priority of 'resource_id' is higher. If both the parameters are provided then the indicator will be deleted based on the 'resource_id'. The CrowdStrike API returns success for the 'resource_id' of the already deleted indicator.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** | optional | Hash, ip or domain IOC from previous upload | string | `ip` `ipv6` `md5` `sha256` `domain` |
**resource_id** | optional | The resource id of the indicator | string | `crowdstrike indicator id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ioc | string | `ip` `ipv6` `md5` `sha256` `domain` | test |
action_result.parameter.resource_id | string | `crowdstrike indicator id` | feaefb786fc648861779b9f906b1426b3d670ffe4c22ec7b7ff3d3e03e88dc43 |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | Indicator deleted successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update indicator'

Update an indicator that has been uploaded

Type: **generic** \
Read only: **False**

Valid values for the <b>host groups</b> parameter are:<ul><li>Comma separated host group IDs for specific groups</li><li>The value '<b>all</b>' for all the host groups</li><li>Leave it blank if there is no change</li></ul>If no parameters are provided as input, the action would pass successfully.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** | required | Hash, ip or domain IOC to update | string | `ip` `md5` `sha256` `domain` |
**action** | optional | Action to take when a host observes the custom IOC | string | `crowdstrike indicator action` |
**platforms** | optional | Comma separated list of platforms | string | `crowdstrike indicator platforms` |
**expiration** | optional | Alert lifetime in days | numeric | |
**source** | optional | Indicator originating source | string | |
**description** | optional | Indicator description | string | |
**tags** | optional | Comma separated list of tags | string | |
**severity** | optional | Severity level | string | `severity` |
**host_groups** | optional | Comma separated list of host group IDs | string | `crowdstrike host group id` |
**filename** | optional | Metadata filename | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.action | string | `crowdstrike indicator action` | detect |
action_result.parameter.description | string | | test description |
action_result.parameter.expiration | numeric | | 10 |
action_result.parameter.filename | string | | filename |
action_result.parameter.host_groups | string | `crowdstrike host group id` | 7f0d05b7b2fd4ddfb34069ab6e99db34 |
action_result.parameter.ioc | string | `ip` `md5` `sha256` `domain` | 8.8.8.8 |
action_result.parameter.platforms | string | `crowdstrike indicator platforms` | linux |
action_result.parameter.severity | string | `severity` | low |
action_result.parameter.source | string | | test source |
action_result.parameter.tags | string | | test_tag |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | Indicator updated successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'file reputation'

Queries CrowdStrike for the file info given a vault ID or a SHA256 hash, vault ID has higher priority than SHA256 hash if both are provided

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | optional | Vault ID of file | string | `vault id` |
**sha256** | optional | SHA256 hash of the file | string | `sha256` |
**limit** | optional | Maximum reports to be fetched | numeric | |
**sort** | optional | Property to sort by | string | |
**offset** | optional | Starting index of overall result set from which to return ids (defaults to 0) | numeric | |
**detail_report** | optional | Get the detailed report | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.detail_report | boolean | | True False |
action_result.parameter.limit | numeric | | 120 |
action_result.parameter.offset | numeric | | 100 |
action_result.parameter.sha256 | string | `sha256` | 3460eb8087523e19ac486f37fc68192c2dcd087814a2a9c9ad6b668fee3e0134 |
action_result.parameter.sort | string | | created_timestamp.asc |
action_result.parameter.vault_id | string | `vault id` | 30c5e524e975816fbce1d958150e394efc219772 |
action_result.data.\*.cid | string | | 3061c7ff3b634e22b38274d4b586558e |
action_result.data.\*.created_timestamp | string | | 2020-10-26T09:26:12Z |
action_result.data.\*.id | string | `crowdstrike resource id` | 3061c7ff3b634e22b38274d4b586558e_5cbc78f5cd4845fd8652896dde973397 |
action_result.data.\*.ioc_report_broad_csv_artifact_id | string | `crowdstrike artifact id` | b735c285c7d4119254d7a4eac9734321cf2dee0a8925f0395df6592cce97f848 |
action_result.data.\*.ioc_report_broad_json_artifact_id | string | `crowdstrike artifact id` | c4a90ac33e499f69fbccf4ca20cd8938a0e3a10055eececfefa99000a475dd7a |
action_result.data.\*.ioc_report_broad_maec_artifact_id | string | `crowdstrike artifact id` | 5a9703fb4d31b4fab70948332af17711b41d06f2fe46406f8abcd810eea8ca2b |
action_result.data.\*.ioc_report_broad_stix_artifact_id | string | `crowdstrike artifact id` | 2433d561ad70b9a30753bc3345bf1d9e986340e40dc59177f91e979d59b4f0f0 |
action_result.data.\*.ioc_report_strict_csv_artifact_id | string | `crowdstrike artifact id` | f54d63e91cafc2aa131d90bab6a60d7dfd0db05f984ebcf9394e4a1d7934c913 |
action_result.data.\*.ioc_report_strict_json_artifact_id | string | `crowdstrike artifact id` | 7d80482e25d2e86867ea6b4b8c0bc9c1235f9e70dbd2a1754ffb86c950994532 |
action_result.data.\*.ioc_report_strict_maec_artifact_id | string | `crowdstrike artifact id` | bf73276e6e07f6c02a242254e846f4ef8e6d12a3114ee8de0e144ee608491457 |
action_result.data.\*.ioc_report_strict_stix_artifact_id | string | `crowdstrike artifact id` | 1f129239876f7eb8287bf112763dada414ee8792ce1ab81eda6adcf322327696 |
action_result.data.\*.malquery.\*.input | string | | c619f87556667f2c1799672d36d55172597f4fed158800d5622edc8abee930e8 |
action_result.data.\*.malquery.\*.resources.\*.file_size | numeric | | 100144 |
action_result.data.\*.malquery.\*.resources.\*.file_type | string | | PE32 |
action_result.data.\*.malquery.\*.resources.\*.first_seen_timestamp | string | | 2020-01-29T00:00:00Z |
action_result.data.\*.malquery.\*.resources.\*.label | string | | clean |
action_result.data.\*.malquery.\*.resources.\*.md5 | string | `md5` | b029f63374652c76e09b6443dd931774 |
action_result.data.\*.malquery.\*.resources.\*.sha1 | string | `sha1` | 8b50322f86d4bd5a7a5bc1d54d16ecfae8d4e693 |
action_result.data.\*.malquery.\*.resources.\*.sha256 | string | `sha256` | 7b982b66433e1c89d094461d3d461eab90c93f72fbe676fcfc17c3c340c9a8b4 |
action_result.data.\*.malquery.\*.type | string | | sha256 |
action_result.data.\*.malquery.\*.verdict | string | | clean |
action_result.data.\*.origin | string | | quarantine |
action_result.data.\*.sandbox.\*.architecture | string | | 32 Bit |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.address | string | `ip` | 1XX.2XX.1X.6X |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.associated_runtime.\*.name | string | | iexplore.exe |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.associated_runtime.\*.pid | numeric | | 7284 |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.country | string | | Test Name |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.port | numeric | `port` | 80 |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.protocol | string | | TCP |
action_result.data.\*.sandbox.\*.dns_requests.\*.address | string | `ip` | 2X.7X.1XX.1XX |
action_result.data.\*.sandbox.\*.dns_requests.\*.country | string | | Test Name |
action_result.data.\*.sandbox.\*.dns_requests.\*.domain | string | `domain` `ip` | clientconfig.passport.net |
action_result.data.\*.sandbox.\*.dns_requests.\*.registrar_creation_timestamp | string | `date` | 1994-08-01T00:00:00+00:00 |
action_result.data.\*.sandbox.\*.dns_requests.\*.registrar_name | string | | MarkMonitor, Inc. |
action_result.data.\*.sandbox.\*.dns_requests.\*.registrar_name_servers | string | | NS1.MSFT.NET |
action_result.data.\*.sandbox.\*.dns_requests.\*.registrar_organization | string | | Test Corporation |
action_result.data.\*.sandbox.\*.environment | numeric | | 100 |
action_result.data.\*.sandbox.\*.environment_description | string | `crowdstrike environment` | Windows 7 32 bit |
action_result.data.\*.sandbox.\*.environment_id | numeric | | 100 |
action_result.data.\*.sandbox.\*.error_message | string | | The requested environment ID "160" and file type "python" have no available execution environment |
action_result.data.\*.sandbox.\*.error_origin | string | | CLIENT |
action_result.data.\*.sandbox.\*.error_type | string | | FILE_TYPE_BAD_ERROR |
action_result.data.\*.sandbox.\*.exact_deep_hash | string | | 026f0c002c06028e00010212000320000000fffffe06030065732078000000e0161f3a9d4755494400ffff0000e804000100e000ff0000b800c900c06f110b7b00706f0e00040d01000000120200e20033303331ffff00000011030400050001000a6f106765745f000000122c06028e0000ffff00ffff00f002a90009000000800000001109142000ffff000a280100088e69fe00ffff000bfe060750000080ffff00000080000000f002a900e000000000000007000000000011000000e80400e80400006f705f0100010000120000561934e00f1a1f6fdf007100100102150000ff2510000000302e302ee80400002e302e30000200e220696e20cf0072370106002affff0000007200460001130f49ae61f1616773000043756c7065730000e8010004effe000070007900f701b700020080fe01130e00ffff00000000000031000b720073001d08050501060a0200ffff0000ff25007e0000ec0011004366006f00446f6d6101130d114d01048000012805012571180100000165006f7003090151fe0000010000a040fe010d010000de00020e0e0300000001029f008100efbbbf002b8c1600f701b78e69fe040a110bfe666f2078150c20050000002b0000ffff006c006100008000110020f400fe010d6f6e732e00e804006be57549ffff00001e01060ade0000000100953b31007400091afe0420001d120000e000 |
action_result.data.\*.sandbox.\*.extracted_files.\*.description | string | | PE32 executable (DLL) (GUI) Intel 80386, for MS Windows |
action_result.data.\*.sandbox.\*.extracted_files.\*.file_path | string | | %TEMP%\\329babfa-d618-4d17-a6b0-79fe02a2d94d\\AgileDotNetRT.dll |
action_result.data.\*.sandbox.\*.extracted_files.\*.file_size | numeric | | 137741 |
action_result.data.\*.sandbox.\*.extracted_files.\*.md5 | string | `md5` | 5ce220e1334193b403e937ecca0b406f |
action_result.data.\*.sandbox.\*.extracted_files.\*.name | string | | AgileDotNetRT.dll |
action_result.data.\*.sandbox.\*.extracted_files.\*.runtime_process | string | | 789356c7d6964b9b4b3d38ecadea3b1570893275013cabbd008900a32c2afd24.exe |
action_result.data.\*.sandbox.\*.extracted_files.\*.sha1 | string | `sha1` | 48c1d47e4a23ebfd739aa86830842d1ead7ced59 |
action_result.data.\*.sandbox.\*.extracted_files.\*.sha256 | string | `sha256` | c619f87556667f2c1799672d36d55172597f4fed158800d5622edc8abee930e8 |
action_result.data.\*.sandbox.\*.extracted_files.\*.threat_level_readable | string | | no specific threat |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.filename | string | | EXAMPLEd6964b9b4b3d38ecadea3b1570893275013cabbd008900a32c2aTEST.bin |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.process | string | | EXAMPLEd6964b9b4b3d38ecadea3b1570893275013cabbd008900a32c2aTEST.exe |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.source | string | | Memory/File Scan |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.type | string | | Ansi |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.value | string | | .http://www.digicert.com/ssl-cps-repository.htm0 |
action_result.data.\*.sandbox.\*.file_imports.\*.module | string | | mscoree.dll |
action_result.data.\*.sandbox.\*.file_size | numeric | | 224888 |
action_result.data.\*.sandbox.\*.file_type | string | | PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows |
action_result.data.\*.sandbox.\*.http_requests.\*.header | string | | GET /gsr2/TESTgwRjAJBgUrDgMCTESTBBTgXIsxbvr2lBkPpoIEVRE6gHlCnAQUm%2BIHV2ccHsBqBt5ZtEXAMPLEhi4CDQHjtJqhjYqpgSVpULg%3D HTTP/1.1<br>Connection: Keep-Alive<br>Accept: \*/\*<br>User-Agent: Test-CryptoAPI/10.0<br>Host: ocsp.pki.goog |
action_result.data.\*.sandbox.\*.http_requests.\*.host | string | `domain` `ip` | ocsp.pki.goog |
action_result.data.\*.sandbox.\*.http_requests.\*.host_ip | string | `ip` | 1XX.2XX.1X.6X |
action_result.data.\*.sandbox.\*.http_requests.\*.host_port | numeric | `port` | 80 |
action_result.data.\*.sandbox.\*.http_requests.\*.method | string | | GET |
action_result.data.\*.sandbox.\*.http_requests.\*.url | string | | /gsr2/ME4wTDBKMEgwRjAJBgUrDgMCGgUABBTgXIsxbvr2lBkPpoIEVRE6gHlCnAQUm%2BIHV2ccHsBqBt5ZtJot39wZhi4CDQHjtJqhjYqpgSVpULg%3D |
action_result.data.\*.sandbox.\*.incidents.\*.name | string | | Fingerprint |
action_result.data.\*.sandbox.\*.memory_strings_artifact_id | string | `crowdstrike artifact id` | 9e5ebb7847a684fe6b9f36bb6bfb36e03b4e2f71b010c67e131652b968695a30 |
action_result.data.\*.sandbox.\*.mitre_attacks.\*.attack_id | string | | T1215 |
action_result.data.\*.sandbox.\*.mitre_attacks.\*.parent.attack_id | string | | T1027 |
action_result.data.\*.sandbox.\*.mitre_attacks.\*.parent.attack_id_wiki | string | | https://attack.mitre.org/techniques/T1027 |
action_result.data.\*.sandbox.\*.mitre_attacks.\*.parent.technique | string | | Obfuscated Files or Information |
action_result.data.\*.sandbox.\*.mitre_attacks.\*.tactic | string | | Persistence |
action_result.data.\*.sandbox.\*.mitre_attacks.\*.technique | string | | Kernel Modules and Extensions |
action_result.data.\*.sandbox.\*.network_settings | string | | default |
action_result.data.\*.sandbox.\*.packer | string | | Test visual C# v7.0 / Basic .NET |
action_result.data.\*.sandbox.\*.pcap_report_artifact_id | string | `crowdstrike artifact id` | e5521d8c988e4fd8f4bff8d90e231ac71d5bde9710382a1a2ac14e9d004eabd8 |
action_result.data.\*.sandbox.\*.processes.\*.command_line | string | | "C:\\dummy-pdf_2.pdf" |
action_result.data.\*.sandbox.\*.processes.\*.file_accesses.\*.mask | string | | FILE_READ_DATA | FILE_EXECUTE |
action_result.data.\*.sandbox.\*.processes.\*.file_accesses.\*.path | string | | %WINDIR%\\SYSTEM32\\MSCOREE.DLL |
action_result.data.\*.sandbox.\*.processes.\*.file_accesses.\*.type | string | | OPEN |
action_result.data.\*.sandbox.\*.processes.\*.handles.\*.id | numeric | | 4 |
action_result.data.\*.sandbox.\*.processes.\*.handles.\*.path | string | | HKLM\\SYSTEM\\ControlSet001\\Control\\Session Manager |
action_result.data.\*.sandbox.\*.processes.\*.handles.\*.type | string | | KeyHandle |
action_result.data.\*.sandbox.\*.processes.\*.icon_artifact_id | string | `crowdstrike artifact id` | 6fc9590b42ff8dcbd51c4cddf7ec83bad13f08dcfc882dfbfae326a4c4d68e8d |
action_result.data.\*.sandbox.\*.processes.\*.name | string | | 789356c7d6964b9b4b3d38ecadea3b1570893275013cabbd008900a32c2afd24.exe |
action_result.data.\*.sandbox.\*.processes.\*.normalized_path | string | | C:\\789356c7d6964b9b4b3d38ecadea3b1570893275013cabbd008900a32c2afd24.exe |
action_result.data.\*.sandbox.\*.processes.\*.parent_uid | string | | 00079399-00003508 |
action_result.data.\*.sandbox.\*.processes.\*.pid | numeric | | 3788 |
action_result.data.\*.sandbox.\*.processes.\*.process_flags.\*.name | string | | Reduced Monitoring |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.key | string | | COMPUTERNAME |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.operation | string | | Open |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.path | string | | HKLM\\SOFTWARE\\Test\\RPC\\ |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.status | string | | c0000034 |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.status_human_readable | string | | STATUS_OBJECT_NAME_NOT_FOUND |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.value | string | | 00000000010000002C000000160000001800000043006F006D00700075007400650072004E0061006D00650048004100500055004200570053002D00500043000000 |
action_result.data.\*.sandbox.\*.processes.\*.sha256 | string | `sha256` | 789356c7d6964b9b4b3d38ecadea3b1570893275013cabbd008900a32c2afd24 |
action_result.data.\*.sandbox.\*.processes.\*.streams.\*.file_name | string | | dc829f01c99e0cc1c3bdbcf626bc87a88c9d9d82b965545d9747b2d2292c3716.bin |
action_result.data.\*.sandbox.\*.processes.\*.streams.\*.human_keywords | string | | {0},11:{0},varsim |
action_result.data.\*.sandbox.\*.processes.\*.streams.\*.instructions_artifact_id | string | | ca39fdd4ec789ac3996014bb6edd4989f3b4988da13dfb69bbdd5299185e50c7 |
action_result.data.\*.sandbox.\*.processes.\*.streams.\*.uid | string | | 272dfd975214d0f4abb93b32797f8605-6000001-Program~Main |
action_result.data.\*.sandbox.\*.processes.\*.uid | string | | 00064737-00003788 |
action_result.data.\*.sandbox.\*.sha256 | string | `sha256` | 789356c7d6964b9b4b3d38ecadea3b1570893275013cabbd008900a32c2afd24 |
action_result.data.\*.sandbox.\*.signatures.\*.attack_id | string | | T1116 |
action_result.data.\*.sandbox.\*.signatures.\*.category | string | | General |
action_result.data.\*.sandbox.\*.signatures.\*.description | string | | "example_input.exe" created file "%TEMP%\\329babfa-d618-4d17-a6b0-79fe02a2d94d\\AgileDotNetRT.dll" |
action_result.data.\*.sandbox.\*.signatures.\*.identifier | string | | api-4 |
action_result.data.\*.sandbox.\*.signatures.\*.name | string | | Creates a writable file in a temporary directory |
action_result.data.\*.sandbox.\*.signatures.\*.origin | string | | API Call |
action_result.data.\*.sandbox.\*.signatures.\*.relevance | numeric | | 1 |
action_result.data.\*.sandbox.\*.signatures.\*.threat_level | numeric | | 1 |
action_result.data.\*.sandbox.\*.signatures.\*.threat_level_human | string | | informative |
action_result.data.\*.sandbox.\*.signatures.\*.type | numeric | | 6 |
action_result.data.\*.sandbox.\*.submission_type | string | | file |
action_result.data.\*.sandbox.\*.submit_name | string | | 789356c7d6964b9b4b3d38ecadea3b1570893275013cabbd008900a32c2afd24 |
action_result.data.\*.sandbox.\*.threat_score | numeric | | 41 |
action_result.data.\*.sandbox.\*.verdict | string | | suspicious |
action_result.data.\*.sandbox.\*.version_info.\*.id | string | | Translation |
action_result.data.\*.sandbox.\*.version_info.\*.value | string | | 0x0000 0x04b0 |
action_result.data.\*.sandbox.\*.windows_version_bitness | numeric | | 32 |
action_result.data.\*.sandbox.\*.windows_version_edition | string | | Professional |
action_result.data.\*.sandbox.\*.windows_version_name | string | | Windows 7 |
action_result.data.\*.sandbox.\*.windows_version_service_pack | string | | Service Pack 1 |
action_result.data.\*.sandbox.\*.windows_version_version | string | | 6.1 (build 7601) |
action_result.data.\*.threat_graph.indicators.\*.customer_prevalence | string | | low |
action_result.data.\*.threat_graph.indicators.\*.global_prevalence | string | | common |
action_result.data.\*.threat_graph.indicators.\*.type | string | | sha256 |
action_result.data.\*.threat_graph.indicators.\*.value | string | | c619f87556667f2c1799672d36d55172597f4fed158800d5622edc8abee930e8 |
action_result.data.\*.user_id | string | | b1cab7e2bda14722aca74b8353f5f6d9 |
action_result.data.\*.user_name | string | | testuser@soar.us |
action_result.data.\*.user_uuid | string | | b6330292-28e6-4198-994d-96f327c5b5bd |
action_result.data.\*.verdict | string | | suspicious |
action_result.summary.total_reports | numeric | | 1 |
action_result.summary.verdict | string | | suspicious |
action_result.message | string | | Verdict: suspicious, Total reports: 1 Total reports: 6 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'url reputation'

Queries CrowdStrike for the url info

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to query | string | `url` |
**limit** | optional | Maximum reports to be fetched | numeric | |
**sort** | optional | Property to sort by | string | |
**offset** | optional | Starting index of overall result set from which to return ids (defaults to 0) | numeric | |
**detail_report** | optional | Get the detailed report | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.detail_report | boolean | | True False |
action_result.parameter.limit | numeric | | 5 |
action_result.parameter.offset | numeric | | 5 |
action_result.parameter.sort | string | | created_timestamp.asc |
action_result.parameter.url | string | `url` | https://www.test.com |
action_result.data.\*.cid | string | | 3061c7ff3b634e22b38274d4b586558e |
action_result.data.\*.created_timestamp | string | | 2021-04-29T02:49:16Z |
action_result.data.\*.id | string | `crowdstrike resource id` | 3061c7ff3b634e22b38274d4b586558e_3ab68d2aa2774ba3a35d6f17ae1a7c0b |
action_result.data.\*.ioc_report_broad_csv_artifact_id | string | `crowdstrike artifact id` | 6ba1a1ab22f1c1fdea253934fd96364513f897a4f697df2058dd8a456dee2cc0 |
action_result.data.\*.ioc_report_broad_json_artifact_id | string | `crowdstrike artifact id` | 3ccac07c025cc4aa4ce900530fb982371d878cf8c80ceeb9247024420b540fa4 |
action_result.data.\*.ioc_report_broad_maec_artifact_id | string | `crowdstrike artifact id` | 0ee0e99a5a032a3c42799d01941938e5b10ed8f13e7452d930648d481af5d51e |
action_result.data.\*.ioc_report_broad_stix_artifact_id | string | `crowdstrike artifact id` | 653ebf60312387e4d519dba01da938294ac607f859b671f5d55980c02732f474 |
action_result.data.\*.ioc_report_strict_csv_artifact_id | string | `crowdstrike artifact id` | 6ba1a1ab22f1c1fdea253934fd96364513f897a4f697df2058dd8a456dee2cc0 |
action_result.data.\*.ioc_report_strict_json_artifact_id | string | `crowdstrike artifact id` | 3ccac07c025cc4aa4ce900530fb982371d878cf8c80ceeb9247024420b540fa4 |
action_result.data.\*.ioc_report_strict_maec_artifact_id | string | `crowdstrike artifact id` | 0ee0e99a5a032a3c42799d01941938e5b10ed8f13e7452d930648d481af5d51e |
action_result.data.\*.ioc_report_strict_stix_artifact_id | string | `crowdstrike artifact id` | 653ebf60312387e4d519dba01da938294ac607f859b671f5d55980c02732f474 |
action_result.data.\*.malquery.\*.input | string | | http://accounts.test.com |
action_result.data.\*.malquery.\*.resources.\*.file_size | numeric | | 466 |
action_result.data.\*.malquery.\*.resources.\*.file_type | string | | HTML |
action_result.data.\*.malquery.\*.resources.\*.first_seen_timestamp | string | `date` | 2021-05-05T00:00:00Z |
action_result.data.\*.malquery.\*.resources.\*.label | string | | unknown |
action_result.data.\*.malquery.\*.resources.\*.md5 | string | `md5` | cf83a54faef91aa5c3f9d89dba8a8b14 |
action_result.data.\*.malquery.\*.resources.\*.sha1 | string | `sha1` | 7fe4176691ffaf6df16090e19cbc36dc3f7ed041 |
action_result.data.\*.malquery.\*.resources.\*.sha256 | string | `sha256` | 80c4f85980efc903c8ae376cd6d88025465d49aec6f84901d41abcc384b99738 |
action_result.data.\*.malquery.\*.type | string | | url |
action_result.data.\*.malquery.\*.verdict | string | | whitelisted |
action_result.data.\*.origin | string | | uiproxy |
action_result.data.\*.sandbox.\*.architecture | string | | WINDOWS |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.address | string | `ip` | 2XX.5X.1XX.6X |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.associated_runtime.\*.name | string | | iexplore.exe |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.associated_runtime.\*.pid | numeric | | 3808 |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.country | string | | Test Name |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.port | numeric | `port` | 443 |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.protocol | string | | TCP |
action_result.data.\*.sandbox.\*.dns_requests.\*.address | string | | 2XX.5X.1XX.2XX |
action_result.data.\*.sandbox.\*.dns_requests.\*.country | string | | Test Name |
action_result.data.\*.sandbox.\*.dns_requests.\*.domain | string | `domain` `ip` | accounts.test.com |
action_result.data.\*.sandbox.\*.dns_requests.\*.registrar_creation_timestamp | string | `date` | 2005-02-15T00:00:00+00:00 |
action_result.data.\*.sandbox.\*.dns_requests.\*.registrar_name | string | | MarkMonitor, Inc. |
action_result.data.\*.sandbox.\*.dns_requests.\*.registrar_name_servers | string | | NS1.TEST.COM |
action_result.data.\*.sandbox.\*.dns_requests.\*.registrar_organization | string | | Test Inc. |
action_result.data.\*.sandbox.\*.environment | numeric | | 100 |
action_result.data.\*.sandbox.\*.environment_description | string | `crowdstrike environment` | Windows 7 32 bit |
action_result.data.\*.sandbox.\*.environment_id | numeric | | 160 |
action_result.data.\*.sandbox.\*.error_message | string | | The requested environment ID "300" and file type "url" have no available execution environment |
action_result.data.\*.sandbox.\*.error_origin | string | | CLIENT |
action_result.data.\*.sandbox.\*.error_type | string | | FILE_TYPE_BAD_ERROR |
action_result.data.\*.sandbox.\*.extracted_files.\*.description | string | | XML 1.0 document, UTF-8 Unicode (with BOM) text, with CRLF line terminators |
action_result.data.\*.sandbox.\*.extracted_files.\*.file_path | string | | %LOCALAPPDATA%\\Test\\Internet Explorer\\VersionManager\\ver2963.tmp |
action_result.data.\*.sandbox.\*.extracted_files.\*.file_size | numeric | | 16339 |
action_result.data.\*.sandbox.\*.extracted_files.\*.md5 | string | `md5` | cbd0581678fa40f0edcbc7c59e0cad10 |
action_result.data.\*.sandbox.\*.extracted_files.\*.name | string | | ver2963.tmp |
action_result.data.\*.sandbox.\*.extracted_files.\*.runtime_process | string | | iexplore.exe (PID: 3808) |
action_result.data.\*.sandbox.\*.extracted_files.\*.sha1 | string | `sha1` | a1463fbcc9b96a8929f8a335f75a89147b300715 |
action_result.data.\*.sandbox.\*.extracted_files.\*.sha256 | string | `sha256` | 159bd4343f344a08f6af3b716b6fa679859c1bd1d7030d26ff5ef0255b86e1d9 |
action_result.data.\*.sandbox.\*.extracted_files.\*.threat_level_readable | string | | no specific threat |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.filename | string | | SSL |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.process | string | | iexplore.exe |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.source | string | | Decrypted SSL Data |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.type | string | | Ansi |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.value | string | | .http://www.digicert.com/ssl-cps-repository.htm0 |
action_result.data.\*.sandbox.\*.file_type | string | | PE32 executable (GUI) Intel 80386, for MS Windows, UPX compressed |
action_result.data.\*.sandbox.\*.http_requests.\*.header | string | | GET /gsr2/EXAMPLEDBKMEgwRjAJBgUrDgMCGgTESTXIsxbvr2lBkPpoIEVRE6gHlCnAQUm%2BIHV2ccHsBqBt5ZtJoEXAMPLEQHjtJqhjYqpgSVpULg%3D HTTP/1.1<br>Connection: Keep-Alive<br>Accept: \*/\*<br>User-Agent: Test-CryptoAPI/6.1<br>Host: ocsp.pki.goog |
action_result.data.\*.sandbox.\*.http_requests.\*.host | string | | ocsp.pki.goog |
action_result.data.\*.sandbox.\*.http_requests.\*.host_ip | string | `ip` | 2XX.5X.1XX.1XX |
action_result.data.\*.sandbox.\*.http_requests.\*.host_port | numeric | `port` | 80 |
action_result.data.\*.sandbox.\*.http_requests.\*.method | string | | GET |
action_result.data.\*.sandbox.\*.http_requests.\*.url | string | | /gsr2/ME4wTDBKMEgwRjAJBgUrDgMCGgUABBTgXIsxbvr2lBkPpoIEVRE6gHlCnAQUm%2BIHV2ccHsBqBt5ZtJot39wZhi4CDQHjtJqhjYqpgSVpULg%3D |
action_result.data.\*.sandbox.\*.incidents.\*.name | string | | Network Behavior |
action_result.data.\*.sandbox.\*.memory_strings_artifact_id | string | `crowdstrike artifact id` | 4300381ecd2f3d62648cdc01d862f4765032f071bad272164c3580b7b6fb8840 |
action_result.data.\*.sandbox.\*.mitre_attacks.\*.attack_id | string | | T1085 |
action_result.data.\*.sandbox.\*.mitre_attacks.\*.tactic | string | | Execution |
action_result.data.\*.sandbox.\*.mitre_attacks.\*.technique | string | | Rundll32 |
action_result.data.\*.sandbox.\*.network_settings | string | | default |
action_result.data.\*.sandbox.\*.pcap_report_artifact_id | string | `crowdstrike artifact id` | 04a091843e91c36357b2ec63a2a7ac8ad7d142d861759062520b0a925e9b875d |
action_result.data.\*.sandbox.\*.processes.\*.command_line | string | | "%WINDIR%\\System32\\ieframe.dll",OpenURL C:\\3cfc7f2806efb5b01deb01164fa00adb46eb73a0d24871a566051fb2204094af.url |
action_result.data.\*.sandbox.\*.processes.\*.file_accesses.\*.mask | string | | FILE_READ_ATTRIBUTES |
action_result.data.\*.sandbox.\*.processes.\*.file_accesses.\*.path | string | | C: |
action_result.data.\*.sandbox.\*.processes.\*.file_accesses.\*.type | string | | CREATE |
action_result.data.\*.sandbox.\*.processes.\*.handles.\*.id | numeric | | 80 |
action_result.data.\*.sandbox.\*.processes.\*.handles.\*.path | string | | HKCU\\Software\\Test\\Internet Explorer\\Main\\WindowsSearch |
action_result.data.\*.sandbox.\*.processes.\*.handles.\*.type | string | | KeyHandle |
action_result.data.\*.sandbox.\*.processes.\*.icon_artifact_id | string | `crowdstrike artifact id` | aa6f1a14d219555f2818f89dee06821824c872ae18279027baa0e160f61f049a |
action_result.data.\*.sandbox.\*.processes.\*.name | string | | rundll32.exe |
action_result.data.\*.sandbox.\*.processes.\*.normalized_path | string | | %WINDIR%\\System32\\rundll32.exe |
action_result.data.\*.sandbox.\*.processes.\*.parent_uid | string | | 00065605-00002148 |
action_result.data.\*.sandbox.\*.processes.\*.pid | numeric | | 2148 |
action_result.data.\*.sandbox.\*.processes.\*.process_flags.\*.name | string | | Reduced Monitoring |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.key | string | | WPADDECISIONREASON |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.operation | string | | Write |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.path | string | | HKCU\\SOFTWARE\\Test\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS\\WPAD\\{0C70BB6D-CFA8-4734-A158-28619E142726}\\WPADDECISIONREASON |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.value | string | | 01000000 |
action_result.data.\*.sandbox.\*.processes.\*.sha256 | string | `sha256` | 3fa4912eb43fc304652d7b01f118589259861e2d628fa7c86193e54d5f987670 |
action_result.data.\*.sandbox.\*.processes.\*.uid | string | | 00065605-00002148 |
action_result.data.\*.sandbox.\*.sha256 | string | `sha256` | 3cfc7f2806efb5b01deb01164fa00adb46eb73a0d24871a566051fb2204094af |
action_result.data.\*.sandbox.\*.signatures.\*.attack_id | string | | T1085 |
action_result.data.\*.sandbox.\*.signatures.\*.category | string | | General |
action_result.data.\*.sandbox.\*.signatures.\*.description | string | | "21X.5X.1XX.6X:4XX"<br> "21X.5X.1XX.1XX:8X" |
action_result.data.\*.sandbox.\*.signatures.\*.identifier | string | | network-1 |
action_result.data.\*.sandbox.\*.signatures.\*.name | string | | Contacts server |
action_result.data.\*.sandbox.\*.signatures.\*.origin | string | | Network Traffic |
action_result.data.\*.sandbox.\*.signatures.\*.relevance | numeric | | 1 |
action_result.data.\*.sandbox.\*.signatures.\*.threat_level | numeric | | 1 |
action_result.data.\*.sandbox.\*.signatures.\*.threat_level_human | string | | informative |
action_result.data.\*.sandbox.\*.signatures.\*.type | numeric | | 7 |
action_result.data.\*.sandbox.\*.submission_type | string | | page_url |
action_result.data.\*.sandbox.\*.submit_name | string | | http://ko.wikipedia.org/wiki/%EC%9C%84%ED%82%A4%EB%B0%B1%EA%B3%BC:%EB%8C%80%EB%AC%B8 |
action_result.data.\*.sandbox.\*.submit_url | string | | hxxps://www.test.com |
action_result.data.\*.sandbox.\*.suricata_alerts.\*.category | string | | Unknown Traffic |
action_result.data.\*.sandbox.\*.suricata_alerts.\*.description | string | | ET USER_AGENTS Test Device Metadata Retrieval Client User-Agent |
action_result.data.\*.sandbox.\*.suricata_alerts.\*.destination_ip | string | | 1XX.XX0.7X.X2 |
action_result.data.\*.sandbox.\*.suricata_alerts.\*.destination_port | numeric | `port` | 80 |
action_result.data.\*.sandbox.\*.suricata_alerts.\*.protocol | string | | TCP |
action_result.data.\*.sandbox.\*.suricata_alerts.\*.sid | string | | 2027390 |
action_result.data.\*.sandbox.\*.threat_score | numeric | | 35 |
action_result.data.\*.sandbox.\*.verdict | string | | no specific threat |
action_result.data.\*.sandbox.\*.windows_version_bitness | numeric | | 32 |
action_result.data.\*.sandbox.\*.windows_version_edition | string | | Professional |
action_result.data.\*.sandbox.\*.windows_version_name | string | | Windows 7 |
action_result.data.\*.sandbox.\*.windows_version_service_pack | string | | Service Pack 1 |
action_result.data.\*.sandbox.\*.windows_version_version | string | | 6.1 (build 7601) |
action_result.data.\*.user_id | string | | 2b32e6795b344abba8925cce6782d128 |
action_result.data.\*.user_name | string | | testuser@soar.us |
action_result.data.\*.user_uuid | string | | b6330292-28e6-4198-994d-96f327c5b5bd |
action_result.data.\*.verdict | string | | no specific threat |
action_result.summary.total_reports | numeric | | 1 |
action_result.summary.verdict | string | | no specific threat |
action_result.message | string | | Verdict: no specific threat, Total reports: 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'download report'

To download the report of the provided artifact id

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**artifact_id** | required | Artifact id to be downloaded | string | `crowdstrike artifact id` |
**file_name** | optional | Filename to use for the file added to vault | string | `filename` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.artifact_id | string | `crowdstrike artifact id` | 6fc9590b42ff8dcbd51c4cddf7ec83bad13f08dcfc882dfbfae326a4c4d68e8d |
action_result.parameter.file_name | string | `filename` | test_file |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | Report downloaded successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'detonate file'

Upload a file to CrowdStrike and retrieve the analysis results

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | required | Vault ID of file | string | `vault id` |
**environment** | required | Sandbox environment to be used for analysis | string | `crowdstrike environment` |
**comment** | optional | A descriptive comment to identify the file | string | |
**limit** | optional | Maximum reports to be fetched | numeric | |
**offset** | optional | Starting index of overall result set from which to return ids (Defaults to 0) | numeric | |
**command_line** | optional | Command line script passed to the submitted file at runtime (Max length: 2048 characters) | string | |
**document_password** | optional | Password of the document if password protected (Max length: 32 characters) | string | |
**submit_name** | optional | Name of the malware sample that's used for file type detection and analysis | string | |
**user_tags** | optional | Comma seperated list of user tags (Max length: 100 characters per tag) | string | |
**sort** | optional | Property to sort by | string | |
**action_script** | optional | Runtime script for sandbox analysis | string | |
**detail_report** | optional | Get the detailed report | boolean | |
**enable_tor** | optional | To route the sandbox network traffic via TOR | boolean | |
**is_confidential** | optional | Defines visibility of the file in Falcon MalQuery (defaults to True) | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.action_script | string | | default |
action_result.parameter.command_line | string | | |
action_result.parameter.comment | string | | This is a test comment |
action_result.parameter.detail_report | boolean | | True False |
action_result.parameter.document_password | string | | test_password |
action_result.parameter.enable_tor | boolean | | True False |
action_result.parameter.environment | string | `crowdstrike environment` | Windows 10, 64-bit |
action_result.parameter.is_confidential | boolean | | True False |
action_result.parameter.limit | numeric | | 5 |
action_result.parameter.offset | numeric | | 5 |
action_result.parameter.sort | string | | created_timestamp.asc |
action_result.parameter.submit_name | string | | test_file_name |
action_result.parameter.user_tags | string | | test_tag1 |
action_result.parameter.vault_id | string | `vault id` | 30c5e524e975816fbce1d958150e394efc219772 |
action_result.data.\*.cid | string | | 3061c7ff3b634e22b38274d4b586558e |
action_result.data.\*.created_timestamp | string | `date` | 2021-05-09T05:58:47Z |
action_result.data.\*.id | string | `crowdstrike resource id` | 3061c7ff3b634e22b38274d4b586558e_ca27f64601b74c1f8a25577007987606 |
action_result.data.\*.ioc_report_broad_csv_artifact_id | string | `crowdstrike artifact id` | 8a06e0e6a04696b16d8bcbe3b7952c6b0b48458f1168bf70ffa97b0993b9d115 |
action_result.data.\*.ioc_report_broad_json_artifact_id | string | `crowdstrike artifact id` | 76dba8304fb398f192202a9dbbb39e259882ee7d9460afb4a07b8f2b8db8679a |
action_result.data.\*.ioc_report_broad_maec_artifact_id | string | `crowdstrike artifact id` | 5391d132d841fe391d3132d2cab43cdf0d5a45c4f146e31cd65f51917dbf6820 |
action_result.data.\*.ioc_report_broad_stix_artifact_id | string | `crowdstrike artifact id` | aaab7615a82190cabdf6086fd818a5a3a5f65072363a7fa89c73e12bf115befd |
action_result.data.\*.ioc_report_strict_csv_artifact_id | string | `crowdstrike artifact id` | 3ebe2620f871109e7048bfb0c1638b8e011b5fb779d6229db7135668fc558208 |
action_result.data.\*.ioc_report_strict_json_artifact_id | string | `crowdstrike artifact id` | 097dc42503083de24bfb80b8964433348dfcb8b769f9abb491f5a97599666279 |
action_result.data.\*.ioc_report_strict_maec_artifact_id | string | `crowdstrike artifact id` | ccbc852e586f1348d83025a98a78398ba97c78d21fd8296676ef7da40852dc9a |
action_result.data.\*.ioc_report_strict_stix_artifact_id | string | `crowdstrike artifact id` | 0967fd13eea5335645e8b2be13f2da7254a8401f1536bd2b939002d69a1af7f6 |
action_result.data.\*.malquery.\*.input | string | | X.X.0.0 |
action_result.data.\*.malquery.\*.resources.\*.file_size | numeric | | 25970 |
action_result.data.\*.malquery.\*.resources.\*.file_type | string | | TEXT |
action_result.data.\*.malquery.\*.resources.\*.first_seen_timestamp | string | `date` | 2017-08-10T00:00:00Z |
action_result.data.\*.malquery.\*.resources.\*.label | string | | unknown |
action_result.data.\*.malquery.\*.resources.\*.md5 | string | `md5` | c7c4bf6fc4e73a85e6ab36711bdd8a7f |
action_result.data.\*.malquery.\*.resources.\*.sha1 | string | `sha1` | a21c5fbfa596efb30180f75062794f01952cf18e |
action_result.data.\*.malquery.\*.resources.\*.sha256 | string | `sha256` | 07c522146bddc664d077c2184e88e5cb17547f2501785506ce2f7b05eaf93af0 |
action_result.data.\*.malquery.\*.type | string | | ip |
action_result.data.\*.malquery.\*.verdict | string | | whitelisted |
action_result.data.\*.origin | string | | apigateway |
action_result.data.\*.sandbox.\*.architecture | string | | Unknown |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.address | string | `ip` | 2X.3X.1XX.X1 |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.associated_runtime.\*.name | string | | svchost.exe |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.associated_runtime.\*.pid | numeric | | 7884 |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.country | string | | Test Name |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.port | numeric | | 443 |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.protocol | string | | TCP |
action_result.data.\*.sandbox.\*.dns_requests.\*.address | string | `ip` | 1X2.XX7.164.XX |
action_result.data.\*.sandbox.\*.dns_requests.\*.country | string | | Test Name |
action_result.data.\*.sandbox.\*.dns_requests.\*.domain | string | `domain` `url` | fonts.gstatic.com |
action_result.data.\*.sandbox.\*.dns_requests.\*.registrar_creation_timestamp | string | `date` | 2008-02-11T00:00:00+00:00 |
action_result.data.\*.sandbox.\*.dns_requests.\*.registrar_name | string | | MarkMonitor, Inc. |
action_result.data.\*.sandbox.\*.dns_requests.\*.registrar_name_servers | string | | NS1.TEST.COM |
action_result.data.\*.sandbox.\*.dns_requests.\*.registrar_organization | string | | Test Inc. |
action_result.data.\*.sandbox.\*.environment | numeric | | 160 |
action_result.data.\*.sandbox.\*.environment_description | string | `crowdstrike environment` | Windows 10 64 bit |
action_result.data.\*.sandbox.\*.environment_id | numeric | | 160 |
action_result.data.\*.sandbox.\*.error_message | string | | The requested environment ID "300" and file type "html" have no available execution environment |
action_result.data.\*.sandbox.\*.error_origin | string | | CLIENT |
action_result.data.\*.sandbox.\*.error_type | string | | FILE_TYPE_BAD_ERROR |
action_result.data.\*.sandbox.\*.extracted_files.\*.description | string | | MS Windows icon resource - 1 icon, 32x32 |
action_result.data.\*.sandbox.\*.extracted_files.\*.file_path | string | | %APPDATA%\\Test\\Windows\\Recent\\CustomDestinations\\RB7520AO5Z28DRA0CR4G.temp |
action_result.data.\*.sandbox.\*.extracted_files.\*.file_size | numeric | | 4286 |
action_result.data.\*.sandbox.\*.extracted_files.\*.md5 | string | `md5` | da597791be3b6e732f0bc8b20e38ee62 |
action_result.data.\*.sandbox.\*.extracted_files.\*.name | string | | search\_\_0633EE93-D776-472f-A0FF-E1416B8B2E3A\_.ico |
action_result.data.\*.sandbox.\*.extracted_files.\*.runtime_process | string | | iexplore.exe (PID: 3508) |
action_result.data.\*.sandbox.\*.extracted_files.\*.sha1 | string | `sha1` | 1125c45d285c360542027d7554a5c442288974de |
action_result.data.\*.sandbox.\*.extracted_files.\*.sha256 | string | `sha256` | 5b2c34b3c4e8dd898b664dba6c3786e2ff9869eff55d673aa48361f11325ed07 |
action_result.data.\*.sandbox.\*.extracted_files.\*.threat_level_readable | string | | no specific threat |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.filename | string | | ver718B.tmp |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.process | string | | iexplore.exe |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.source | string | | Runtime Data |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.type | string | | Unicode |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.value | string | | %LOCALAPPDATA%\\Test\\Internet Explorer\\Recovery\\High\\Active\\{EAD6EFB1-2090-11E8-9BD7-0A00274B5076}.dat |
action_result.data.\*.sandbox.\*.file_imports.\*.module | string | | KERNEL32.dll |
action_result.data.\*.sandbox.\*.file_size | numeric | | 70595 |
action_result.data.\*.sandbox.\*.file_type | string | | SVG Scalable Vector Graphics image |
action_result.data.\*.sandbox.\*.http_requests.\*.header | string | | GET /gsr2/TESTMEgwRjAJBgUrDgMCGgUABBTgXIsxbvEXAMPLEkIEVRE6gHlCnAQUm%2BIHV2ccHsBqBt5ZtJot39wZhi4CDQHjtJqhjYqTESTULg%3D HTTP/1.1<br>Connection: Keep-Alive<br>Accept: \*/\*<br>User-Agent: Test-CryptoAPI/10.0<br>Host: ocsp.pki.goog |
action_result.data.\*.sandbox.\*.http_requests.\*.host | string | `hostname` | ocsp.pki.goog |
action_result.data.\*.sandbox.\*.http_requests.\*.host_ip | string | `ip` | 1X2.2X7.13.67 |
action_result.data.\*.sandbox.\*.http_requests.\*.host_port | numeric | `port` | 80 |
action_result.data.\*.sandbox.\*.http_requests.\*.method | string | | GET |
action_result.data.\*.sandbox.\*.http_requests.\*.url | string | | /gsr2/ME4wTDBKMEgwRjAJBgUrDgMCGgUABBTgXIsxbvr2lBkPpoIEVRE6gHlCnAQUm%2BIHV2ccHsBqBt5ZtJot39wZhi4CDQHjtJqhjYqpgSVpULg%3D |
action_result.data.\*.sandbox.\*.incidents.\*.name | string | | Network Behavior |
action_result.data.\*.sandbox.\*.memory_strings_artifact_id | string | `crowdstrike artifact id` | ba1b505d2495d9258817ae235fd12331ec1d6805543df5ff99c98168ff003af5 |
action_result.data.\*.sandbox.\*.mitre_attacks.\*.attack_id | string | | T1179 |
action_result.data.\*.sandbox.\*.mitre_attacks.\*.tactic | string | | Persistence |
action_result.data.\*.sandbox.\*.mitre_attacks.\*.technique | string | | Hooking |
action_result.data.\*.sandbox.\*.network_settings | string | | tor |
action_result.data.\*.sandbox.\*.pcap_report_artifact_id | string | `crowdstrike artifact id` | cce20f960ed692d8cd1e82418d98133c54eeb0e989941545a25e17c13629c9a6 |
action_result.data.\*.sandbox.\*.processes.\*.command_line | string | | C:\\TestName.svg |
action_result.data.\*.sandbox.\*.processes.\*.file_accesses.\*.mask | string | | GENERIC_READ | FILE_READ_ATTRIBUTES |
action_result.data.\*.sandbox.\*.processes.\*.file_accesses.\*.path | string | | %WINDIR%\\apppatch\\sysmain.sdb |
action_result.data.\*.sandbox.\*.processes.\*.file_accesses.\*.type | string | | CREATE |
action_result.data.\*.sandbox.\*.processes.\*.handles.\*.id | numeric | | 152 |
action_result.data.\*.sandbox.\*.processes.\*.handles.\*.path | string | | \\Device\\CNG |
action_result.data.\*.sandbox.\*.processes.\*.handles.\*.type | string | | FileHandle |
action_result.data.\*.sandbox.\*.processes.\*.icon_artifact_id | string | `crowdstrike artifact id` | eed07c63db692d7cb4af1daa44bdc5b03a63050290277d1e383601de95c05775 |
action_result.data.\*.sandbox.\*.processes.\*.name | string | | iexplore.exe |
action_result.data.\*.sandbox.\*.processes.\*.normalized_path | string | | %PROGRAMFILES%\\internet explorer\\iexplore.exe |
action_result.data.\*.sandbox.\*.processes.\*.parent_uid | string | | 00079399-00003508 |
action_result.data.\*.sandbox.\*.processes.\*.pid | numeric | | 3508 |
action_result.data.\*.sandbox.\*.processes.\*.process_flags.\*.name | string | | Reduced Monitoring |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.key | string | | TYPE |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.operation | string | | Write |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.path | string | | HKCU\\SOFTWARE\\Test\\INTERNET EXPLORER\\VERSIONMANAGER\\LASTUPDATELOWDATETIME |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.status | string | | c0000022 |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.status_human_readable | string | | STATUS_ACCESS_DENIED |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.value | string | | C4110129 |
action_result.data.\*.sandbox.\*.processes.\*.sha256 | string | `sha256` | 8dea16e513f70e1a98be6ec48439b5499d2c740247716f6bcb990b7c305ec0a0 |
action_result.data.\*.sandbox.\*.processes.\*.uid | string | | 00079399-00003508 |
action_result.data.\*.sandbox.\*.sha256 | string | `sha256` | 43e6a1253ebd103b93d50531ee05ba9cf7d87f043b6bca96a0edec311494d875 |
action_result.data.\*.sandbox.\*.signatures.\*.attack_id | string | | T1010 |
action_result.data.\*.sandbox.\*.signatures.\*.category | string | | General |
action_result.data.\*.sandbox.\*.signatures.\*.description | string | | "2XX.1XX.2XX.1X:8X" |
action_result.data.\*.sandbox.\*.signatures.\*.identifier | string | | mutant-0 |
action_result.data.\*.sandbox.\*.signatures.\*.name | string | | Creates mutants |
action_result.data.\*.sandbox.\*.signatures.\*.origin | string | | Created Mutant |
action_result.data.\*.sandbox.\*.signatures.\*.relevance | numeric | | 3 |
action_result.data.\*.sandbox.\*.signatures.\*.threat_level | numeric | | 1 |
action_result.data.\*.sandbox.\*.signatures.\*.threat_level_human | string | | informative |
action_result.data.\*.sandbox.\*.signatures.\*.type | numeric | | 4 |
action_result.data.\*.sandbox.\*.submission_type | string | | file |
action_result.data.\*.sandbox.\*.submit_name | string | | Test Name |
action_result.data.\*.sandbox.\*.suricata_alerts.\*.category | string | | Unknown Traffic |
action_result.data.\*.sandbox.\*.suricata_alerts.\*.description | string | | ET USER_AGENTS Test Device Metadata Retrieval Client User-Agent |
action_result.data.\*.sandbox.\*.suricata_alerts.\*.destination_ip | string | `ip` | 1X4.1XX.8X.21 |
action_result.data.\*.sandbox.\*.suricata_alerts.\*.destination_port | numeric | `port` | 80 |
action_result.data.\*.sandbox.\*.suricata_alerts.\*.protocol | string | | TCP |
action_result.data.\*.sandbox.\*.suricata_alerts.\*.sid | string | | 2027390 |
action_result.data.\*.sandbox.\*.threat_score | numeric | | 35 |
action_result.data.\*.sandbox.\*.verdict | string | | no specific threat |
action_result.data.\*.sandbox.\*.version_info.\*.id | string | | LegalCopyright |
action_result.data.\*.sandbox.\*.version_info.\*.value | string | | Copyright (C) Test Corp. 1981-1998 |
action_result.data.\*.sandbox.\*.windows_version_bitness | numeric | | 64 |
action_result.data.\*.sandbox.\*.windows_version_edition | string | | Professional |
action_result.data.\*.sandbox.\*.windows_version_name | string | | Windows 10 |
action_result.data.\*.sandbox.\*.windows_version_service_pack | string | | Service Pack 1 |
action_result.data.\*.sandbox.\*.windows_version_version | string | | 10.0 (build 16299) |
action_result.data.\*.threat_graph.indicators.\*.global_prevalence | string | | common |
action_result.data.\*.threat_graph.indicators.\*.type | string | | sha256 |
action_result.data.\*.threat_graph.indicators.\*.value | string | | 7ef166e82439ea3cafcb28754245325bfbf73e4eb94041bd77fd5c961924709c |
action_result.data.\*.user_id | string | | b1cab7e2bda14722aca74b8353f5f6d9 |
action_result.data.\*.user_name | string | | testuser@soar.us |
action_result.data.\*.user_tags | string | | test_tag1 |
action_result.data.\*.user_uuid | string | | b6330292-28e6-4198-994d-96f327c5b5bd |
action_result.data.\*.verdict | string | | no specific threat |
action_result.summary.total_reports | numeric | | 1 |
action_result.summary.verdict | string | | suspicious |
action_result.message | string | | Verdict: no specific threat, Total reports: 1 Total reports: 6 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'detonate url'

Upload an url to CrowdStrike and retrieve the analysis results

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to query | string | `url` |
**environment** | required | Sandbox environment to be used for analysis | string | `crowdstrike environment` |
**limit** | optional | Maximum reports to be fetched | numeric | |
**offset** | optional | Starting index of overall result set from which to return ids (Defaults to 0) | numeric | |
**document_password** | optional | Password of the document if password protected (Max length: 32 characters) | string | |
**command_line** | optional | Command line script passed to the submitted file at runtime (Max length: 2048 characters) | string | |
**user_tags** | optional | Comma seperated list of user tags (Max length: 100 characters per tag) | string | |
**sort** | optional | Property to sort by | string | |
**action_script** | optional | Runtime script for sandbox analysis | string | |
**detail_report** | optional | Get the detailed report | boolean | |
**enable_tor** | optional | To route the sandbox network traffic via TOR | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.action_script | string | | default |
action_result.parameter.command_line | string | | |
action_result.parameter.detail_report | boolean | | True False |
action_result.parameter.document_password | string | | test_password |
action_result.parameter.enable_tor | boolean | | True False |
action_result.parameter.environment | string | `crowdstrike environment` | Windows 10, 64-bit |
action_result.parameter.limit | numeric | | 5 |
action_result.parameter.offset | numeric | | 5 |
action_result.parameter.sort | string | | created_timestamp.asc |
action_result.parameter.url | string | `url` | https://www.test.com |
action_result.parameter.user_tags | string | | test_tag1 |
action_result.data.\*.cid | string | | 3061c7ff3b634e22b38274d4b586558e |
action_result.data.\*.created_timestamp | string | `date` | 2021-05-14T10:03:35Z |
action_result.data.\*.id | string | `crowdstrike resource id` | 3061c7ff3b634e22b38274d4b586558e_5e2ec86aa5e444ac93d298df547e4d40 |
action_result.data.\*.ioc_report_broad_csv_artifact_id | string | `crowdstrike artifact id` | 3b4ca1c6dd800fa60aaa4eb7154da76da7604067bcb3df160caa984ed7eabf3e |
action_result.data.\*.ioc_report_broad_json_artifact_id | string | `crowdstrike artifact id` | 5b7554048df30cb234d11a9d4d77a64e9f033dbe53265ee9a0e74fd7f803cf59 |
action_result.data.\*.ioc_report_broad_maec_artifact_id | string | `crowdstrike artifact id` | eefd76de04f16b6187d0f2b728dafec578e47cbfec140e7a6735f2f173d0cbcf |
action_result.data.\*.ioc_report_broad_stix_artifact_id | string | `crowdstrike artifact id` | bb6089f7c2da27e70eb93447a724287572d3b4cac1c91e78edc264ee30dc401d |
action_result.data.\*.ioc_report_strict_csv_artifact_id | string | `crowdstrike artifact id` | 3b4ca1c6dd800fa60aaa4eb7154da76da7604067bcb3df160caa984ed7eabf3e |
action_result.data.\*.ioc_report_strict_json_artifact_id | string | `crowdstrike artifact id` | 5b7554048df30cb234d11a9d4d77a64e9f033dbe53265ee9a0e74fd7f803cf59 |
action_result.data.\*.ioc_report_strict_maec_artifact_id | string | `crowdstrike artifact id` | eefd76de04f16b6187d0f2b728dafec578e47cbfec140e7a6735f2f173d0cbcf |
action_result.data.\*.ioc_report_strict_stix_artifact_id | string | `crowdstrike artifact id` | bb6089f7c2da27e70eb93447a724287572d3b4cac1c91e78edc264ee30dc401d |
action_result.data.\*.malquery.\*.input | string | | http://mm.test.com |
action_result.data.\*.malquery.\*.resources.\*.family | string | | Coinminer |
action_result.data.\*.malquery.\*.resources.\*.file_size | numeric | | 2313692 |
action_result.data.\*.malquery.\*.resources.\*.file_type | string | | PCAP |
action_result.data.\*.malquery.\*.resources.\*.first_seen_timestamp | string | `date` | 2021-05-26T00:00:00Z |
action_result.data.\*.malquery.\*.resources.\*.label | string | | unknown |
action_result.data.\*.malquery.\*.resources.\*.md5 | string | `md5` | 4446a961902d0094397a071d75e4abf8 |
action_result.data.\*.malquery.\*.resources.\*.sha1 | string | `sha1` | cb1c5bb0d84e3efb978efede256ebec5308873c0 |
action_result.data.\*.malquery.\*.resources.\*.sha256 | string | `sha256` | 0091a4c5bc7bea90faadeee2ae71bd29e131d3f59f8ffb9f58ec7276953fafe5 |
action_result.data.\*.malquery.\*.type | string | | url |
action_result.data.\*.malquery.\*.verdict | string | | unknown |
action_result.data.\*.origin | string | | apigateway |
action_result.data.\*.sandbox.\*.architecture | string | | WINDOWS |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.address | string | `ip` | 1XX.2XX.7X.1XX |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.associated_runtime.\*.name | string | | Testedgecp.exe |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.associated_runtime.\*.pid | numeric | | 1600 |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.country | string | | Test Name |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.port | numeric | | 443 |
action_result.data.\*.sandbox.\*.contacted_hosts.\*.protocol | string | | TCP |
action_result.data.\*.sandbox.\*.dns_requests.\*.address | string | `ip` | 1XX.2X.X.X |
action_result.data.\*.sandbox.\*.dns_requests.\*.country | string | | Test Name |
action_result.data.\*.sandbox.\*.dns_requests.\*.domain | string | `domain` `url` | www.test.com |
action_result.data.\*.sandbox.\*.dns_requests.\*.registrar_creation_timestamp | string | `date` | 2007-11-13T00:00:00+00:00 |
action_result.data.\*.sandbox.\*.dns_requests.\*.registrar_name | string | | RegistryGate GmbH |
action_result.data.\*.sandbox.\*.dns_requests.\*.registrar_name_servers | string | | NS-1109.AWSDNS-10.ORG |
action_result.data.\*.sandbox.\*.dns_requests.\*.registrar_organization | string | | Creationes Virtuales CV GmbH |
action_result.data.\*.sandbox.\*.environment | numeric | | 160 |
action_result.data.\*.sandbox.\*.environment_description | string | `crowdstrike environment` | Windows 10 64 bit |
action_result.data.\*.sandbox.\*.environment_id | numeric | | 100 |
action_result.data.\*.sandbox.\*.error_message | string | | The requested environment ID "300" and file type "url" have no available execution environment |
action_result.data.\*.sandbox.\*.error_origin | string | | CLIENT |
action_result.data.\*.sandbox.\*.error_type | string | | FILE_TYPE_BAD_ERROR |
action_result.data.\*.sandbox.\*.extracted_files.\*.description | string | | data |
action_result.data.\*.sandbox.\*.extracted_files.\*.file_path | string | | %APPDATA%\\Adobe\\Acrobat\\11.0\\Security\\CRLCache\\0FDED5CEB68C302B1CDB2BDDD9D0000E76539CB0.crl |
action_result.data.\*.sandbox.\*.extracted_files.\*.file_size | numeric | | 637 |
action_result.data.\*.sandbox.\*.extracted_files.\*.md5 | string | `md5` | 974e8536b8767ac5be204f35d16f73e8 |
action_result.data.\*.sandbox.\*.extracted_files.\*.name | string | | 0FDED5CEB68C302B1CDB2BDDD9D0000E76539CB0.crl |
action_result.data.\*.sandbox.\*.extracted_files.\*.runtime_process | string | | AcroRd32.exe (PID: 4084) |
action_result.data.\*.sandbox.\*.extracted_files.\*.sha1 | string | `sha1` | e847897947a3db26e35cb7d490c688e8c410dfb7 |
action_result.data.\*.sandbox.\*.extracted_files.\*.sha256 | string | `sha256` | d1bb4b163fe01acc368a92b385bb0bd3a9fc2340b6d485b77a20553a713166d3 |
action_result.data.\*.sandbox.\*.extracted_files.\*.threat_level_readable | string | | no specific threat |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.filename | string | | rundll32.exe |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.process | string | | AcroRd32.exe |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.source | string | | Process Commandline |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.type | string | | Ansi |
action_result.data.\*.sandbox.\*.extracted_interesting_strings.\*.value | string | | "%WINDIR%\\system32\\ieframe.dll",OpenURL C:\\a3d7be9b5d8f9070d96789cdf7ee5ce2f1ee827f261faa0d43d4de605ad3194c.url |
action_result.data.\*.sandbox.\*.file_size | numeric | | 690028 |
action_result.data.\*.sandbox.\*.file_type | string | | PDF document, version 1.6 |
action_result.data.\*.sandbox.\*.http_requests.\*.header | string | | GET /gsr2/EXAMPLEMEgwRjAJBgUrDgMCGgUABBTgXTEST2lBkPpoIEVRE6gHlCnAQUm%2BIHV2ccHsBqBtTESTt39wZhi4CDQHjtJqhjYqpgSVpULg%3D HTTP/1.1<br>Connection: Keep-Alive<br>Accept: \*/\*<br>User-Agent: Test-CryptoAPI/10.0<br>Host: ocsp.pki.goog |
action_result.data.\*.sandbox.\*.http_requests.\*.host | string | `hostname` | ocsp.pki.goog |
action_result.data.\*.sandbox.\*.http_requests.\*.host_ip | string | `ip` | 1XX.2XX.X.6X |
action_result.data.\*.sandbox.\*.http_requests.\*.host_port | numeric | | 80 |
action_result.data.\*.sandbox.\*.http_requests.\*.method | string | | GET |
action_result.data.\*.sandbox.\*.http_requests.\*.url | string | `url` | /gsr2/ME4wTDBKMEgwRjAJBgUrDgMCGgUABBTgXIsxbvr2lBkPpoIEVRE6gHlCnAQUm%2BIHV2ccHsBqBt5ZtJot39wZhi4CDQHjtJqhjYqpgSVpULg%3D |
action_result.data.\*.sandbox.\*.incidents.\*.name | string | | Network Behavior |
action_result.data.\*.sandbox.\*.memory_strings_artifact_id | string | `crowdstrike artifact id` | 84626f942fc9dffdeb6facc2fb4a337bc8f52323a6a8be3e16d0c2ea57d30820 |
action_result.data.\*.sandbox.\*.mitre_attacks.\*.attack_id | string | | T1085 |
action_result.data.\*.sandbox.\*.mitre_attacks.\*.tactic | string | | Execution |
action_result.data.\*.sandbox.\*.mitre_attacks.\*.technique | string | | Rundll32 |
action_result.data.\*.sandbox.\*.network_settings | string | | tor |
action_result.data.\*.sandbox.\*.pcap_report_artifact_id | string | `crowdstrike artifact id` | 506bc12accb770cdb032ad567ee478842a8cf1506ce9658f78f46d6b6cc65099 |
action_result.data.\*.sandbox.\*.processes.\*.command_line | string | | "%WINDIR%\\system32\\ieframe.dll",OpenURL C:\\a3d7be9b5d8f9070d96789cdf7ee5ce2f1ee827f261faa0d43d4de605ad3194c.url |
action_result.data.\*.sandbox.\*.processes.\*.file_accesses.\*.mask | string | | GENERIC_READ | FILE_READ_ATTRIBUTES |
action_result.data.\*.sandbox.\*.processes.\*.file_accesses.\*.path | string | | %WINDIR%\\apppatch\\sysmain.sdb |
action_result.data.\*.sandbox.\*.processes.\*.file_accesses.\*.type | string | | CREATE |
action_result.data.\*.sandbox.\*.processes.\*.handles.\*.id | numeric | | 176 |
action_result.data.\*.sandbox.\*.processes.\*.handles.\*.path | string | | \\Device\\CNG |
action_result.data.\*.sandbox.\*.processes.\*.handles.\*.type | string | | FileHandle |
action_result.data.\*.sandbox.\*.processes.\*.icon_artifact_id | string | `crowdstrike artifact id` | 25f2b36dff5226562d05a905dae09c7e4ef627528e74dd5b95cc3575da3697dd |
action_result.data.\*.sandbox.\*.processes.\*.name | string | | rundll32.exe |
action_result.data.\*.sandbox.\*.processes.\*.normalized_path | string | | %WINDIR%\\System32\\rundll32.exe |
action_result.data.\*.sandbox.\*.processes.\*.pid | numeric | | 4340 |
action_result.data.\*.sandbox.\*.processes.\*.process_flags.\*.name | string | | Reduced Monitoring |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.key | string | | BLASTEXITNORMAL |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.operation | string | | Delete |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.path | string | | HKLM\\SYSTEM\\ACROBATVIEWERCPP473\\ |
action_result.data.\*.sandbox.\*.processes.\*.registry.\*.value | string | | 00000000 |
action_result.data.\*.sandbox.\*.processes.\*.sha256 | string | `sha256` | b1e6a7a3e2597e51836277a32b2bc61aa781c8f681d44dfddea618b32e2bf2a6 |
action_result.data.\*.sandbox.\*.processes.\*.uid | string | | 00177892-00004340 |
action_result.data.\*.sandbox.\*.sha256 | string | `sha256` | a3d7be9b5d8f9070d96789cdf7ee5ce2f1ee827f261faa0d43d4de605ad3194c |
action_result.data.\*.sandbox.\*.signatures.\*.attack_id | string | | T1085 |
action_result.data.\*.sandbox.\*.signatures.\*.category | string | | General |
action_result.data.\*.sandbox.\*.signatures.\*.description | string | | "www.test.com" |
action_result.data.\*.sandbox.\*.signatures.\*.identifier | string | | network-0 |
action_result.data.\*.sandbox.\*.signatures.\*.name | string | | Contacts domains |
action_result.data.\*.sandbox.\*.signatures.\*.origin | string | | Network Traffic |
action_result.data.\*.sandbox.\*.signatures.\*.relevance | numeric | | 1 |
action_result.data.\*.sandbox.\*.signatures.\*.threat_level | numeric | | 1 |
action_result.data.\*.sandbox.\*.signatures.\*.threat_level_human | string | | informative |
action_result.data.\*.sandbox.\*.signatures.\*.type | numeric | | 7 |
action_result.data.\*.sandbox.\*.submission_type | string | | page_url |
action_result.data.\*.sandbox.\*.submit_name | string | | whatami |
action_result.data.\*.sandbox.\*.submit_url | string | `url` | hxxps://test.com |
action_result.data.\*.sandbox.\*.threat_score | numeric | | 35 |
action_result.data.\*.sandbox.\*.verdict | string | | no specific threat |
action_result.data.\*.sandbox.\*.windows_version_bitness | numeric | | 64 |
action_result.data.\*.sandbox.\*.windows_version_edition | string | | Professional |
action_result.data.\*.sandbox.\*.windows_version_name | string | | Windows 10 |
action_result.data.\*.sandbox.\*.windows_version_version | string | | 10.0 (build 16299) |
action_result.data.\*.user_id | string | | 225bf5b4490348d9a1eacddc61501c09 |
action_result.data.\*.user_name | string | | Test user |
action_result.data.\*.user_tags | string | | test_tag1 |
action_result.data.\*.user_uuid | string | | b6330292-28e6-4198-994d-96f327c5b5bd |
action_result.data.\*.verdict | string | | no specific threat |
action_result.summary.total_reports | numeric | | 5 |
action_result.summary.verdict | string | | suspicious |
action_result.message | string | | Verdict: no specific threat, Total reports: 1 Total reports: 6 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'check status'

To check detonation status of the provided resource id

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**resource_id** | required | Id of the resource | string | `crowdstrike resource id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.resource_id | string | `crowdstrike resource id` | 3061c7ff3b634e22b38274d4b586558e_48004b5623af49ce9442d4bafd8e7b3d |
action_result.data | string | | |
action_result.data.\*.cid | string | | 3061c7ff3b634e22b38274d4b586558e |
action_result.data.\*.created_timestamp | string | `date` | 2021-05-15T13:12:02Z |
action_result.data.\*.id | string | `crowdstrike resource id` | 3061c7ff3b634e22b38274d4b586558e_48004b5623af49ce9442d4bafd8e7b3d |
action_result.data.\*.origin | string | | uiproxy |
action_result.data.\*.sandbox.\*.action_script | string | | default |
action_result.data.\*.sandbox.\*.command_line | string | | taskkill /IM * |
action_result.data.\*.sandbox.\*.enable_tor | boolean | | True |
action_result.data.\*.sandbox.\*.environment_id | numeric | | 160 |
action_result.data.\*.sandbox.\*.network_settings | string | | default |
action_result.data.\*.sandbox.\*.sha256 | string | `sha256` | 70641a2ef9a116fa7f5b1376654657926a91a2bed913837c62f5598c77a3e191 |
action_result.data.\*.sandbox.\*.submit_name | string | | example.csv |
action_result.data.\*.sandbox.\*.url | string | `url` | hxxps://www.test.com |
action_result.data.\*.state | string | | success |
action_result.data.\*.user_id | string | | 225bf5b4490348d9a1eacddc61501c09 |
action_result.data.\*.user_name | string | | test_user |
action_result.data.\*.user_uuid | string | | b6330292-28e6-4198-994d-96f327c5b5bd |
action_result.summary.state | string | | success |
action_result.message | string | | State: success |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get device scroll'

Search for hosts in your environment by platform, hostname, IP, and other criteria with continuous pagination capability (based on offset pointer which expires after 2 minutes with no maximum limit)

Type: **investigate** \
Read only: **True**

More info can be found at <a href='https://assets.falcon.crowdstrike.com/support/api/swagger.html#/hosts/QueryDevicesByFilterScroll' target='_blank'>here</a>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**offset** | optional | The offset to page from, for the next result set | string | |
**limit** | optional | The maximum records to return. [1-5000] | numeric | |
**sort** | optional | The property to sort by (e.g. status.desc or hostname.asc) | string | |
**filter** | optional | The offset to page from, for the next result set | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.filter | string | | platform_name:'windows' |
action_result.parameter.limit | numeric | | 120 |
action_result.parameter.offset | string | | |
action_result.parameter.sort | string | | status.desc |
action_result.data.\*.errors.\*.code | string | | |
action_result.data.\*.errors.\*.id | string | | |
action_result.data.\*.errors.\*.message | string | | |
action_result.data.\*.meta.pagination.expires_at | numeric | | 1632462683095273200 |
action_result.data.\*.meta.pagination.limit | string | | |
action_result.data.\*.meta.pagination.offset | string | | |
action_result.data.\*.meta.pagination.total | numeric | | 2 |
action_result.data.\*.meta.powered_by | string | | device-api |
action_result.data.\*.meta.query_time | numeric | | 0.004875208 |
action_result.data.\*.meta.trace_id | string | | 008a2081-1ad7-4e80-a2cc-0acc1562302b |
action_result.data.\*.resources | string | `crowdstrike device id` | 12e75112bdc44ac7a60b5ad1d2765303 |
action_result.summary | string | | |
action_result.message | string | | Device scroll fetched successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get zta data'

Get Zero Trust Assessment data for one or more hosts by providing agent IDs (AID)

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**agent_id** | required | Agent ID to get zero trust assessment data about. Comma-separated list allowed | string | `crowdstrike device id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.agent_id | string | `crowdstrike device id` | 95969e1abbea43bdaf6cc50c9b4aec2e,46592f3d661a469eb2503d72a29afd3a |
action_result.data.\*.aid | string | `crowdstrike device id` | 95969e1abbea43bdaf6cc50c9b4aec2e |
action_result.data.\*.assessment.os | numeric | | 38 |
action_result.data.\*.assessment.overall | numeric | | 32 |
action_result.data.\*.assessment.sensor_config | numeric | | 29 |
action_result.data.\*.assessment.version | string | | 3.3.0 |
action_result.data.\*.assessment_items.os_signals.\*.criteria | string | | Kernel Mode Code Integrity: enabled |
action_result.data.\*.assessment_items.os_signals.\*.group_name | string | | Windows 10 |
action_result.data.\*.assessment_items.os_signals.\*.meets_criteria | string | | no |
action_result.data.\*.assessment_items.os_signals.\*.signal_id | string | | windows_os_build |
action_result.data.\*.assessment_items.os_signals.\*.signal_name | string | | Windows OS Build |
action_result.data.\*.assessment_items.sensor_signals.\*.criteria | string | | Spotlight: enabled |
action_result.data.\*.assessment_items.sensor_signals.\*.group_name | string | | Sensor |
action_result.data.\*.assessment_items.sensor_signals.\*.meets_criteria | string | | no |
action_result.data.\*.assessment_items.sensor_signals.\*.signal_id | string | | spotlight_enabled |
action_result.data.\*.assessment_items.sensor_signals.\*.signal_name | string | | Spotlight |
action_result.data.\*.cid | string | `crowdstrike customer id` | 3061c7ff3b634e22b38274d4b586558e |
action_result.data.\*.event_platform | string | | Win |
action_result.data.\*.modified_time | string | | 2022-03-21T23:07:13Z |
action_result.data.\*.product_type_desc | string | | Server |
action_result.data.\*.sensor_file_status | string | | not deployed |
action_result.data.\*.system_serial_number | string | | VMware-42 2a 23 c9 7f 05 df a5-23 51 df 2c 02 ce 36 fb |
action_result.summary | string | | |
action_result.message | string | | Zero Trust Assessment data fetched successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create ioa rule group'

Create an empty IOA Rule Group

Type: **contain** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** | required | Name of the new Rule Group | string | |
**description** | required | Longer description for the new Rule Group | string | |
**platform** | required | Platform that this Rule Group applies to | string | |
**enabled** | optional | Enable the new Rule Group immediately upon creation | boolean | |
**policy_id** | optional | Prevention Policy ID to assign the new Rule Group to | string | `crowdstrike prevention policy id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.name | string | | my_rule_group |
action_result.parameter.description | string | | Custom rule group |
action_result.parameter.platform | string | | windows mac linux |
action_result.parameter.enabled | boolean | | True False |
action_result.parameter.policy_id | string | `crowdstrike prevention policy id` | 2018f9894359493cb756bfa7dd3357a6 |
action_result.data.\*.errors | string | | |
action_result.data.\*.meta.powered_by | string | | empower-api |
action_result.data.\*.meta.query_time | numeric | | 5.917429897 |
action_result.data.\*.meta.trace_id | string | | 6b7c63e1-0ebd-4121-90f3-cd53451be245 |
action_result.data.\*.resources.\*.id | string | `crowdstrike ioa rule group id` | 3263801f7612424ba923f4e6e4bfe2f2 |
action_result.data.\*.resources.\*.customer_id | string | `crowdstrike customer id` | 4061c7ff3b634e22b38274d4b586554r |
action_result.data.\*.resources.\*.enabled | boolean | | True False |
action_result.data.\*.resources.\*.name | string | | my_rule_group |
action_result.data.\*.resources.\*.description | string | | Custom rule group |
action_result.data.\*.resources.\*.platform | string | | windows mac linux |
action_result.data.\*.resources.\*.deleted | boolean | | True False |
action_result.data.\*.resources.\*.rule_ids.\* | string | `crowdstrike ioa rule id` | 6 |
action_result.data.\*.resources.\*.comment | string | | Updated description |
action_result.data.\*.resources.\*.version | numeric | | 1 |
action_result.data.\*.resources.\*.created_by | string | `crowdstrike user id` | 65f616497d0d40d4b6e7a68389323605 |
action_result.data.\*.resources.\*.created_on | string | | 2024-01-25T19:17:02.117884262Z |
action_result.data.\*.resources.\*.modified_by | string | `crowdstrike user id` | 65f616497d0d40d4b6e7a68389323605 |
action_result.data.\*.resources.\*.modified_on | string | | 2024-01-25T19:17:02.117884262Z |
action_result.data.\*.resources.\*.committed_on | string | | 0001-01-01T00:00:00Z |
action_result.data.\*.resources.\*.assigned_policy_ids.\* | string | `crowdstrike prevention policy id` | 2018f9894359493cb756bfa7dd3357a6 |
action_result.summary.rule_group_id | string | | |
action_result.message | string | | Rule Group created successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update ioa rule group'

Modify an existing IOA Rule Group

Type: **contain** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | Rule Group ID | string | `crowdstrike ioa rule group id` |
**version** | required | Latest version of this Rule Group | numeric | |
**name** | required | Name of the Rule Group | string | |
**description** | required | Longer description for the Rule Group | string | |
**enabled** | optional | Enable or disable the Rule Group | boolean | |
**comment** | required | Comment for the audit log | string | |
**assign_policy_id** | optional | Prevention Policy ID to assign the Rule Group to | string | `crowdstrike prevention policy id` |
**remove_policy_id** | optional | Prevention Policy ID to remove the Rule Group from | string | `crowdstrike prevention policy id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.id | string | `crowdstrike ioa rule group id` | 3263801f7612424ba923f4e6e4bfe2f2 |
action_result.parameter.version | numeric | | 1 |
action_result.parameter.name | string | | my_rule_group |
action_result.parameter.description | string | | Custom rule group |
action_result.parameter.enabled | boolean | | True False |
action_result.parameter.comment | boolean | | Updated rule description |
action_result.parameter.assign_policy_id | string | `crowdstrike prevention policy id` | 2018f9894359493cb756bfa7dd3357a6 |
action_result.parameter.remove_policy_id | string | `crowdstrike prevention policy id` | 2018f9894359493cb756bfa7dd3357a6 |
action_result.data.\*.errors | string | | |
action_result.data.\*.meta.powered_by | string | | empower-api |
action_result.data.\*.meta.query_time | numeric | | 5.917429897 |
action_result.data.\*.meta.trace_id | string | | 6b7c63e1-0ebd-4121-90f3-cd53451be245 |
action_result.data.\*.resources.\*.id | string | `crowdstrike ioa rule group id` | 3263801f7612424ba923f4e6e4bfe2f2 |
action_result.data.\*.resources.\*.customer_id | string | `crowdstrike customer id` | 4061c7ff3b634e22b38274d4b586554r |
action_result.data.\*.resources.\*.enabled | boolean | | True False |
action_result.data.\*.resources.\*.name | string | | my_rule_group |
action_result.data.\*.resources.\*.description | string | | Custom rule group |
action_result.data.\*.resources.\*.platform | string | | windows mac linux |
action_result.data.\*.resources.\*.deleted | boolean | | True False |
action_result.data.\*.resources.\*.rule_ids.\* | string | `crowdstrike ioa rule id` | 6 |
action_result.data.\*.resources.\*.comment | string | | Updated description |
action_result.data.\*.resources.\*.version | numeric | | 1 |
action_result.data.\*.resources.\*.created_by | string | `crowdstrike user id` | 65f616497d0d40d4b6e7a68389323605 |
action_result.data.\*.resources.\*.created_on | string | | 2024-01-25T19:17:02.117884262Z |
action_result.data.\*.resources.\*.modified_by | string | `crowdstrike user id` | 65f616497d0d40d4b6e7a68389323605 |
action_result.data.\*.resources.\*.modified_on | string | | 2024-01-25T19:17:02.117884262Z |
action_result.data.\*.resources.\*.committed_on | string | | 0001-01-01T00:00:00Z |
action_result.data.\*.resources.\*.assigned_policy_ids.\* | string | `crowdstrike prevention policy id` | 2018f9894359493cb756bfa7dd3357a6 |
action_result.data.\*.resources.\*.removed_policy_ids.\* | string | `crowdstrike prevention policy id` | 2018f9894359493cb756bfa7dd3357a6 |
action_result.summary.rule_group_id | string | | |
action_result.message | string | | Rule Group updated successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'delete ioa rule group'

Delete an existing IOA Rule Group

Type: **contain** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | required | Rule Group ID | string | `crowdstrike ioa rule group id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.id | string | `crowdstrike ioa rule group id` | 3263801f7612424ba923f4e6e4bfe2f2 |
action_result.data.\*.errors | string | | |
action_result.data.\*.meta.powered_by | string | | empower-api |
action_result.data.\*.meta.query_time | numeric | | 5.917429897 |
action_result.data.\*.meta.trace_id | string | | 6b7c63e1-0ebd-4121-90f3-cd53451be245 |
action_result.data.\*.meta.writes.resources_affected | numeric | | 1 |
action_result.summary.resources_affected | string | | |
action_result.message | string | | Deleted 1 rule groups |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list ioa platforms'

List valid platforms for IOA Rule Groups

Type: **investigate** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data.\*.errors | string | | |
action_result.data.\*.meta.powered_by | string | | empower-api |
action_result.data.\*.meta.query_time | numeric | | 5.917429897 |
action_result.data.\*.meta.trace_id | string | | 6b7c63e1-0ebd-4121-90f3-cd53451be245 |
action_result.data.\*.resources.\* | string | | windows mac linux |
action_result.summary.result_count | numeric | | |
action_result.message | string | | Found 3 rule groups |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list ioa rule groups'

List IOA Rule Groups

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**fql_query** | optional | FQL query to filter rule groups | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.fql_query | string | | enabled: true + platform: 'mac' |
action_result.data.\*.errors | string | | |
action_result.data.\*.meta.powered_by | string | | empower-api |
action_result.data.\*.meta.query_time | numeric | | 5.917429897 |
action_result.data.\*.meta.trace_id | string | | 6b7c63e1-0ebd-4121-90f3-cd53451be245 |
action_result.data.\*.resources.\*.instance_id | string | `crowdstrike ioa rule id` | 1 |
action_result.data.\*.resources.\*.customer_id | string | `crowdstrike customer id` | 4061c7ff3b634e22b38274d4b586554r |
action_result.data.\*.resources.\*.ruletype_id | string | | 5 |
action_result.data.\*.resources.\*.ruletype_name | string | | Process Creation |
action_result.data.\*.resources.\*.comment | string | | Created rule |
action_result.data.\*.resources.\*.enabled | boolean | | True False |
action_result.data.\*.resources.\*.deleted | boolean | | True False |
action_result.data.\*.resources.\*.magic_cookie | numeric | | 2 |
action_result.data.\*.resources.\*.rulegroup_id | string | `crowdstrike ioa rule group id` | 83f596d2f8c04f36ad39182311e90e3a |
action_result.data.\*.resources.\*.version_ids.\* | string | | 1 |
action_result.data.\*.resources.\*.instance_version | numeric | | 1 |
action_result.data.\*.resources.\*.name | string | | BugRule |
action_result.data.\*.resources.\*.description | string | | Stops the bug |
action_result.data.\*.resources.\*.pattern_id | string | | 41005 |
action_result.data.\*.resources.\*.pattern_severity | string | | critical |
action_result.data.\*.resources.\*.action_label | string | | Block Execution |
action_result.data.\*.resources.\*.disposition_id | numeric | | 30 |
action_result.data.\*.resources.\*.field_values.\*.name | string | | GrandparentImageFilename |
action_result.data.\*.resources.\*.field_values.\*.value | string | | (?i).+bug.exe |
action_result.data.\*.resources.\*.field_values.\*.label | string | | Grandparent Image Filename |
action_result.data.\*.resources.\*.field_values.\*.type | string | | excludable |
action_result.data.\*.resources.\*.field_values.\*.values.\*.label | string | | include |
action_result.data.\*.resources.\*.field_values.\*.values.\*.value | string | | .+bug.exe |
action_result.data.\*.resources.\*.field_values.\*.final_value | string | | (?i).+bug.exe |
action_result.summary.result_count | numeric | | |
action_result.message | string | | Found 3 rule groups |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list ioa severities'

List valid severity values for IOA rules

Type: **investigate** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data.\*.errors | string | | |
action_result.data.\*.meta.powered_by | string | | empower-api |
action_result.data.\*.meta.query_time | numeric | | 5.917429897 |
action_result.data.\*.meta.trace_id | string | | 6b7c63e1-0ebd-4121-90f3-cd53451be245 |
action_result.data.\*.resources.\* | string | | informational low medium high critical |
action_result.summary.result_count | numeric | | |
action_result.message | string | | Found 3 supported platforms |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list ioa types'

List valid types of IOA rules

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**platform** | optional | Show only IOA types supported by the given platform | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.platform | string | | mac linux windows |
action_result.data.\*.errors | string | | |
action_result.data.\*.meta.powered_by | string | | empower-api |
action_result.data.\*.meta.query_time | numeric | | 5.917429897 |
action_result.data.\*.meta.trace_id | string | | 6b7c63e1-0ebd-4121-90f3-cd53451be245 |
action_result.data.\*.resources.\*.id | string | | 1 |
action_result.data.\*.resources.\*.name | string | | Process Creation |
action_result.data.\*.resources.\*.channel | numeric | | 501 |
action_result.data.\*.resources.\*.long_desc | string | | Mac basic process custom template. Triggered off of CreateProcessPreventionQueryMac. |
action_result.data.\*.resources.\*.released | boolean | | True False |
action_result.data.\*.resources.\*.fields.\*.name | string | | GrandparentImageFilename |
action_result.data.\*.resources.\*.fields.\*.label | string | | Grandparent Image Filename |
action_result.data.\*.resources.\*.fields.\*.type | string | | excludable |
action_result.data.\*.resources.\*.fields.\*.type.\*.label | string | | include |
action_result.data.\*.resources.\*.fields.\*.type.\*.value | string | | |
action_result.data.\*.resources.\*.disposition_map.\*.id | numeric | | 10 |
action_result.data.\*.resources.\*.disposition_map.\*.label | string | | Monitor |
action_result.data.\*.resources.\*.fields_pretty | string | | {} |
action_result.summary.result_count | numeric | | |
action_result.message | string | | Found 3 rule types |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'create ioa rule'

Create a new IOA Rule

Type: **contain** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**rule_group_id** | required | Rule Group ID in which to create this rule | string | `crowdstrike ioa rule group id` |
**name** | required | Rule name | string | |
**description** | required | Rule description | string | |
**severity** | required | Rule severity (run the "list ioa severities" action to find valid severities) | string | |
**rule_type_id** | required | Rule type to create (run the "list ioa types" action to find valid types of rules and their IDs and parameters) | numeric | |
**disposition_id** | required | The action that the rule should take when triggered (valid dispositions can be found in the "list ioa types" output) | numeric | |
**field_values** | required | JSON list of parameters to pass to the new rule (valid fields can be found in the "list ioa types" output) | string | |
**comment** | optional | Comment for the audit log (optional) | string | |
**enabled** | optional | Enable this rule immediately | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.rule_group_id | string | `crowdstrike ioa rule group id` | 83f596d2f8c04f36ad39182311e90e3a |
action_result.parameter.name | string | | BugRule |
action_result.parameter.description | string | | Stops the bug |
action_result.parameter.severity | string | | critical |
action_result.parameter.rule_type_id | numeric | | 5 |
action_result.parameter.disposition_id | numeric | | 30 |
action_result.parameter.field_values | string | | {"label":"Grandparent Image Filename","name":"GrandparentImageFilename","type":"excludable","values":[{"label":"include","value":".+bug.exe"}]}\] |
action_result.parameter.comment | string | | Example comment |
action_result.parameter.enabled | boolean | | True False |
action_result.data.\*.errors | string | | |
action_result.data.\*.meta.powered_by | string | | empower-api |
action_result.data.\*.meta.query_time | numeric | | 5.917429897 |
action_result.data.\*.meta.trace_id | string | | 6b7c63e1-0ebd-4121-90f3-cd53451be245 |
action_result.data.\*.resources.\*.instance_id | string | `crowdstrike ioa rule id` | 1 |
action_result.data.\*.resources.\*.customer_id | string | `crowdstrike customer id` | 4061c7ff3b634e22b38274d4b586554r |
action_result.data.\*.resources.\*.ruletype_id | string | | 5 |
action_result.data.\*.resources.\*.ruletype_name | string | | Process Creation |
action_result.data.\*.resources.\*.comment | string | | Created rule |
action_result.data.\*.resources.\*.enabled | boolean | | True False |
action_result.data.\*.resources.\*.deleted | boolean | | True False |
action_result.data.\*.resources.\*.magic_cookie | numeric | | 2 |
action_result.data.\*.resources.\*.rulegroup_id | string | `crowdstrike ioa rule group id` | 83f596d2f8c04f36ad39182311e90e3a |
action_result.data.\*.resources.\*.version_ids.\* | string | | 1 |
action_result.data.\*.resources.\*.instance_version | numeric | | 1 |
action_result.data.\*.resources.\*.name | string | | BugRule |
action_result.data.\*.resources.\*.description | string | | Stops the bug |
action_result.data.\*.resources.\*.pattern_id | string | | 41005 |
action_result.data.\*.resources.\*.pattern_severity | string | | critical |
action_result.data.\*.resources.\*.action_label | string | | Block Execution |
action_result.data.\*.resources.\*.disposition_id | numeric | | 30 |
action_result.data.\*.resources.\*.field_values.\*.name | string | | GrandparentImageFilename |
action_result.data.\*.resources.\*.field_values.\*.value | string | | (?i).+bug.exe |
action_result.data.\*.resources.\*.field_values.\*.label | string | | Grandparent Image Filename |
action_result.data.\*.resources.\*.field_values.\*.type | string | | excludable |
action_result.data.\*.resources.\*.field_values.\*.values.\*.label | string | | include |
action_result.data.\*.resources.\*.field_values.\*.values.\*.value | string | | .+bug.exe |
action_result.data.\*.resources.\*.field_values.\*.final_value | string | | (?i).+bug.exe |
action_result.summary.rule_group_id | string | `crowdstrike ioa rule group id` | 83f596d2f8c04f36ad39182311e90e3a |
action_result.summary.rule_id | string | `crowdstrike ioa rule id` | 1 |
action_result.message | string | | Rule created successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update ioa rule'

Update an existing IOA Rule

Type: **contain** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**rule_group_id** | required | Rule Group ID containing the rule | string | `crowdstrike ioa rule group id` |
**rule_group_version** | required | Latest version of Rule Group | numeric | |
**rule_id** | required | Rule ID to update | string | `crowdstrike ioa rule id` |
**rule_version** | required | Latest version of Rule | numeric | |
**name** | required | Rule name | string | |
**description** | required | Rule description | string | |
**severity** | required | Rule severity (run the "list ioa severities" action to find valid severities) | string | |
**disposition_id** | required | The action that the rule should take when triggered (valid dispositions can be found in the "list ioa types" output) | numeric | |
**field_values** | required | JSON list of parameters to pass to the new rule (valid fields can be found in the "list ioa types" output) | string | |
**comment** | optional | Comment for the audit log (optional) | string | |
**enabled** | optional | Enable this rule | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.rule_group_id | string | `crowdstrike ioa rule group id` | 83f596d2f8c04f36ad39182311e90e3a |
action_result.parameter.rule_group_version | numeric | | 2 |
action_result.parameter.rule_id | string | `crowdstrike ioa rule id` | 1 |
action_result.parameter.rule_version | numeric | | 1 |
action_result.parameter.name | string | | BugRule |
action_result.parameter.description | string | | Stops the bug |
action_result.parameter.severity | string | | critical |
action_result.parameter.disposition_id | numeric | | 30 |
action_result.parameter.field_values | string | | {"label":"Grandparent Image Filename","name":"GrandparentImageFilename","type":"excludable","values":[{"label":"include","value":".+bug.exe"}]}\] |
action_result.parameter.comment | string | | Example comment |
action_result.parameter.enabled | boolean | | True False |
action_result.data.\*.errors | string | | |
action_result.data.\*.meta.powered_by | string | | empower-api |
action_result.data.\*.meta.query_time | numeric | | 5.917429897 |
action_result.data.\*.meta.trace_id | string | | 6b7c63e1-0ebd-4121-90f3-cd53451be245 |
action_result.data.\*.resources.\*.id | string | `crowdstrike ioa rule group id` | 83f596d2f8c04f36ad39182311e90e3a |
action_result.data.\*.resources.\*.name | string | | Bug Rule Group |
action_result.data.\*.resources.\*.rules.\*.name | string | | BugRule |
action_result.data.\*.resources.\*.rules.\*.comment | string | | Updated the thing |
action_result.data.\*.resources.\*.rules.\*.deleted | boolean | | True False |
action_result.data.\*.resources.\*.rules.\*.enabled | boolean | | True False |
action_result.data.\*.resources.\*.rules.\*.created_by | string | `crowdstrike unique user id` | bb777249-c782-4434-b57a-f15ac742926c |
action_result.data.\*.resources.\*.rules.\*.created_on | string | `date` | 2021-09-15T09:52:27.651770437Z |
action_result.data.\*.resources.\*.rules.\*.pattern_id | string | | 41007 |
action_result.data.\*.resources.\*.rules.\*.customer_id | string | `crowdstrike customer id` | 4061c7ff3b634e22b38274d4b586554r |
action_result.data.\*.resources.\*.rules.\*.description | string | | Stops the bug |
action_result.data.\*.resources.\*.rules.\*.modified_by | string | `crowdstrike unique user id` | bb777249-c782-4434-b57a-f15ac742926c |
action_result.data.\*.resources.\*.rules.\*.modified_on | string | `date` | 2021-09-15T09:52:27.651770437Z |
action_result.data.\*.resources.\*.rules.\*.ruletype_id | string | | |
action_result.data.\*.resource.\*.rules.\*.version_ids.\* | string | | |
action_result.data.\*.resource.\*.rules.\*.action_label | string | | |
action_result.data.\*.resources.\*.rules.\*.committed_on | string | `date` | 2021-09-15T09:52:27.651770437Z |
action_result.data.\*.resources.\*.rules.\*.field_values.\*.name | string | | GrandparentImageFilename |
action_result.data.\*.resources.\*.rules.\*.field_values.\*.value | string | | (?i).+bug.exe |
action_result.data.\*.resources.\*.rules.\*.field_values.\*.label | string | | Grandparent Image Filename |
action_result.data.\*.resources.\*.rules.\*.field_values.\*.type | string | | excludable |
action_result.data.\*.resources.\*.rules.\*.field_values.\*.values.\*.label | string | | include |
action_result.data.\*.resources.\*.rules.\*.field_values.\*.values.\*.value | string | | .+bug.exe |
action_result.data.\*.resources.\*.rules.\*.field_values.\*.final_value | string | | (?i).+bug.exe |
action_result.data.\*.resources.\*.rules.\*.magic_cookie | numeric | | 6 |
action_result.data.\*.resources.\*.rules.\*.rulegroup_id | string | `crowdstrike ioa rule group id` | |
action_result.data.\*.resources.\*.rules.\*.ruletype_name | string | | Process Creation |
action_result.data.\*.resources.\*.rules.\*.disposition_id | numeric | | 10 |
action_result.data.\*.resources.\*.rules.\*.instance_version | numeric | | 3 |
action_result.data.\*.resources.\*.rules.\*.pattern_severity | string | | medium |
action_result.data.\*.resources.\*.comment | string | | Created rule |
action_result.data.\*.resources.\*.enabled | boolean | | True False |
action_result.data.\*.resources.\*.deleted | boolean | | True False |
action_result.data.\*.resources.\*.version | numeric | | 2 |
action_result.data.\*.resources.\*.platform | string | | mac windows linux |
action_result.data.\*.resources.\*.rule_ids.\* | string | `crowdstrike ioa rule id` | 1 |
action_result.data.\*.resources.\*.created_by | string | `crowdstrike unique user id` | bb777249-c782-4434-b57a-f15ac742926c |
action_result.data.\*.resources.\*.created_on | string | `date` | 2021-09-15T09:52:27.651770437Z |
action_result.data.\*.resources.\*.customer_id | string | `crowdstrike customer id` | 4061c7ff3b634e22b38274d4b586554r |
action_result.data.\*.resources.\*.description | string | | Stops the bug |
action_result.data.\*.resources.\*.modified_by | string | `crowdstrike unique user id` | bb777249-c782-4434-b57a-f15ac742926c |
action_result.data.\*.resources.\*.modified_on | string | `date` | 2021-09-15T09:52:27.651770437Z |
action_result.data.\*.resources.\*.committed_on | string | `date` | 2021-09-15T09:52:27.651770437Z |
action_result.summary.rule_group_id | string | `crowdstrike ioa rule group id` | 83f596d2f8c04f36ad39182311e90e3a |
action_result.summary.rule_group_version | numeric | | 1 |
action_result.summary.rule_id | string | `crowdstrike ioa rule id` | 1 |
action_result.summary.rule_version | numeric | | 1 |
action_result.message | string | | Rule updated successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'delete ioa rule'

Delete an existing IOA Rule

Type: **contain** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**rule_group_id** | required | Rule Group ID containing the rule | string | `crowdstrike ioa rule group id` |
**rule_id** | required | Rule ID to delete | string | `crowdstrike ioa rule id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.rule_group_id | string | `crowdstrike ioa rule group id` | 83f596d2f8c04f36ad39182311e90e3a |
action_result.parameter.rule_id | string | `crowdstrike ioa rule id` | 1 |
action_result.data.\*.errors | string | | |
action_result.data.\*.meta.powered_by | string | | empower-api |
action_result.data.\*.meta.query_time | numeric | | 5.917429897 |
action_result.data.\*.meta.trace_id | string | | 6b7c63e1-0ebd-4121-90f3-cd53451be245 |
action_result.summary.resources_affected | string | | |
action_result.message | string | | Rule deleted successfully |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
