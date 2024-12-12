[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2019-2024 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Steps to create API clients and key

- In Falcon UI, Go to menubar on the left, From **Support and resources** section, Select **API clients and keys**.
- Click on **Create API client**.
- Add **Client name**, **Description(optional)** and [Scopes](#minimal-required-scopes-to-run-all-actions) (defined below).
- Click on **Create** to obtain the **Client ID** and **Client secret**.

## Minimal required scope(s) (Action wise)
| **Action**                                                  | **Required Scope(s)**          | **Read**             | **Write**            |
|-------------------------------------------------------------|--------------------------------|----------------------|----------------------|
| [test connectivity](#action-test-connectivity)              | Hosts                          | &check;              | &cross;              |
| [query device](#action-query-device)                        | Hosts                          | &check;              | &cross;              |
| [list groups](#action-list-groups)                          | Host Groups                    | &check;              | &cross;              |
| [quarantine device](#action-quarantine-device)              | Hosts                          | &check;              | &check;              |
| [unquarantine device](#action-unquarantine-device)          | Hosts                          | &check;              | &check;              |
| [assign hosts](#action-assign-hosts)                        | Hosts <br> Hosts Group         | &check; <br> &cross; | &cross; <br> &check; |
| [remove hosts](#action-remove-hosts)                        | Hosts <br> Hosts Group         | &check; <br> &cross; | &cross; <br> &check; |
| [create session](#action-create-session)                    | Real time response(RTR)        | &check;              | &cross;              |
| [delete session](#action-delete-session)                    | Real time response(RTR)        | &check;              | &cross;              |
| [list detections](#action-list-detections)                  | Detections                     | &check;              | &cross;              |
| [get detections details](#action-get-detections-details)    | Detections                     | &check;              | &cross;              |
| [update detections](#action-update-detections)              | Detections                     | &cross;              | &check;              |
| [list alerts](#action-list-alerts)                          | Alerts                         | &check;              | &cross;              |
| [list epp alerts](#action-list-epp-alerts)                  | Alerts                         | &check;              | &cross;              |
| [get epp details](#action-get-epp-details)                  | Alerts                         | &check;              | &cross;              |
| [update epp alerts](#action-update-epp-alerts)              | Alerts                         | &cross;              | &check;              |
| [resolve epp alerts](#action-resolve-epp-alerts)            | Alerts                         | &cross;              | &check;              |
| [list sessions](#action-list-sessions)                      | Real time response(RTR)        | &check;              | &cross;              |
| [run command](#action-run-command)                          | Real time response(RTR)        | &check;              | &cross;              |
| [run admin command](#action-run-admin-command)              | Real time response(admin)      | &cross;              | &check;              |
| [get command details](#action-get-command-details)          | Real time response(RTR)        | &cross;              | &check;              |
| [list session files](#action-list-session-files)            | Real time response(RTR)        | &cross;              | &check;              |
| [get incident behaviors](#action-get-incident-behaviors)    | Incidents                      | &check;              | &cross;              |
| [update incident](#action-update-incident)                  | Incidents                      | &cross;              | &check;              |
| [list users](#action-list-users)                            | User Management                | &check;              | &cross;              |
| [get user roles](#action-get-user-roles)                    | User Management                | &check;              | &cross;              |
| [list roles](#action-list-roles)                            | User Management                | &check;              | &cross;              |
| [get role](#action-get-role)                                | User Management                | &check;              | &cross;              |
| [list crowdscores](#action-list-crowdscores)                | Incidents                      | &check;              | &cross;              |
| [get incident details](#action-get-incident-details)        | Incidents                      | &check;              | &cross;              |
| [list incident behaviors](#action-list-incident-behaviors)  | Incidents                      | &check;              | &cross;              |
| [list incidents](#action-list-incidents)                    | Incidents                      | &check;              | &cross;              |
| [get session file](#action-get-session-file)                | Real time response(RTR)        | &cross;              | &check;              |
| [set status](#action-set-status)                            | Detections                     | &cross;              | &check;              |
| [get system info](#action-get-system-info)                  | Hosts                          | &check;              | &cross;              |
| [get process detail](#action-get-process-detail)            | IOCs(Indicators of Compromise) | &check;              | &cross;              |
| [hunt file](#action-hunt-file)                              | IOCs(Indicators of Compromise) | &check;              | &cross;              |
| [hunt domain](#action-hunt-domain)                          | IOCs(Indicators of Compromise) | &check;              | &cross;              |
| [hunt ip](#action-hunt-ip)                                  | IOCs(Indicators of Compromise) | &check;              | &cross;              |
| [upload put file](#action-upload-put-file)                  | Real time response             | &cross;              | &check;              |
| [get indicator](#action-get-indicator)                      | IOC Management                 | &check;              | &cross;              |
| [list custom indicators](#action-list-custom-indicators)    | IOC Management                 | &check;              | &cross;              |
| [list put files](#action-list-put-files)                    | Real time response(admin)      | &cross;              | &check;              |
| [on poll](#action-on-poll)                                  | Event Stream                   | &check;              | &cross;              |
| [list processes](#action-list-processes)                    | IOCs                           | &check;              | &cross;              |
| [upload indicator](#action-upload-indicator)                | IOC Management                | &cross;              | &check;              |
| [delete indicator](#action-delete-indicator)                | IOC Management                | &check;              | &check;              |
| [update indicator](#action-update-indicator)                | IOC Management                | &cross;              | &check;              |
| [file reputation](#action-file-reputation)                  | Sandbox(Falcon Intelligence)   | &check;              | &cross;              |
| [url reputation](#action-url-reputation)                    | Sandbox(Falcon Intelligence)   | &check;              | &cross;              |
| [download report](#action-download-report)                  | Sandbox(Falcon Intelligence)   | &check;              | &cross;              |
| [detonate file](#action-detonate-file)                      | Sandbox(Falcon Intelligence)   | &check;              | &cross;              |
| [detonate url](#action-detonate-url)                        | Sandbox(Falcon Intelligence)   | &check;              | &cross;              |
| [check status](#action-check-status)                        | Sandbox(Falcon Intelligence)   | &check;              | &cross;              |
| [get device scroll](#action-get-device-scroll)              | Hosts                          | &check;              | &cross;              |
| [get zta data](#action-get-zta-data)                        | Zero Trust Assessment          | &check;              | &cross;              |


## Preprocess Script

The user can add a script file in the configuration parameter \[ **Script with functions to
preprocess containers and artifacts** \]. The script must contain a function with the name
**preprocess_container** (to pre-process the containers and the artifacts) or else, it will throw an
error.

## App ID

-   Optionally, you can specify an **App ID** to be used with the Crowdstrike OAuth API used in the
    on poll action. If one isn't set, it will default to the asset ID.
-   It is recommended to have a unique **App ID** for each connection to the Crowdstrike OAuth API.
    That is to say, if you are planning on having multiple assets using the Crowdstrike OAuth API at
    once, you should give them unique App IDs.

## On Poll

-   Common points for both manual and scheduled interval polling
    -   Default parameters of the On Poll action are ignored in the app. i.e. start_time, end_time,
        container_count, artifact_count
    -   The app will fetch all the events based on the value specified in the configuration
        parameters \[Maximum events to get while POLL NOW\] (default 2000 if not specified) and
        \[Maximum events to get while scheduled and interval polling\] (default 10,000 if not
        specified). For ingestion, the events are fetched after filtering them based on the event
        types - **DetectionSummaryEvent** and **EppDetectionSummaryEvent**. The app will exit from the polling cycle in the
        below-mentioned 2 cases whichever is earlier.
        -   If the total events fetched equals the value provided in the \[Maximum
            events to get while POLL NOW\] (for manual polling) or \[Maximum events to get while
            scheduled and interval polling\] (for scheduled | interval polling) parameters
        -   If the total number of continuous blank lines encountered while streaming the data
            equals the value provided in the \[Maximum allowed continuous blank lines\] (default 50
            if not specified) asset configuration parameter
    -   The default behavior of the app is that each event will be placed in its container. By
        checking the configuration parameter \[Merge containers for Hostname and Eventname\] as well
        as specifying an interval in the configuration parameter \[Merge same containers within
        specified seconds\], all events which are of the same type and on the same host will be put
        into one container, as long as the time between those two events is less than the interval.
    -   The \[Maximum allowed continuous blank lines\] asset configuration parameter will be used to
        indicate the allowed number of continuous blank lines while fetching events. For example, if some events exist after 100 continuous blank lines and you've
        set the \[Maximum allowed continues blank lines\] parameter value to 500, it will keep on
        ingesting all events until the code gets 500 continuous blank lines
        and hence, it will be able to cover the events successfully even after the
        100 blank lines. If you set it to 50, it will break after the 50th blank line is
        encountered. Hence, it won't be able to ingest the events which exist after the 100
        continuous blank lines because the code considers that after the configured value in the
        \[Maximum allowed continuous blank lines\] configuration parameter (here 50), there is no
        data available.
-   Manual Polling
    -   During manual poll now, the app starts from the first event that it can query up to the
        value configured in the configuration parameter \[Maximum events to get while POLL NOW\] and
        creates artifacts for all the fetched DetectionSummaryEvents. The last queried event's
        offset ID will not be remembered in Manual POLL NOW and it fetches everything every time
        from the beginning.
-   Scheduled | Interval Polling
    -   During scheduled | interval polling, the app starts from the first event that it can query
        up to the value configured in the configuration parameter \[Maximum events to get while
        scheduled and interval polling\] and creates artifacts for all the fetched
        DetectionSummaryEvents. Then, it remembers the last event's offset ID and stores it in the
        state file against the key \[last_offset_id\]. In the next scheduled poll run, it will start
        from the stored offset ID in the state file and will fetch the maximum events as configured
        in the \[Maximum events to get while scheduled and interval polling\] parameter.

The **DetectionSummaryEvent** is parsed to extract the following values into an Artifact.  

| **Artifact Field** | **Event Field** |
|--------------------|-----------------|
| cef.sourceUserName | UserName        |
| cef.fileName       | FileName        |
| cef.filePath       | FilePath        |
| cef.sourceHostName | ComputerName    |
| cef.sourceNtDomain | MachineDomain   |
| cef.hash           | MD5String       |
| cef.hash           | SHA1String      |
| cef.hash           | SHA256STring    |
| cef.cs1            | cmdLine         |

The **EppDetectionSummaryEvent** is parsed to extract the following values into an Artifact.  

| **Artifact Field** | **Event Field**  |
|--------------------|------------------|
| cef.sourceUserName | UserName         |
| cef.fileName       | FileName         |
| cef.filePath       | FilePath         |
| cef.sourceHostName | Hostname         |
| cef.sourceNtDomain | LogonDomain      |
| cef.hash           | MD5String        |
| cef.hash           | SHA1String       |
| cef.hash           | SHA256String     |
| cef.cs1            | cmdLine          |

The app also parses the following **sub-events** into their own artifacts.  

-   Documents Accessed
-   Executables Written
-   Network Access
-   Scan Result
-   Quarantine Files
-   DNS Requests

Each of the sub-events has a CEF key called **parentSdi** which stands for Parent Source Data
Identifier. This is the value of the SDI of the main event that the sub-events were generated from.

## Falcon X Sandbox Actions

**This is different from Falcon Sandbox.**

-   **Action -** File Reputation, Url reputation

<!-- -->

-   Report of the resource will be fetched if it has been detonated previously on the CrowdStrike
    Server otherwise no data found message will be displayed to the user.

<!-- -->

-   **Action -** Download Report

<!-- -->

-   This action will download the resource report based on the provided artifact ID. Currently, we
    support the following Strict IOC CSV, Strict IOC JSON, Strict IOC STIX2.1, Strict IOC MAEC5.0,
    Broad IOC CSV, Broad IOC JSON, Broad IOC STIX2.1, Broad IOC MAEC5.0, Memory Strings, Icon,
    Screenshot artifact IDs.

<!-- -->

-   **Action -** Detonate File

<!-- -->

-   This action will upload the given file to the CrowdStrike sandbox and will submit it for
    analysis with the entered environment details. If the report of the given file is already
    present with the same environment, it will fetch the result and the file won't be submitted
    again.
-   If the analysis is in progress and reaches the time entered in the detonate_timeout parameter,
    then this action will return the resource_id of the submitted file using which the submission
    status can be checked.
-   If the submitted file will be analyzed within the entered time in the detonate_timeout
    parameter, its report will be fetched. Currently, these file types are supported .exe, .scr,
    .pif, .dll, .com, .cpl, etc., .doc, .docx, .ppt, .pps, .pptx, .ppsx, .xls, .xlsx, .rtf, .pub,
    .pdf, Executable JAR, .sct, .lnk, .chm, .hta, .wsf, .js, .vbs, .vbe, .swf, pl, .ps1, .psd1,
    .psm1, .svg, .py, Linux ELF executables, .eml, .msg.

<!-- -->

-   **Action -** Detonate Url

<!-- -->

-   This action will submit the given URL for analysis with the entered environment details. If the
    report of the given URL is already present with the same environment, it will fetch the result
    and the url won't be submitted again.
-   If the analysis is in progress and it reaches the time entered in the detonate_timeout
    parameter, then this action will return the resource_id of the submitted URL using which the
    status of the submission can be checked. If the analysis status is running then do not re-run
    the detonate URL action, otherwise, the URL will be again submitted for the analysis.
-   If the submitted URL will be analyzed within the entered time in the detonate_timeout parameter,
    its report will be fetched. Currently, 3 domains of URL are supported http, https, and ftp.

<!-- -->

-   **Action -** Check Status

<!-- -->

-   This action will return the status of the given resource_id in case of timeout in detonate file
    and detonate URL actions.

## Notes


-   **Action -** List Alerts

<!-- -->

-   The filter parameter values follow the [FQL
    Syntax](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-fql-reference)
    .
-   The sort parameter value has to be provided in the format property_name.asc for ascending and
    property_name.desc for descending order.

-   The `include_hidden` parameter has been added to the action as it's behavior in the API has changed. In the
    prior API version, the default behavior of the `include_hidden` parameter was either not supported or defaulted
    to `false`. The latest version of the API now defaults `include_hidden` to `true` if it is not included in
    the API call. Therefore, we have included this parameter in the action configuration and set it to `false` by
    default in order to keep the action behavior consistent with the previous app version. Hidden alerts can be
    identified by the `show_in_ui` field of an alert object.

    If you experience any `list alerts` action failures in an existing playbook that passed in the previous version
    of the app, you may need to edit the action in the playbook and then save. This will then add the `include_hidden`
    field to the playbook action.

-   **Action -** List Groups

<!-- -->

-   The filter parameter values follow the [FQL
    Syntax](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-fql-reference)
    .
-   The sort parameter value has to be provided in the format property_name.asc for ascending and
    property_name.desc for descending order.

  

-   **Action -** Query Device

<!-- -->

-   Both the filter and sort parameters follow the same concepts as mentioned above for the list
    groups action.

  

-   **Action -** Assign Hosts, Remove Hosts, Quarantine Device, and Unquarantine Device

<!-- -->

-   The devices will be fetched based on the values provided in both the device_id and hostname
    parameters.
-   If an incorrect value is provided in both the device_id and hostname parameters each, then, the
    action will fail with an appropriate error message.

<!-- -->

-   **Action -** List Session Files, Get Session File

<!-- -->

-   To add \[session id\] to the action parameters of these actions, a session with the Create
    Session action needs to be created. Also, the user can delete the session using the Delete
    Session action.

  

-   **Action -** Run Command

<!-- -->

-   This action can run the below-mentioned RTR commands on the host:
    -   cat
    -   cd
    -   env
    -   eventlog
    -   filehash
    -   getsid
    -   ipconfig
    -   ls
    -   mount
    -   netstat
    -   ps
    -   reg query
-   To add \[session id\] to the action parameters of these actions, a session with the Create
    Session action needs to be created. Also, the user can delete the session using the Delete
    Session action.
-   Example action run: If "cd C:\\some_directory" command needs to be run using this action, valid
    \[device_id\] and \[session_id\] parameters should be provided by the user. The user should
    select "cd" from the \[command\] dropdown parameter and provide "C:\\some_directory" input in
    the \[data\] parameter.

<!-- -->

-   **Action -** Run Admin Command

<!-- -->

-   This action can run the below-mentioned RTR administrator commands on the host:
    -   cat
    -   cd
    -   cp
    -   encrypt
    -   env
    -   eventlog
    -   filehash
    -   get
    -   getsid
    -   ipconfig
    -   kill
    -   ls
    -   map
    -   memdump
    -   mkdir
    -   mount
    -   mv
    -   netstat
    -   ps
    -   put
    -   reg query
    -   reg set
    -   reg delete
    -   reg load
    -   reg unload
    -   restart
    -   rm
    -   run
    -   runscript
    -   shutdown
    -   unmap
    -   xmemdump
    -   zip
-   To add \[session id\] to the action parameters of these actions, a session with the Create
    Session action needs to be created. Also, the user can delete the session using the Delete
    Session action.
-   Example action run: If "cd C:\\some_directory" command needs to be run using this action, valid
    \[device_id\] and \[session_id\] parameters should be provided by the user. The user should
    select "cd" from the \[command\] dropdown parameter and provide "C:\\some_directory" input in
    the \[data\] parameter.

## Port Information

The app uses HTTP/HTTPS protocol for communicating with the Crowdstrike Server. Below are the
default ports used by Splunk SOAR.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |

## Playbook Backward Compatibility

-   The output data-paths have been updated in the below-existing action. Hence, it is requested to
    update existing playbooks created in the earlier versions of the app by re-inserting |
    modifying | deleting the corresponding action blocks.

      

    -   list users - Below output data-paths have been updated.

          

        -   Updated name from 'customer' to 'cid'
        -   Updated name from 'firstName' to 'first_name'
        -   Updated name from 'lastName' to 'last_name'

