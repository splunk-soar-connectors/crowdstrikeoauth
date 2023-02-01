[comment]: # "Auto-generated SOAR connector documentation"
# CrowdStrike OAuth API

Publisher: Splunk  
Connector Version: 4\.0\.0  
Product Vendor: CrowdStrike  
Product Name: CrowdStrike  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.4\.0  

This app integrates with CrowdStrike OAuth2 authentication standard to implement querying of endpoint security data

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2019-2023 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
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
        type - **DetectionSummaryEvent** . The app will exit from the polling cycle in the
        below-mentioned 2 cases whichever is earlier.
        -   If the total DetectionSummaryEvents fetched equals the value provided in the \[Maximum
            events to get while POLL NOW\] (for manual polling) or \[Maximum events to get while
            scheduled and interval polling\] (for scheduled \| interval polling) parameters
        -   If the total number of continuous blank lines encountered while streaming the data
            equals the value provided in the \[Maximum allowed continuous blank lines\] (default 50
            if not specified) asset configuration parameter
    -   The default behavior of the app is that each event will be placed in its container. By
        checking the configuration parameter \[Merge containers for Hostname and Eventname\] as well
        as specifying an interval in the configuration parameter \[Merge same containers within
        specified seconds\], all events which are of the same type and on the same host will be put
        into one container, as long as the time between those two events is less than the interval.
    -   The \[Maximum allowed continuous blank lines\] asset configuration parameter will be used to
        indicate the allowed number of continuous blank lines while fetching
        **DetectionSummaryEvents** . For example, of the entire data of the DetectionSummaryEvents,
        some of the 'DetectionSummaryEvents' exists after 100 continuous blank lines and if you've
        set the \[Maximum allowed continues blank lines\] parameter value to 500, it will keep on
        ingesting all the 'DetectionSummaryEvents' until the code gets 500 continuous blank lines
        and hence, it will be able to cover the DetectionSummaryEvents successfully even after the
        100 blank lines. If you set it to 50, it will break after the 50th blank line is
        encountered. Hence, it won't be able to ingest the events which exist after the 100
        continuous blank lines because the code considers that after the configured value in the
        \[Maximum allowed continuous blank lines\] configuration parameter (here 50), there is no
        data available for the 'DetectionSummaryEvents'.
-   Manual Polling
    -   During manual poll now, the app starts from the first event that it can query up to the
        value configured in the configuration parameter \[Maximum events to get while POLL NOW\] and
        creates artifacts for all the fetched DetectionSummaryEvents. The last queried event's
        offset ID will not be remembered in Manual POLL NOW and it fetches everything every time
        from the beginning.
-   Scheduled \| Interval Polling
    -   During scheduled \| interval polling, the app starts from the first event that it can query
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
    update existing playbooks created in the earlier versions of the app by re-inserting \|
    modifying \| deleting the corresponding action blocks.

      

    -   list users - Below output data-paths have been updated.

          

        -   Updated name from 'customer' to 'cid'
        -   Updated name from 'firstName' to 'first_name'
        -   Updated name from 'lastName' to 'last_name'


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a CrowdStrike asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | Base URL
**place\_holder** |  optional  | ph | Placeholder
**client\_id** |  required  | password | Client ID
**client\_secret** |  required  | password | Client Secret
**app\_id** |  optional  | string | App ID
**max\_events** |  optional  | numeric | Maximum events to get for scheduled and interval polling
**max\_events\_poll\_now** |  optional  | numeric | Maximum events to get while POLL NOW
**collate** |  optional  | boolean | Merge containers for hostname and eventname
**merge\_time\_interval** |  optional  | numeric | Merge same containers within specified seconds
**max\_crlf** |  optional  | numeric | Maximum allowed continuous blank lines
**preprocess\_script** |  optional  | file | Script with functions to preprocess containers and artifacts
**detonate\_timeout** |  optional  | numeric | Timeout for detonation result in minutes \(Default\: 15 minutes\)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity\. This action logs into the site to check the connection and credentials  
[query device](#action-query-device) - Fetch the device details based on the provided query  
[list groups](#action-list-groups) - Fetch the details of the host groups  
[quarantine device](#action-quarantine-device) - Block the device  
[unquarantine device](#action-unquarantine-device) - Unblock the device  
[assign hosts](#action-assign-hosts) - Assign one or more hosts to the static host group  
[remove hosts](#action-remove-hosts) - Remove one or more hosts from the static host group  
[create session](#action-create-session) - Initialize a new session with the Real Time Response cloud  
[delete session](#action-delete-session) - Deletes a Real Time Response session  
[list detections](#action-list-detections) - Get a list of detections  
[get detections details](#action-get-detections-details) - Get a list of detections details by providing detection ID's  
[update detections](#action-update-details) - Update detections in Crowdstrike Host  
[list alerts](#action-list-alerts) - Get a list of alerts  
[list sessions](#action-list-sessions) - Lists Real Time Response sessions  
[run command](#action-run-command) - Execute an active responder command on a single host  
[run admin command](#action-run-admin-command) - Execute an RTR Admin command on a single host  
[get command details](#action-get-command-details) - Retrieve results of an active responder command executed on a single host  
[list session files](#action-list-session-files) - Get a list of files for the specified RTR session  
[get incident behaviors](#action-get-incident-behaviors) - Get details on behaviors by providing behavior IDs  
[update incident](#action-update-incident) - Perform a set of actions on one or more incidents, such as adding tags or comments or updating the incident name or description  
[list users](#action-list-users) - Get information about all users in your Customer ID  
[get user roles](#action-get-user-roles) - Gets the roles that are assigned to the user  
[list roles](#action-list-roles) - Get information about all user roles from your Customer ID  
[get role](#action-get-role) - Get information about all user roles from your Customer ID  
[list crowdscores](#action-list-crowdscores) - Query environment wide CrowdScore and return the entity data  
[get incident details](#action-get-incident-details) - Get details on incidents by providing incident IDs  
[list incident behaviors](#action-list-incident-behaviors) - Search for behaviors by providing an FQL filter, sorting, and paging details  
[list incidents](#action-list-incidents) - Search for incidents by providing an FQL filter, sorting, and paging details  
[get session file](#action-get-session-file) - Get RTR extracted file contents for the specified session and sha256 and add it to the vault  
[set status](#action-set-status) - Set the state of a detection in Crowdstrike Host  
[get system info](#action-get-system-info) - Get details of a device, given the device ID  
[get process detail](#action-get-process-detail) - Retrieve the details of a process that is running or that previously ran, given a process ID  
[hunt file](#action-hunt-file) - Hunt for a file on the network by querying for the hash  
[hunt domain](#action-hunt-domain) - Get a list of device IDs on which the domain was matched  
[upload put file](#action-upload-put-file) - Upload a new put\-file to use for the RTR \`put\` command  
[get indicator](#action-get-indicator) - Get the full definition of one or more indicators that are being watched  
[list custom indicators](#action-list-custom-indicators) - Queries for custom indicators in your customer account  
[list put files](#action-list-put-files) - Queries for files uploaded to Crowdstrike for use with the RTR \`put\` command  
[on poll](#action-on-poll) - Callback action for the on\_poll ingest functionality  
[list processes](#action-list-processes) - List processes that have recently used the IOC on a particular device  
[upload indicator](#action-upload-indicator) - Upload indicator that you want CrowdStrike to watch  
[delete indicator](#action-delete-indicator) - Delete an indicator that is being watched  
[update indicator](#action-update-indicator) - Update an indicator that has been uploaded  
[file reputation](#action-file-reputation) - Queries CrowdStrike for the file info given a vault ID or a SHA256 hash, vault ID has higher priority than SHA256 hash if both are provided  
[url reputation](#action-url-reputation) - Queries CrowdStrike for the url info  
[download report](#action-download-report) - To download the report of the provided artifact id  
[detonate file](#action-detonate-file) - Upload a file to CrowdStrike and retrieve the analysis results  
[detonate url](#action-detonate-url) - Upload an url to CrowdStrike and retrieve the analysis results  
[check status](#action-check-status) - To check detonation status of the provided resource id  
[get device scroll](#action-get-device-scroll) - Search for hosts in your environment by platform, hostname, IP, and other criteria with continuous pagination capability \(based on offset pointer which expires after 2 minutes with no maximum limit\)  
[get zta data](#action-get-zta-data) - Get Zero Trust Assessment data for one or more hosts by providing agent IDs \(AID\)  

## action: 'test connectivity'
Validate the asset configuration for connectivity\. This action logs into the site to check the connection and credentials

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'query device'
Fetch the device details based on the provided query

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Maximum devices to be fetched | numeric | 
**offset** |  optional  | Starting index of overall result set from which to return ids\. \(Defaults to 0\) | numeric | 
**filter** |  optional  | Filter expression used to limit the fetched devices \(FQL Syntax\) | string | 
**sort** |  optional  | Property to sort by | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.filter | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.offset | numeric | 
action\_result\.parameter\.sort | string | 
action\_result\.data\.\*\.agent\_load\_flags | string | 
action\_result\.data\.\*\.agent\_local\_time | string | 
action\_result\.data\.\*\.agent\_version | string | 
action\_result\.data\.\*\.bios\_manufacturer | string | 
action\_result\.data\.\*\.bios\_version | string | 
action\_result\.data\.\*\.build\_number | string | 
action\_result\.data\.\*\.cid | string |  `md5` 
action\_result\.data\.\*\.config\_id\_base | string | 
action\_result\.data\.\*\.config\_id\_build | string | 
action\_result\.data\.\*\.config\_id\_platform | string | 
action\_result\.data\.\*\.connection\_ip | string |  `ip` 
action\_result\.data\.\*\.connection\_mac\_address | string | 
action\_result\.data\.\*\.cpu\_signature | string | 
action\_result\.data\.\*\.default\_gateway\_ip | string |  `ip` 
action\_result\.data\.\*\.device\_id | string |  `crowdstrike device id` 
action\_result\.data\.\*\.device\_policies\.device\_control\.applied | boolean | 
action\_result\.data\.\*\.device\_policies\.device\_control\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.device\_control\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.device\_control\.policy\_id | string |  `md5` 
action\_result\.data\.\*\.device\_policies\.device\_control\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.firewall\.applied | boolean | 
action\_result\.data\.\*\.device\_policies\.firewall\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.firewall\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.firewall\.policy\_id | string | 
action\_result\.data\.\*\.device\_policies\.firewall\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.firewall\.rule\_set\_id | string | 
action\_result\.data\.\*\.device\_policies\.global\_config\.applied | boolean | 
action\_result\.data\.\*\.device\_policies\.global\_config\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.global\_config\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.global\_config\.policy\_id | string |  `md5` 
action\_result\.data\.\*\.device\_policies\.global\_config\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.global\_config\.settings\_hash | string | 
action\_result\.data\.\*\.device\_policies\.jumpcloud\.applied | numeric | 
action\_result\.data\.\*\.device\_policies\.jumpcloud\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.jumpcloud\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.jumpcloud\.policy\_id | string |  `md5` 
action\_result\.data\.\*\.device\_policies\.jumpcloud\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.jumpcloud\.settings\_hash | string |  `sha256` 
action\_result\.data\.\*\.device\_policies\.prevention\.applied | boolean | 
action\_result\.data\.\*\.device\_policies\.prevention\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.prevention\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.prevention\.policy\_id | string |  `md5` 
action\_result\.data\.\*\.device\_policies\.prevention\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.prevention\.settings\_hash | string | 
action\_result\.data\.\*\.device\_policies\.remote\_response\.applied | boolean | 
action\_result\.data\.\*\.device\_policies\.remote\_response\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.remote\_response\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.remote\_response\.policy\_id | string |  `md5` 
action\_result\.data\.\*\.device\_policies\.remote\_response\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.remote\_response\.settings\_hash | string | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.applied | boolean | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.policy\_id | string |  `md5` 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.settings\_hash | string | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.uninstall\_protection | string | 
action\_result\.data\.\*\.external\_ip | string |  `ip` 
action\_result\.data\.\*\.first\_seen | string | 
action\_result\.data\.\*\.group\_hash | string |  `sha256` 
action\_result\.data\.\*\.groups | string |  `md5` 
action\_result\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.instance\_id | string | 
action\_result\.data\.\*\.kernel\_version | string | 
action\_result\.data\.\*\.last\_seen | string | 
action\_result\.data\.\*\.local\_ip | string |  `ip` 
action\_result\.data\.\*\.mac\_address | string | 
action\_result\.data\.\*\.machine\_domain | string |  `domain` 
action\_result\.data\.\*\.major\_version | string | 
action\_result\.data\.\*\.meta\.version | string | 
action\_result\.data\.\*\.minor\_version | string | 
action\_result\.data\.\*\.modified\_timestamp | string | 
action\_result\.data\.\*\.os\_build | string | 
action\_result\.data\.\*\.os\_version | string | 
action\_result\.data\.\*\.ou | string | 
action\_result\.data\.\*\.platform\_id | string | 
action\_result\.data\.\*\.platform\_name | string | 
action\_result\.data\.\*\.pointer\_size | string | 
action\_result\.data\.\*\.policies\.\*\.applied | boolean | 
action\_result\.data\.\*\.policies\.\*\.applied\_date | string | 
action\_result\.data\.\*\.policies\.\*\.assigned\_date | string | 
action\_result\.data\.\*\.policies\.\*\.policy\_id | string |  `md5` 
action\_result\.data\.\*\.policies\.\*\.policy\_type | string | 
action\_result\.data\.\*\.policies\.\*\.settings\_hash | string | 
action\_result\.data\.\*\.product\_type | string | 
action\_result\.data\.\*\.product\_type\_desc | string | 
action\_result\.data\.\*\.provision\_status | string | 
action\_result\.data\.\*\.reduced\_functionality\_mode | string | 
action\_result\.data\.\*\.serial\_number | string | 
action\_result\.data\.\*\.service\_pack\_major | string | 
action\_result\.data\.\*\.service\_pack\_minor | string | 
action\_result\.data\.\*\.service\_provider | string | 
action\_result\.data\.\*\.service\_provider\_account\_id | string | 
action\_result\.data\.\*\.site\_name | string | 
action\_result\.data\.\*\.slow\_changing\_modified\_timestamp | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.system\_manufacturer | string | 
action\_result\.data\.\*\.system\_product\_name | string | 
action\_result\.data\.\*\.zone\_group | string | 
action\_result\.summary\.total\_devices | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list groups'
Fetch the details of the host groups

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Maximum host groups to be fetched | numeric | 
**filter** |  optional  | Filter expression used to limit the fetched host groups \(FQL Syntax\) | string | 
**sort** |  optional  | Property to sort by | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.filter | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.sort | string | 
action\_result\.data\.\*\.assignment\_rule | string | 
action\_result\.data\.\*\.created\_by | string |  `email` 
action\_result\.data\.\*\.created\_timestamp | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.group\_type | string | 
action\_result\.data\.\*\.id | string |  `crowdstrike host group id` 
action\_result\.data\.\*\.modified\_by | string |  `email` 
action\_result\.data\.\*\.modified\_timestamp | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.summary\.total\_host\_group | numeric | 
action\_result\.summary\.total\_host\_groups | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'quarantine device'
Block the device

Type: **contain**  
Read only: **False**

This action contains the host, which stops any network communications to locations other than the CrowdStrike cloud and IPs specified in the user's containment policy\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  optional  | Comma\-separated list of device IDs | string |  `crowdstrike device id` 
**hostname** |  optional  | Comma\-separated list of hostnames | string |  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.device\_id | string |  `crowdstrike device id` 
action\_result\.parameter\.hostname | string |  `host name` 
action\_result\.data\.\*\.id | string |  `crowdstrike device id` 
action\_result\.data\.\*\.path | string | 
action\_result\.summary\.total\_quarantined\_device | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unquarantine device'
Unblock the device

Type: **correct**  
Read only: **False**

This action lifts containment on the host, which returns its network communications to normal\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  optional  | Comma\-separated list of device IDs | string |  `crowdstrike device id` 
**hostname** |  optional  | Comma\-separated list of hostnames | string |  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.device\_id | string |  `crowdstrike device id` 
action\_result\.parameter\.hostname | string |  `host name` 
action\_result\.data\.\*\.id | string |  `crowdstrike device id` 
action\_result\.data\.\*\.path | string | 
action\_result\.summary\.total\_unquarantined\_device | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'assign hosts'
Assign one or more hosts to the static host group

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  optional  | Comma\-separated list of device IDs | string |  `crowdstrike device id` 
**hostname** |  optional  | Comma separated list of hostnames | string |  `host name` 
**host\_group\_id** |  required  | Static host group ID | string |  `crowdstrike host group id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.device\_id | string |  `crowdstrike device id` 
action\_result\.parameter\.host\_group\_id | string |  `crowdstrike host group id` 
action\_result\.parameter\.hostname | string |  `host name` 
action\_result\.data\.\*\.assignment\_rule | string | 
action\_result\.data\.\*\.created\_by | string | 
action\_result\.data\.\*\.created\_timestamp | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.group\_type | string | 
action\_result\.data\.\*\.id | string |  `crowdstrike host group id` 
action\_result\.data\.\*\.modified\_by | string | 
action\_result\.data\.\*\.modified\_timestamp | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.summary\.total\_assigned\_device | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'remove hosts'
Remove one or more hosts from the static host group

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  optional  | Comma\-separated list of device IDs | string |  `crowdstrike device id` 
**hostname** |  optional  | Comma\-separated list of hostnames | string |  `host name` 
**host\_group\_id** |  required  | Static host group ID | string |  `crowdstrike host group id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.device\_id | string |  `crowdstrike device id` 
action\_result\.parameter\.host\_group\_id | string |  `crowdstrike host group id` 
action\_result\.parameter\.hostname | string |  `host name` 
action\_result\.data\.\*\.assignment\_rule | string | 
action\_result\.data\.\*\.created\_by | string | 
action\_result\.data\.\*\.created\_timestamp | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.group\_type | string | 
action\_result\.data\.\*\.id | string |  `crowdstrike host group id` 
action\_result\.data\.\*\.modified\_by | string | 
action\_result\.data\.\*\.modified\_timestamp | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.summary\.total\_removed\_device | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create session'
Initialize a new session with the Real Time Response cloud

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | Device ID for session to be created | string |  `crowdstrike device id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.device\_id | string |  `crowdstrike device id` 
action\_result\.data\.\*\.errors | string | 
action\_result\.data\.\*\.meta\.powered\_by | string | 
action\_result\.data\.\*\.meta\.query\_time | numeric | 
action\_result\.data\.\*\.meta\.trace\_id | string | 
action\_result\.data\.\*\.resources\.\*\.created\_at | string | 
action\_result\.data\.\*\.resources\.\*\.existing\_aid\_sessions | numeric | 
action\_result\.data\.\*\.resources\.\*\.offline\_queued | boolean | 
action\_result\.data\.\*\.resources\.\*\.pwd | string |  `file path` 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.args\.\*\.arg\_name | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.args\.\*\.arg\_type | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.args\.\*\.command\_level | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.args\.\*\.created\_at | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.args\.\*\.data\_type | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.args\.\*\.default\_value | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.args\.\*\.description | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.args\.\*\.encoding | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.args\.\*\.id | numeric | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.args\.\*\.options | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.args\.\*\.required | boolean | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.args\.\*\.requires\_value | boolean | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.args\.\*\.script\_id | numeric | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.args\.\*\.sequence | numeric | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.args\.\*\.updated\_at | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.command | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.description | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.examples | string |  `file path` 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.internal\_only | boolean | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.runnable | boolean | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.args\.\*\.arg\_name | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.args\.\*\.arg\_type | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.args\.\*\.command\_level | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.args\.\*\.created\_at | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.args\.\*\.data\_type | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.args\.\*\.default\_value | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.args\.\*\.description | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.args\.\*\.encoding | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.args\.\*\.id | numeric | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.args\.\*\.options | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.args\.\*\.required | boolean | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.args\.\*\.requires\_value | boolean | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.args\.\*\.script\_id | numeric | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.args\.\*\.sequence | numeric | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.args\.\*\.updated\_at | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.command | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.description | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.examples | string | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.internal\_only | boolean | 
action\_result\.data\.\*\.resources\.\*\.scripts\.\*\.sub\_commands\.\*\.runnable | boolean | 
action\_result\.data\.\*\.resources\.\*\.session\_id | string |  `crowdstrike rtr session id` 
action\_result\.summary\.session\_id | string |  `crowdstrike rtr session id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete session'
Deletes a Real Time Response session

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**session\_id** |  required  | RTR Session ID | string |  `crowdstrike rtr session id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.session\_id | string |  `crowdstrike rtr session id` 
action\_result\.data | string | 
action\_result\.summary\.results | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list detections'
Get a list of detections

Type: **investigate**  
Read only: **True**

This action supports filtering in order to retrieve a particular set of detections\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Maximum detections to be fetched | numeric | 
**filter** |  optional  | Filter expression used to limit the fetched detections \(FQL Syntax\) | string | 
**sort** |  optional  | Property to sort by | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.filter | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.sort | string | 
action\_result\.data | string | 
action\_result\.data\.\*\.behaviors\.\*\.alleged\_filetype | string | 
action\_result\.data\.\*\.behaviors\.\*\.behavior\_id | string | 
action\_result\.data\.\*\.behaviors\.\*\.cmdline | string | 
action\_result\.data\.\*\.behaviors\.\*\.confidence | numeric | 
action\_result\.data\.\*\.behaviors\.\*\.control\_graph\_id | string | 
action\_result\.data\.\*\.behaviors\.\*\.description | string | 
action\_result\.data\.\*\.behaviors\.\*\.device\_id | string |  `md5`  `crowdstrike device id` 
action\_result\.data\.\*\.behaviors\.\*\.display\_name | string | 
action\_result\.data\.\*\.behaviors\.\*\.filename | string | 
action\_result\.data\.\*\.behaviors\.\*\.filepath | string | 
action\_result\.data\.\*\.behaviors\.\*\.ioc\_description | string | 
action\_result\.data\.\*\.behaviors\.\*\.ioc\_source | string | 
action\_result\.data\.\*\.behaviors\.\*\.ioc\_type | string | 
action\_result\.data\.\*\.behaviors\.\*\.ioc\_value | string | 
action\_result\.data\.\*\.behaviors\.\*\.md5 | string | 
action\_result\.data\.\*\.behaviors\.\*\.objective | string | 
action\_result\.data\.\*\.behaviors\.\*\.parent\_details\.parent\_cmdline | string | 
action\_result\.data\.\*\.behaviors\.\*\.parent\_details\.parent\_md5 | string | 
action\_result\.data\.\*\.behaviors\.\*\.parent\_details\.parent\_process\_graph\_id | string | 
action\_result\.data\.\*\.behaviors\.\*\.parent\_details\.parent\_sha256 | string | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition | numeric | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.blocking\_unsupported\_or\_disabled | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.bootup\_safeguard\_enabled | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.critical\_process\_disabled | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.detect | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.fs\_operation\_blocked | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.handle\_operation\_downgraded | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.inddet\_mask | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.indicator | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.kill\_action\_failed | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.kill\_parent | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.kill\_process | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.kill\_subprocess | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.operation\_blocked | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.policy\_disabled | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.process\_blocked | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.quarantine\_file | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.quarantine\_machine | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.registry\_operation\_blocked | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.rooting | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.sensor\_only | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.suspend\_parent | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.suspend\_process | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.scenario | string | 
action\_result\.data\.\*\.behaviors\.\*\.severity | numeric | 
action\_result\.data\.\*\.behaviors\.\*\.sha256 | string | 
action\_result\.data\.\*\.behaviors\.\*\.tactic | string | 
action\_result\.data\.\*\.behaviors\.\*\.tactic\_id | string | 
action\_result\.data\.\*\.behaviors\.\*\.technique | string | 
action\_result\.data\.\*\.behaviors\.\*\.technique\_id | string | 
action\_result\.data\.\*\.behaviors\.\*\.template\_instance\_id | string | 
action\_result\.data\.\*\.behaviors\.\*\.timestamp | string | 
action\_result\.data\.\*\.behaviors\.\*\.triggering\_process\_graph\_id | string | 
action\_result\.data\.\*\.behaviors\.\*\.user\_id | string | 
action\_result\.data\.\*\.behaviors\.\*\.user\_name | string | 
action\_result\.data\.\*\.cid | string |  `md5` 
action\_result\.data\.\*\.created\_timestamp | string | 
action\_result\.data\.\*\.date\_updated | string | 
action\_result\.data\.\*\.detection\_id | string | 
action\_result\.data\.\*\.device\.agent\_load\_flags | string | 
action\_result\.data\.\*\.device\.agent\_local\_time | string | 
action\_result\.data\.\*\.device\.agent\_version | string | 
action\_result\.data\.\*\.device\.bios\_manufacturer | string | 
action\_result\.data\.\*\.device\.bios\_version | string | 
action\_result\.data\.\*\.device\.cid | string | 
action\_result\.data\.\*\.device\.config\_id\_base | string | 
action\_result\.data\.\*\.device\.config\_id\_build | string | 
action\_result\.data\.\*\.device\.config\_id\_platform | string | 
action\_result\.data\.\*\.device\.device\_id | string |  `md5`  `crowdstrike device id` 
action\_result\.data\.\*\.device\.external\_ip | string | 
action\_result\.data\.\*\.device\.first\_seen | string | 
action\_result\.data\.\*\.device\.hostname | string | 
action\_result\.data\.\*\.device\.last\_seen | string | 
action\_result\.data\.\*\.device\.local\_ip | string | 
action\_result\.data\.\*\.device\.mac\_address | string | 
action\_result\.data\.\*\.device\.machine\_domain | string | 
action\_result\.data\.\*\.device\.major\_version | string | 
action\_result\.data\.\*\.device\.minor\_version | string | 
action\_result\.data\.\*\.device\.modified\_timestamp | string | 
action\_result\.data\.\*\.device\.os\_version | string | 
action\_result\.data\.\*\.device\.platform\_id | string | 
action\_result\.data\.\*\.device\.platform\_name | string | 
action\_result\.data\.\*\.device\.product\_type | string | 
action\_result\.data\.\*\.device\.product\_type\_desc | string | 
action\_result\.data\.\*\.device\.site\_name | string | 
action\_result\.data\.\*\.device\.status | string | 
action\_result\.data\.\*\.device\.system\_manufacturer | string | 
action\_result\.data\.\*\.device\.system\_product\_name | string | 
action\_result\.data\.\*\.email\_sent | boolean | 
action\_result\.data\.\*\.first\_behavior | string | 
action\_result\.data\.\*\.hostinfo\.domain | string | 
action\_result\.data\.\*\.last\_behavior | string | 
action\_result\.data\.\*\.max\_confidence | numeric | 
action\_result\.data\.\*\.max\_severity | numeric | 
action\_result\.data\.\*\.max\_severity\_displayname | string | 
action\_result\.data\.\*\.seconds\_to\_resolved | numeric | 
action\_result\.data\.\*\.seconds\_to\_triaged | numeric | 
action\_result\.data\.\*\.show\_in\_ui | boolean | 
action\_result\.data\.\*\.status | string | 
action\_result\.summary\.total\_detections | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get detections details'
Get a list of detections details by providing detection ID's

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ids** |  required  | List of detection IDs. Comma separated list allowed | string | `crowdstrike detection id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string |  
action\_result\.data | string | 
action\_result\.data\.\*\.behaviors\.\*\.alleged\_filetype | string | 
action\_result\.data\.\*\.behaviors\.\*\.behavior\_id | string | 
action\_result\.data\.\*\.behaviors\.\*\.cmdline | string | 
action\_result\.data\.\*\.behaviors\.\*\.confidence | numeric | 
action\_result\.data\.\*\.behaviors\.\*\.control\_graph\_id | string | 
action\_result\.data\.\*\.behaviors\.\*\.description | string | 
action\_result\.data\.\*\.behaviors\.\*\.device\_id | string |  `md5`  `crowdstrike device id` 
action\_result\.data\.\*\.behaviors\.\*\.display\_name | string | 
action\_result\.data\.\*\.behaviors\.\*\.filename | string | 
action\_result\.data\.\*\.behaviors\.\*\.filepath | string | 
action\_result\.data\.\*\.behaviors\.\*\.ioc\_description | string | 
action\_result\.data\.\*\.behaviors\.\*\.ioc\_source | string | 
action\_result\.data\.\*\.behaviors\.\*\.ioc\_type | string | 
action\_result\.data\.\*\.behaviors\.\*\.ioc\_value | string | 
action\_result\.data\.\*\.behaviors\.\*\.md5 | string | 
action\_result\.data\.\*\.behaviors\.\*\.objective | string | 
action\_result\.data\.\*\.behaviors\.\*\.parent\_details\.parent\_cmdline | string | 
action\_result\.data\.\*\.behaviors\.\*\.parent\_details\.parent\_md5 | string | 
action\_result\.data\.\*\.behaviors\.\*\.parent\_details\.parent\_process\_graph\_id | string | 
action\_result\.data\.\*\.behaviors\.\*\.parent\_details\.parent\_sha256 | string | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition | numeric | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.blocking\_unsupported\_or\_disabled | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.bootup\_safeguard\_enabled | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.critical\_process\_disabled | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.detect | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.fs\_operation\_blocked | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.handle\_operation\_downgraded | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.inddet\_mask | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.indicator | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.kill\_action\_failed | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.kill\_parent | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.kill\_process | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.kill\_subprocess | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.operation\_blocked | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.policy\_disabled | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.process\_blocked | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.quarantine\_file | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.quarantine\_machine | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.registry\_operation\_blocked | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.rooting | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.sensor\_only | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.suspend\_parent | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.pattern\_disposition\_details\.suspend\_process | boolean | 
action\_result\.data\.\*\.behaviors\.\*\.scenario | string | 
action\_result\.data\.\*\.behaviors\.\*\.severity | numeric | 
action\_result\.data\.\*\.behaviors\.\*\.sha256 | string | 
action\_result\.data\.\*\.behaviors\.\*\.tactic | string | 
action\_result\.data\.\*\.behaviors\.\*\.tactic\_id | string | 
action\_result\.data\.\*\.behaviors\.\*\.technique | string | 
action\_result\.data\.\*\.behaviors\.\*\.technique\_id | string | 
action\_result\.data\.\*\.behaviors\.\*\.template\_instance\_id | string | 
action\_result\.data\.\*\.behaviors\.\*\.timestamp | string | 
action\_result\.data\.\*\.behaviors\.\*\.triggering\_process\_graph\_id | string | 
action\_result\.data\.\*\.behaviors\.\*\.user\_id | string | 
action\_result\.data\.\*\.behaviors\.\*\.user\_name | string | 
action\_result\.data\.\*\.cid | string |  `md5` 
action\_result\.data\.\*\.created\_timestamp | string | 
action\_result\.data\.\*\.date\_updated | string | 
action\_result\.data\.\*\.detection\_id | string | 
action\_result\.data\.\*\.device\.agent\_load\_flags | string | 
action\_result\.data\.\*\.device\.agent\_local\_time | string | 
action\_result\.data\.\*\.device\.agent\_version | string | 
action\_result\.data\.\*\.device\.bios\_manufacturer | string | 
action\_result\.data\.\*\.device\.bios\_version | string | 
action\_result\.data\.\*\.device\.cid | string | 
action\_result\.data\.\*\.device\.config\_id\_base | string | 
action\_result\.data\.\*\.device\.config\_id\_build | string | 
action\_result\.data\.\*\.device\.config\_id\_platform | string | 
action\_result\.data\.\*\.device\.device\_id | string |  `md5`  `crowdstrike device id` 
action\_result\.data\.\*\.device\.external\_ip | string | 
action\_result\.data\.\*\.device\.first\_seen | string | 
action\_result\.data\.\*\.device\.hostname | string | 
action\_result\.data\.\*\.device\.last\_seen | string | 
action\_result\.data\.\*\.device\.local\_ip | string | 
action\_result\.data\.\*\.device\.mac\_address | string | 
action\_result\.data\.\*\.device\.machine\_domain | string | 
action\_result\.data\.\*\.device\.major\_version | string | 
action\_result\.data\.\*\.device\.minor\_version | string | 
action\_result\.data\.\*\.device\.modified\_timestamp | string | 
action\_result\.data\.\*\.device\.os\_version | string | 
action\_result\.data\.\*\.device\.platform\_id | string | 
action\_result\.data\.\*\.device\.platform\_name | string | 
action\_result\.data\.\*\.device\.product\_type | string | 
action\_result\.data\.\*\.device\.product\_type\_desc | string | 
action\_result\.data\.\*\.device\.site\_name | string | 
action\_result\.data\.\*\.device\.status | string | 
action\_result\.data\.\*\.device\.system\_manufacturer | string | 
action\_result\.data\.\*\.device\.system\_product\_name | string | 
action\_result\.data\.\*\.email\_sent | boolean | 
action\_result\.data\.\*\.first\_behavior | string | 
action\_result\.data\.\*\.hostinfo\.domain | string | 
action\_result\.data\.\*\.last\_behavior | string | 
action\_result\.data\.\*\.max\_confidence | numeric | 
action\_result\.data\.\*\.max\_severity | numeric | 
action\_result\.data\.\*\.max\_severity\_displayname | string | 
action\_result\.data\.\*\.seconds\_to\_resolved | numeric | 
action\_result\.data\.\*\.seconds\_to\_triaged | numeric | 
action\_result\.data\.\*\.show\_in\_ui | boolean | 
action\_result\.data\.\*\.status | string | 
action\_result\.summary\.total\_detections | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update detections'
Update detections in Crowdstrike Host

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ids** |  required  | List of detection IDs. Comma separated list allowed | string | `crowdstrike detection id` 
**comment** |  required  | Comment to add to the detection | string | 
**assigned_to_uuid** |  optional  | User ID | string | 
**show_in_ui** |  optional  | This detection is displayed or not in Falcon | boolean | 
**status** |  optional  | Status to set | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ids | string | `crowdstrike incident id` 
action\_result\.parameter\.comment| string | 
action\_result\.parameter\.show\_in\_ui | boolean | 
action\_result\.parameter\.assigned\_to\_uuid" | string |  
action\_result\.parameter\.status | string | 
action\_result\.data\.\*\.meta\.query\_time | numeric | 
action\_result\.data\.\*\.meta\.trace\_id | string |
action\_result\.data\.\*\.meta\.writes\.resources\_affected| numeric | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list alerts'
Get a list of alerts

Type: **investigate**  
Read only: **True**

This action supports filtering in order to retrieve a particular set of alerts\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Maximum alerts to be fetched | numeric | 
**filter** |  optional  | Filter expression used to limit the fetched alerts \(FQL Syntax\) | string | 
**sort** |  optional  | Property to sort by | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.filter | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.sort | string | 
action\_result\.data\.\*\.aggregate\_id | string | 
action\_result\.data\.\*\.cid | string |  `md5` 
action\_result\.data\.\*\.composite\_id | string | 
action\_result\.data\.\*\.confidence | numeric | 
action\_result\.data\.\*\.context\_timestamp | string | 
action\_result\.data\.\*\.crawled\_timestamp | string | 
action\_result\.data\.\*\.created\_timestamp | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.display\_name | string | 
action\_result\.data\.\*\.end\_time | string | 
action\_result\.data\.\*\.falcon\_host\_link | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.objective | string | 
action\_result\.data\.\*\.pattern\_id | numeric | 
action\_result\.data\.\*\.previous\_privileges | string | 
action\_result\.data\.\*\.privileges | string | 
action\_result\.data\.\*\.product | string | 
action\_result\.data\.\*\.scenario | string | 
action\_result\.data\.\*\.severity | numeric | 
action\_result\.data\.\*\.show\_in\_ui | boolean | 
action\_result\.data\.\*\.source\_account\_domain | string | 
action\_result\.data\.\*\.source\_account\_name | string | 
action\_result\.data\.\*\.source\_account\_object\_sid | string | 
action\_result\.data\.\*\.start\_time | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.tactic | string | 
action\_result\.data\.\*\.tactic\_id | string | 
action\_result\.data\.\*\.technique | string | 
action\_result\.data\.\*\.technique\_id | string | 
action\_result\.data\.\*\.timestamp | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.updated\_timestamp | string | 
action\_result\.summary\.total\_alerts | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list sessions'
Lists Real Time Response sessions

Type: **investigate**  
Read only: **True**

This action supports filtering in order to retrieve a particular session\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Maximum RTR sessions to be fetched | numeric | 
**filter** |  optional  | Filter expression used to limit the fetched RTR sessions \(FQL Syntax\) | string | 
**sort** |  optional  | Property to sort by | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.filter | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.sort | string | 
action\_result\.data\.\*\.cid | string |  `md5` 
action\_result\.data\.\*\.cloud\_request\_ids | string | 
action\_result\.data\.\*\.commands | string | 
action\_result\.data\.\*\.commands\_queued | boolean | 
action\_result\.data\.\*\.created\_at | string | 
action\_result\.data\.\*\.deleted\_at | string | 
action\_result\.data\.\*\.device\_details | string | 
action\_result\.data\.\*\.device\_id | string |  `md5`  `crowdstrike device id` 
action\_result\.data\.\*\.duration | numeric | 
action\_result\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.id | string |  `crowdstrike rtr session id` 
action\_result\.data\.\*\.logs\.\*\.base\_command | string | 
action\_result\.data\.\*\.logs\.\*\.cloud\_request\_id | string | 
action\_result\.data\.\*\.logs\.\*\.command\_string | string | 
action\_result\.data\.\*\.logs\.\*\.created\_at | string | 
action\_result\.data\.\*\.logs\.\*\.current\_directory | string | 
action\_result\.data\.\*\.logs\.\*\.id | numeric | 
action\_result\.data\.\*\.logs\.\*\.session\_id | string | 
action\_result\.data\.\*\.logs\.\*\.updated\_at | string | 
action\_result\.data\.\*\.offline\_queued | boolean | 
action\_result\.data\.\*\.origin | string | 
action\_result\.data\.\*\.platform\_id | numeric | 
action\_result\.data\.\*\.platform\_name | string | 
action\_result\.data\.\*\.pwd | string | 
action\_result\.data\.\*\.updated\_at | string | 
action\_result\.data\.\*\.user\_id | string | 
action\_result\.data\.\*\.user\_uuid | string | 
action\_result\.summary\.total\_sessions | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'run command'
Execute an active responder command on a single host

Type: **generic**  
Read only: **False**

The API works by first creating a cloud request to execute the command, then the results need to be retrieved using a GET with the cloud\_request\_id\. The action will attempt to retrieve the results, but in the event that a timeout occurs, execute a 'get command details' action\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | Device ID | string |  `crowdstrike device id` 
**session\_id** |  required  | RTR Session ID | string |  `crowdstrike rtr session id` 
**command** |  required  | RTR command to execute on host | string | 
**data** |  optional  | Data/Arguments for the command | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.command | string | 
action\_result\.parameter\.data | string | 
action\_result\.parameter\.device\_id | string |  `crowdstrike device id` 
action\_result\.parameter\.session\_id | string |  `crowdstrike rtr session id` 
action\_result\.data\.\*\.meta\.powered\_by | string | 
action\_result\.data\.\*\.meta\.query\_time | numeric | 
action\_result\.data\.\*\.meta\.trace\_id | string | 
action\_result\.data\.\*\.resources\.\*\.base\_command | string | 
action\_result\.data\.\*\.resources\.\*\.complete | boolean | 
action\_result\.data\.\*\.resources\.\*\.session\_id | string | 
action\_result\.data\.\*\.resources\.\*\.stderr | string | 
action\_result\.data\.\*\.resources\.\*\.stdout | string | 
action\_result\.data\.\*\.resources\.\*\.task\_id | string | 
action\_result\.summary\.cloud\_request\_id | string |  `crowdstrike cloud request id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'run admin command'
Execute an RTR Admin command on a single host

Type: **generic**  
Read only: **False**

This action requires a token with RTR Admin permissions\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | Device ID | string |  `crowdstrike device id` 
**session\_id** |  required  | RTR Session ID | string |  `crowdstrike rtr session id` 
**command** |  required  | RTR Admin command to execute on host | string | 
**data** |  optional  | Data/Arguments for the command | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.command | string | 
action\_result\.parameter\.data | string | 
action\_result\.parameter\.device\_id | string |  `crowdstrike device id` 
action\_result\.parameter\.session\_id | string |  `crowdstrike rtr session id` 
action\_result\.data\.\*\.meta\.powered\_by | string | 
action\_result\.data\.\*\.meta\.query\_time | numeric | 
action\_result\.data\.\*\.meta\.trace\_id | string | 
action\_result\.data\.\*\.resources\.\*\.base\_command | string | 
action\_result\.data\.\*\.resources\.\*\.complete | boolean | 
action\_result\.data\.\*\.resources\.\*\.session\_id | string | 
action\_result\.data\.\*\.resources\.\*\.stderr | string | 
action\_result\.data\.\*\.resources\.\*\.stdout | string | 
action\_result\.data\.\*\.resources\.\*\.task\_id | string | 
action\_result\.summary\.cloud\_request\_id | string |  `crowdstrike cloud request id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get command details'
Retrieve results of an active responder command executed on a single host

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**cloud\_request\_id** |  required  | Cloud Request ID for Command | string |  `crowdstrike cloud request id` 
**timeout\_seconds** |  optional  | Time \(in seconds; default is 60\) to wait before timing out poll for results | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.cloud\_request\_id | string |  `crowdstrike cloud request id` 
action\_result\.parameter\.timeout\_seconds | numeric | 
action\_result\.data\.\*\.meta\.powered\_by | string | 
action\_result\.data\.\*\.meta\.query\_time | numeric | 
action\_result\.data\.\*\.meta\.trace\_id | string | 
action\_result\.data\.\*\.resources\.\*\.base\_command | string | 
action\_result\.data\.\*\.resources\.\*\.complete | boolean | 
action\_result\.data\.\*\.resources\.\*\.session\_id | string | 
action\_result\.data\.\*\.resources\.\*\.stderr | string | 
action\_result\.data\.\*\.resources\.\*\.stdout | string | 
action\_result\.data\.\*\.resources\.\*\.task\_id | string | 
action\_result\.summary\.results | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list session files'
Get a list of files for the specified RTR session

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**session\_id** |  required  | RTR Session ID | string |  `crowdstrike rtr session id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.session\_id | string |  `crowdstrike rtr session id` 
action\_result\.data\.\*\.meta\.powered\_by | string | 
action\_result\.data\.\*\.meta\.query\_time | numeric | 
action\_result\.data\.\*\.meta\.trace\_id | string | 
action\_result\.data\.\*\.resources\.\*\.cloud\_request\_id | string | 
action\_result\.data\.\*\.resources\.\*\.created\_at | string | 
action\_result\.data\.\*\.resources\.\*\.deleted\_at | string | 
action\_result\.data\.\*\.resources\.\*\.id | numeric | 
action\_result\.data\.\*\.resources\.\*\.name | string |  `file name` 
action\_result\.data\.\*\.resources\.\*\.session\_id | string |  `crowdstrike rtr session id` 
action\_result\.data\.\*\.resources\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.resources\.\*\.size | numeric | 
action\_result\.data\.\*\.resources\.\*\.updated\_at | string | 
action\_result\.summary\.total\_files | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get incident behaviors'
Get details on behaviors by providing behavior IDs

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ids** |  required  | List of behavior IDs\. Comma separated list allowed | string |  `crowdstrike incidentbehavior id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ids | string |  `crowdstrike incidentbehavior id` 
action\_result\.data\.\*\.aid | string | 
action\_result\.data\.\*\.behavior\_id | string |  `crowdstrike incidentbehavior id` 
action\_result\.data\.\*\.cid | string | 
action\_result\.data\.\*\.cmdline | string | 
action\_result\.data\.\*\.compound\_tto | string | 
action\_result\.data\.\*\.detection\_ids | string |  `crowdstrike detection id` 
action\_result\.data\.\*\.display\_name | string | 
action\_result\.data\.\*\.domain | string | 
action\_result\.data\.\*\.errors\.\*\.code | numeric | 
action\_result\.data\.\*\.errors\.\*\.message | string | 
action\_result\.data\.\*\.filepath | string | 
action\_result\.data\.\*\.incident\_id | string |  `crowdstrike incident id` 
action\_result\.data\.\*\.meta\.powered\_by | string | 
action\_result\.data\.\*\.meta\.query\_time | numeric | 
action\_result\.data\.\*\.meta\.trace\_id | string | 
action\_result\.data\.\*\.objective | string | 
action\_result\.data\.\*\.pattern\_disposition | numeric | 
action\_result\.data\.\*\.pattern\_disposition\_details\.blocking\_unsupported\_or\_disabled | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.bootup\_safeguard\_enabled | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.critical\_process\_disabled | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.detect | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.fs\_operation\_blocked | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.handle\_operation\_downgraded | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.inddet\_mask | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.indicator | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.kill\_action\_failed | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.kill\_parent | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.kill\_process | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.kill\_subprocess | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.operation\_blocked | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.policy\_disabled | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.process\_blocked | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.quarantine\_file | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.quarantine\_machine | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.registry\_operation\_blocked | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.rooting | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.sensor\_only | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.suspend\_parent | boolean | 
action\_result\.data\.\*\.pattern\_disposition\_details\.suspend\_process | boolean | 
action\_result\.data\.\*\.pattern\_id | numeric | 
action\_result\.data\.\*\.sha256 | string | 
action\_result\.data\.\*\.tactic | string | 
action\_result\.data\.\*\.tactic\_id | string | 
action\_result\.data\.\*\.technique | string | 
action\_result\.data\.\*\.technique\_id | string | 
action\_result\.data\.\*\.template\_instance\_id | numeric | 
action\_result\.data\.\*\.timestamp | string | 
action\_result\.data\.\*\.user\_name | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update incident'
Perform a set of actions on one or more incidents, such as adding tags or comments or updating the incident name or description

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ids** |  required  | List of incident IDs\. Comma separated list allowed | string |  `crowdstrike incident id` 
**add\_tag** |  optional  | Adds the associated tag to all the incident\(s\) of the ids list\. See example values for the defined list | string | 
**delete\_tag** |  optional  | Deletes the matching tag from all the incident\(s\) in the ids list\. See example values for the defined list | string | 
**update\_name** |  optional  | Updates the name of all the incident\(s\) in the ids list | string | 
**update\_description** |  optional  | Updates the description of all the incident\(s\) listed in the ids | string | 
**update\_status** |  optional  | Updates the status of all the incident\(s\) in the ids list | string | 
**add\_comment** |  optional  | Adds a comment for all the incident\(s\) in the ids list | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.add\_comment | string | 
action\_result\.parameter\.add\_tag | string | 
action\_result\.parameter\.delete\_tag | string | 
action\_result\.parameter\.ids | string |  `crowdstrike incident id` 
action\_result\.parameter\.update\_description | string | 
action\_result\.parameter\.update\_name | string | 
action\_result\.parameter\.update\_status | string | 
action\_result\.data\.\*\.meta\.powered\_by | string | 
action\_result\.data\.\*\.meta\.query\_time | numeric | 
action\_result\.data\.\*\.meta\.trace\_id | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list users'
Get information about all users in your Customer ID

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.meta\.powered\_by | string | 
action\_result\.data\.\*\.meta\.query\_time | numeric | 
action\_result\.data\.\*\.meta\.trace\_id | string | 
action\_result\.data\.\*\.resources\.\*\.cid | string |  `crowdstrike customer id` 
action\_result\.data\.\*\.resources\.\*\.first\_name | string | 
action\_result\.data\.\*\.resources\.\*\.last\_name | string | 
action\_result\.data\.\*\.resources\.\*\.uid | string |  `crowdstrike user id` 
action\_result\.data\.\*\.resources\.\*\.uuid | string |  `crowdstrike unique user id` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get user roles'
Gets the roles that are assigned to the user

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_uuid** |  required  | Users Unqiue ID to get the roles for | string |  `crowdstrike unique user id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.user\_uuid | string |  `crowdstrike unique user id` 
action\_result\.data\.\*\.cid | string | 
action\_result\.data\.\*\.grant\_type | string | 
action\_result\.data\.\*\.role\_id | string | 
action\_result\.data\.\*\.role\_name | string | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list roles'
Get information about all user roles from your Customer ID

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.meta\.powered\_by | string | 
action\_result\.data\.\*\.meta\.query\_time | numeric | 
action\_result\.data\.\*\.meta\.trace\_id | string | 
action\_result\.data\.\*\.resources\.\*\.description | string | 
action\_result\.data\.\*\.resources\.\*\.display\_name | string | 
action\_result\.data\.\*\.resources\.\*\.id | string |  `crowdstrike user role id` 
action\_result\.data\.\*\.resources\.\*\.is\_global | boolean | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get role'
Get information about all user roles from your Customer ID

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**role\_id** |  required  | Role ID to get information about\. Comma separated list allowed | string |  `crowdstrike user role id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.role\_id | string |  `crowdstrike user role id` 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.display\_name | string | 
action\_result\.data\.\*\.errors\.\*\.code | numeric | 
action\_result\.data\.\*\.errors\.\*\.message | string | 
action\_result\.data\.\*\.id | string |  `crowdstrike user role id` 
action\_result\.data\.\*\.is\_global | boolean | 
action\_result\.data\.\*\.meta\.powered\_by | string | 
action\_result\.data\.\*\.meta\.query\_time | numeric | 
action\_result\.data\.\*\.meta\.trace\_id | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list crowdscores'
Query environment wide CrowdScore and return the entity data

Type: **investigate**  
Read only: **True**

This action fetches crowdscores using pagination logic\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** |  optional  | Optional filter and sort criteria in the form of an FQL query | string | 
**sort** |  optional  | Sort the results by a specific field and direction\. \(Example\: assigned\_to\.asc\) | string | 
**offset** |  optional  | Starting index of overall result set from which to return ids\. \(Defaults to 0\) | numeric | 
**limit** |  optional  | Limit the number of results to return\. \(Defaults to 50, Max 500\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.filter | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.offset | numeric | 
action\_result\.parameter\.sort | string | 
action\_result\.data\.\*\.adjusted\_score | numeric | 
action\_result\.data\.\*\.cid | string | 
action\_result\.data\.\*\.errors\.\*\.code | numeric | 
action\_result\.data\.\*\.errors\.\*\.message | string | 
action\_result\.data\.\*\.id | string |  `crowdstrike crowdscore id` 
action\_result\.data\.\*\.meta\.pagination\.limit | numeric | 
action\_result\.data\.\*\.meta\.pagination\.offset | numeric | 
action\_result\.data\.\*\.meta\.pagination\.total | numeric | 
action\_result\.data\.\*\.meta\.powered\_by | string | 
action\_result\.data\.\*\.meta\.query\_time | numeric | 
action\_result\.data\.\*\.meta\.trace\_id | string | 
action\_result\.data\.\*\.pagination\.\*\.limit | numeric | 
action\_result\.data\.\*\.pagination\.\*\.offset | numeric | 
action\_result\.data\.\*\.pagination\.\*\.total | numeric | 
action\_result\.data\.\*\.resources\.\*\.cid | string | 
action\_result\.data\.\*\.score | numeric | 
action\_result\.data\.\*\.timestamp | string | 
action\_result\.summary\.total\_crowdscores | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get incident details'
Get details on incidents by providing incident IDs

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ids** |  required  | List of incident IDs\. Comma separated list allowed | string |  `crowdstrike incident id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ids | string |  `crowdstrike incident id` 
action\_result\.data\.\*\.assigned\_to | string | 
action\_result\.data\.\*\.assigned\_to\_name | string | 
action\_result\.data\.\*\.cid | string | 
action\_result\.data\.\*\.created | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.end | string | 
action\_result\.data\.\*\.errors\.\*\.code | numeric | 
action\_result\.data\.\*\.errors\.\*\.message | string | 
action\_result\.data\.\*\.fine\_score | numeric | 
action\_result\.data\.\*\.host\_ids | string |  `crowdstrike device id` 
action\_result\.data\.\*\.hosts\.\*\.agent\_load\_flags | string | 
action\_result\.data\.\*\.hosts\.\*\.agent\_local\_time | string | 
action\_result\.data\.\*\.hosts\.\*\.agent\_version | string | 
action\_result\.data\.\*\.hosts\.\*\.bios\_manufacturer | string | 
action\_result\.data\.\*\.hosts\.\*\.bios\_version | string | 
action\_result\.data\.\*\.hosts\.\*\.cid | string | 
action\_result\.data\.\*\.hosts\.\*\.config\_id\_base | string | 
action\_result\.data\.\*\.hosts\.\*\.config\_id\_build | string | 
action\_result\.data\.\*\.hosts\.\*\.config\_id\_platform | string | 
action\_result\.data\.\*\.hosts\.\*\.device\_id | string |  `crowdstrike device id` 
action\_result\.data\.\*\.hosts\.\*\.external\_ip | string | 
action\_result\.data\.\*\.hosts\.\*\.first\_seen | string | 
action\_result\.data\.\*\.hosts\.\*\.hostname | string | 
action\_result\.data\.\*\.hosts\.\*\.last\_seen | string | 
action\_result\.data\.\*\.hosts\.\*\.local\_ip | string | 
action\_result\.data\.\*\.hosts\.\*\.mac\_address | string | 
action\_result\.data\.\*\.hosts\.\*\.machine\_domain | string | 
action\_result\.data\.\*\.hosts\.\*\.major\_version | string | 
action\_result\.data\.\*\.hosts\.\*\.minor\_version | string | 
action\_result\.data\.\*\.hosts\.\*\.modified\_timestamp | string | 
action\_result\.data\.\*\.hosts\.\*\.os\_version | string | 
action\_result\.data\.\*\.hosts\.\*\.ou | string | 
action\_result\.data\.\*\.hosts\.\*\.platform\_id | string | 
action\_result\.data\.\*\.hosts\.\*\.platform\_name | string | 
action\_result\.data\.\*\.hosts\.\*\.product\_type | string | 
action\_result\.data\.\*\.hosts\.\*\.product\_type\_desc | string | 
action\_result\.data\.\*\.hosts\.\*\.site\_name | string | 
action\_result\.data\.\*\.hosts\.\*\.status | string | 
action\_result\.data\.\*\.hosts\.\*\.system\_manufacturer | string | 
action\_result\.data\.\*\.hosts\.\*\.system\_product\_name | string | 
action\_result\.data\.\*\.incident\_id | string |  `crowdstrike incident id` 
action\_result\.data\.\*\.incident\_type | numeric | 
action\_result\.data\.\*\.meta\.powered\_by | string | 
action\_result\.data\.\*\.meta\.query\_time | numeric | 
action\_result\.data\.\*\.meta\.trace\_id | string | 
action\_result\.data\.\*\.modified\_timestamp | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.start | string | 
action\_result\.data\.\*\.state | string | 
action\_result\.data\.\*\.status | numeric | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.users | string | 
action\_result\.summary\.total\_incidents | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list incident behaviors'
Search for behaviors by providing an FQL filter, sorting, and paging details

Type: **investigate**  
Read only: **True**

This action fetches incident behaviors using pagination logic\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** |  optional  | Optional filter and sort criteria in the form of an FQL query | string | 
**sort** |  optional  | Sort the results by a specific field and direction\. \(Example\: assigned\_to\.asc\) | string | 
**offset** |  optional  | Starting index of overall result set from which to return ids\. \(Defaults to 0\) | numeric | 
**limit** |  optional  | Limit the number of results to return\. \(Defaults to 50, Max 500\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.filter | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.offset | numeric | 
action\_result\.parameter\.sort | string | 
action\_result\.data\.\* | string |  `crowdstrike incidentbehavior id` 
action\_result\.data\.\*\.errors\.\*\.code | numeric | 
action\_result\.data\.\*\.errors\.\*\.message | string | 
action\_result\.data\.\*\.meta\.pagination\.limit | numeric | 
action\_result\.data\.\*\.meta\.pagination\.offset | numeric | 
action\_result\.data\.\*\.meta\.pagination\.total | numeric | 
action\_result\.data\.\*\.meta\.powered\_by | string | 
action\_result\.data\.\*\.meta\.query\_time | numeric | 
action\_result\.data\.\*\.meta\.trace\_id | string | 
action\_result\.data\.\*\.pagination\.\*\.limit | numeric | 
action\_result\.data\.\*\.pagination\.\*\.offset | numeric | 
action\_result\.data\.\*\.pagination\.\*\.total | numeric | 
action\_result\.summary\.total\_incident\_behaviors | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list incidents'
Search for incidents by providing an FQL filter, sorting, and paging details

Type: **investigate**  
Read only: **True**

This action fetches incidents using pagination logic\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** |  optional  | Optional filter and sort criteria in the form of an FQL query | string | 
**sort** |  optional  | Sort the results by a specific field and direction\. \(Example\: assigned\_to\.asc\) | string | 
**offset** |  optional  | Starting index of overall result set from which to return ids\. \(Defaults to 0\) | numeric | 
**limit** |  optional  | Limit the number of results to return\. \(Defaults to 50, Max 500\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.filter | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.offset | numeric | 
action\_result\.parameter\.sort | string | 
action\_result\.data\.\* | string |  `crowdstrike incident id` 
action\_result\.data\.\* | string |  `crowdstrike incident id` 
action\_result\.data\.\*\.errors\.\*\.code | numeric | 
action\_result\.data\.\*\.errors\.\*\.message | string | 
action\_result\.data\.\*\.meta\.pagination\.limit | numeric | 
action\_result\.data\.\*\.meta\.pagination\.offset | numeric | 
action\_result\.data\.\*\.meta\.pagination\.total | numeric | 
action\_result\.data\.\*\.meta\.powered\_by | string | 
action\_result\.data\.\*\.meta\.query\_time | numeric | 
action\_result\.data\.\*\.meta\.trace\_id | string | 
action\_result\.data\.\*\.pagination\.\*\.limit | numeric | 
action\_result\.data\.\*\.pagination\.\*\.offset | numeric | 
action\_result\.data\.\*\.pagination\.\*\.total | numeric | 
action\_result\.summary\.total\_incidents | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get session file'
Get RTR extracted file contents for the specified session and sha256 and add it to the vault

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**session\_id** |  required  | RTR Session ID | string |  `crowdstrike rtr session id` 
**file\_hash** |  required  | SHA256 hash to retrieve | string |  `sha256` 
**file\_name** |  optional  | Filename to use for the archive name and the file within the archive | string |  `filename` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_hash | string |  `sha256` 
action\_result\.parameter\.file\_name | string |  `filename` 
action\_result\.parameter\.session\_id | string |  `crowdstrike rtr session id` 
action\_result\.data\.\*\.container | string | 
action\_result\.data\.\*\.container\_id | numeric | 
action\_result\.data\.\*\.create\_time | string | 
action\_result\.data\.\*\.created\_via | string | 
action\_result\.data\.\*\.hash | string |  `sha1` 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.metadata\.md5 | string | 
action\_result\.data\.\*\.metadata\.sha1 | string | 
action\_result\.data\.\*\.metadata\.sha256 | string | 
action\_result\.data\.\*\.mime\_type | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.path | string | 
action\_result\.data\.\*\.size | numeric | 
action\_result\.data\.\*\.task | string | 
action\_result\.data\.\*\.user | string | 
action\_result\.data\.\*\.vault\_document | numeric | 
action\_result\.data\.\*\.vault\_id | string |  `sha1`  `vault id` 
action\_result\.summary\.vault\_id | string |  `sha1`  `vault id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'set status'
Set the state of a detection in Crowdstrike Host

Type: **generic**  
Read only: **False**

The detection <b>id</b> can be obtained from the Crowdstrike UI and its state can be set\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Detection ID to set the state of | string |  `crowdstrike detection id` 
**state** |  required  | State to set | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `crowdstrike detection id` 
action\_result\.parameter\.state | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get system info'
Get details of a device, given the device ID

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Device ID from previous Crowdstrike IOC search | string |  `crowdstrike device id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `crowdstrike device id` 
action\_result\.data\.\*\.agent\_load\_flags | string | 
action\_result\.data\.\*\.agent\_local\_time | string | 
action\_result\.data\.\*\.agent\_version | string | 
action\_result\.data\.\*\.bios\_manufacturer | string | 
action\_result\.data\.\*\.bios\_version | string | 
action\_result\.data\.\*\.build\_number | string | 
action\_result\.data\.\*\.cid | string |  `md5` 
action\_result\.data\.\*\.config\_id\_base | string | 
action\_result\.data\.\*\.config\_id\_build | string | 
action\_result\.data\.\*\.config\_id\_platform | string | 
action\_result\.data\.\*\.connection\_ip | string |  `ip` 
action\_result\.data\.\*\.connection\_mac\_address | string | 
action\_result\.data\.\*\.cpu\_signature | string | 
action\_result\.data\.\*\.default\_gateway\_ip | string |  `ip` 
action\_result\.data\.\*\.device\_id | string |  `crowdstrike device id` 
action\_result\.data\.\*\.device\_policies\.device\_control\.applied | boolean | 
action\_result\.data\.\*\.device\_policies\.device\_control\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.device\_control\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.device\_control\.policy\_id | string | 
action\_result\.data\.\*\.device\_policies\.device\_control\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.firewall\.applied | boolean | 
action\_result\.data\.\*\.device\_policies\.firewall\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.firewall\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.firewall\.policy\_id | string | 
action\_result\.data\.\*\.device\_policies\.firewall\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.firewall\.rule\_set\_id | string | 
action\_result\.data\.\*\.device\_policies\.global\_config\.applied | boolean | 
action\_result\.data\.\*\.device\_policies\.global\_config\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.global\_config\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.global\_config\.policy\_id | string | 
action\_result\.data\.\*\.device\_policies\.global\_config\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.global\_config\.settings\_hash | string | 
action\_result\.data\.\*\.device\_policies\.jumpcloud\.applied | numeric | 
action\_result\.data\.\*\.device\_policies\.jumpcloud\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.jumpcloud\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.jumpcloud\.policy\_id | string |  `md5` 
action\_result\.data\.\*\.device\_policies\.jumpcloud\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.jumpcloud\.settings\_hash | string |  `sha256` 
action\_result\.data\.\*\.device\_policies\.prevention\.applied | boolean | 
action\_result\.data\.\*\.device\_policies\.prevention\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.prevention\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.prevention\.policy\_id | string |  `md5` 
action\_result\.data\.\*\.device\_policies\.prevention\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.prevention\.settings\_hash | string | 
action\_result\.data\.\*\.device\_policies\.remote\_response\.applied | boolean | 
action\_result\.data\.\*\.device\_policies\.remote\_response\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.remote\_response\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.remote\_response\.policy\_id | string | 
action\_result\.data\.\*\.device\_policies\.remote\_response\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.remote\_response\.settings\_hash | string | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.applied | boolean | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.policy\_id | string |  `md5` 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.settings\_hash | string | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.uninstall\_protection | string | 
action\_result\.data\.\*\.external\_ip | string |  `ip` 
action\_result\.data\.\*\.first\_seen | string | 
action\_result\.data\.\*\.group\_hash | string |  `sha256` 
action\_result\.data\.\*\.groups | string |  `md5` 
action\_result\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.instance\_id | string | 
action\_result\.data\.\*\.kernel\_version | string | 
action\_result\.data\.\*\.last\_seen | string | 
action\_result\.data\.\*\.local\_ip | string |  `ip` 
action\_result\.data\.\*\.mac\_address | string | 
action\_result\.data\.\*\.machine\_domain | string |  `domain` 
action\_result\.data\.\*\.major\_version | string | 
action\_result\.data\.\*\.meta\.version | string | 
action\_result\.data\.\*\.minor\_version | string | 
action\_result\.data\.\*\.modified\_timestamp | string | 
action\_result\.data\.\*\.os\_build | string | 
action\_result\.data\.\*\.os\_version | string | 
action\_result\.data\.\*\.ou | string | 
action\_result\.data\.\*\.platform\_id | string | 
action\_result\.data\.\*\.platform\_name | string | 
action\_result\.data\.\*\.pointer\_size | string | 
action\_result\.data\.\*\.policies\.\*\.applied | boolean | 
action\_result\.data\.\*\.policies\.\*\.applied\_date | string | 
action\_result\.data\.\*\.policies\.\*\.assigned\_date | string | 
action\_result\.data\.\*\.policies\.\*\.policy\_id | string |  `md5` 
action\_result\.data\.\*\.policies\.\*\.policy\_type | string | 
action\_result\.data\.\*\.policies\.\*\.settings\_hash | string | 
action\_result\.data\.\*\.product\_type | string | 
action\_result\.data\.\*\.product\_type\_desc | string | 
action\_result\.data\.\*\.provision\_status | string | 
action\_result\.data\.\*\.reduced\_functionality\_mode | string | 
action\_result\.data\.\*\.release\_group | string | 
action\_result\.data\.\*\.serial\_number | string | 
action\_result\.data\.\*\.service\_pack\_major | string | 
action\_result\.data\.\*\.service\_pack\_minor | string | 
action\_result\.data\.\*\.service\_provider | string | 
action\_result\.data\.\*\.service\_provider\_account\_id | string | 
action\_result\.data\.\*\.site\_name | string | 
action\_result\.data\.\*\.slow\_changing\_modified\_timestamp | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.system\_manufacturer | string | 
action\_result\.data\.\*\.system\_product\_name | string | 
action\_result\.data\.\*\.zone\_group | string | 
action\_result\.summary\.hostname | string |  `host name` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get process detail'
Retrieve the details of a process that is running or that previously ran, given a process ID

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**falcon\_process\_id** |  required  | Process ID from previous Falcon IOC search | string |  `falcon process id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.falcon\_process\_id | string |  `falcon process id` 
action\_result\.data\.\*\.command\_line | string | 
action\_result\.data\.\*\.device\_id | string |  `crowdstrike device id` 
action\_result\.data\.\*\.file\_name | string |  `file name` 
action\_result\.data\.\*\.process\_id | string |  `pid` 
action\_result\.data\.\*\.process\_id\_local | string |  `pid` 
action\_result\.data\.\*\.start\_timestamp | string | 
action\_result\.data\.\*\.start\_timestamp\_raw | string | 
action\_result\.data\.\*\.stop\_timestamp | string | 
action\_result\.data\.\*\.stop\_timestamp\_raw | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt file'
Hunt for a file on the network by querying for the hash

Type: **investigate**  
Read only: **True**

In case of count\_only set to true, keep the limit value larger to fetch count of all the devices\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File hash to search | string |  `hash`  `sha256`  `sha1`  `md5` 
**count\_only** |  optional  | Get endpoint count only | boolean | 
**limit** |  optional  | Maximum device IDs to be fetched \(defaults to 100\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.count\_only | boolean | 
action\_result\.parameter\.hash | string |  `hash`  `sha256`  `sha1`  `md5` 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.device\_id | string |  `crowdstrike device id` 
action\_result\.summary\.device\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt domain'
Get a list of device IDs on which the domain was matched

Type: **investigate**  
Read only: **True**

In case of count\_only set to true, keep the limit value larger to fetch count of all the devices\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to search | string |  `domain` 
**count\_only** |  optional  | Get endpoint count only | boolean | 
**limit** |  optional  | Maximum device IDs to be fetched \(defaults to 100\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.count\_only | boolean | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.device\_id | string |  `crowdstrike device id` 
action\_result\.summary\.device\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'upload put file'
Upload a new put\-file to use for the RTR \`put\` command

Type: **generic**  
Read only: **False**

This action requires a token with RTR Admin permissions\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Vault ID of file to upload | string |  `vault id` 
**description** |  required  | File description | string | 
**file\_name** |  optional  | Filename to use \(if different than actual file name\) | string |  `filename` 
**comment** |  optional  | Comment for the audit log | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.description | string | 
action\_result\.parameter\.file\_name | string |  `filename` 
action\_result\.parameter\.vault\_id | string |  `vault id` 
action\_result\.data\.\*\.meta\.powered\_by | string | 
action\_result\.data\.\*\.meta\.query\_time | numeric | 
action\_result\.data\.\*\.meta\.trace\_id | string | 
action\_result\.data\.\*\.meta\.writes\.resources\_affected | numeric | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get indicator'
Get the full definition of one or more indicators that are being watched

Type: **investigate**  
Read only: **True**

In this action, either 'indicator\_value' and 'indicator\_type' or 'resource\_id' should be provided\. The priority of 'resource\_id' is higher\. If all the parameters are provided then the indicator will be fetched based on the 'resource\_id'\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator\_value** |  optional  | String representation of the indicator | string |  `domain`  `md5`  `sha256`  `ip`  `ipv6` 
**indicator\_type** |  optional  | The type of the indicator | string |  `crowdstrike indicator type` 
**resource\_id** |  optional  | The resource id of the indicator | string |  `crowdstrike indicator id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.indicator\_type | string |  `crowdstrike indicator type` 
action\_result\.parameter\.indicator\_value | string |  `domain`  `md5`  `sha256`  `ip`  `ipv6` 
action\_result\.parameter\.resource\_id | string |  `crowdstrike indicator id` 
action\_result\.data\.\*\.action | string |  `crowdstrike indicator action` 
action\_result\.data\.\*\.applied\_globally | boolean | 
action\_result\.data\.\*\.created\_by | string | 
action\_result\.data\.\*\.created\_on | string |  `date` 
action\_result\.data\.\*\.created\_timestamp | string |  `date` 
action\_result\.data\.\*\.deleted | boolean | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.expiration | string |  `date` 
action\_result\.data\.\*\.expiration\_timestamp | string |  `date` 
action\_result\.data\.\*\.expired | boolean | 
action\_result\.data\.\*\.from\_parent | boolean | 
action\_result\.data\.\*\.host\_groups\.\* | string |  `crowdstrike host group id` 
action\_result\.data\.\*\.id | string |  `crowdstrike indicator id` 
action\_result\.data\.\*\.metadata\.av\_hits | numeric | 
action\_result\.data\.\*\.metadata\.company\_name | string | 
action\_result\.data\.\*\.metadata\.file\_description | string | 
action\_result\.data\.\*\.metadata\.file\_version | string | 
action\_result\.data\.\*\.metadata\.filename | string | 
action\_result\.data\.\*\.metadata\.original\_filename | string | 
action\_result\.data\.\*\.metadata\.product\_name | string | 
action\_result\.data\.\*\.metadata\.product\_version | string | 
action\_result\.data\.\*\.metadata\.signed | boolean | 
action\_result\.data\.\*\.mobile\_action | string | 
action\_result\.data\.\*\.modified\_by | string | 
action\_result\.data\.\*\.modified\_on | string | 
action\_result\.data\.\*\.modified\_timestamp | string |  `date` 
action\_result\.data\.\*\.platforms\.\* | string |  `crowdstrike indicator platforms` 
action\_result\.data\.\*\.severity | string |  `severity` 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.type | string |  `crowdstrike indicator type` 
action\_result\.data\.\*\.value | string |  `ip`  `ipv6`  `md5`  `sha256`  `domain` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list custom indicators'
Queries for custom indicators in your customer account

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator\_value** |  optional  | String representation of the indicator | string |  `ip`  `ipv6`  `md5`  `sha256`  `domain` 
**indicator\_type** |  optional  | The type of the indicator | string |  `crowdstrike indicator type` 
**action** |  optional  | Enforcement policy | string |  `crowdstrike indicator action` 
**source** |  optional  | The source of indicators | string | 
**from\_expiration** |  optional  | The earliest indicator expiration date \(RFC3339\) | string |  `date` 
**to\_expiration** |  optional  | The latest indicator expiration date \(RFC3339\) | string |  `date` 
**limit** |  optional  | The limit of indicator to be fetched \(defaults to 100\) | numeric | 
**sort** |  optional  | Property to sort by | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.action | string |  `crowdstrike indicator action` 
action\_result\.parameter\.from\_expiration | string |  `date` 
action\_result\.parameter\.indicator\_type | string |  `crowdstrike indicator type` 
action\_result\.parameter\.indicator\_value | string |  `ip`  `ipv6`  `md5`  `sha256`  `domain` 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.ph | string | 
action\_result\.parameter\.sort | string | 
action\_result\.parameter\.source | string | 
action\_result\.parameter\.to\_expiration | string |  `date` 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.domain\.\*\.action | string |  `crowdstrike indicator action` 
action\_result\.data\.\*\.domain\.\*\.applied\_globally | boolean | 
action\_result\.data\.\*\.domain\.\*\.created\_by | string |  `md5` 
action\_result\.data\.\*\.domain\.\*\.created\_on | string |  `date` 
action\_result\.data\.\*\.domain\.\*\.created\_timestamp | string |  `date` 
action\_result\.data\.\*\.domain\.\*\.deleted | boolean | 
action\_result\.data\.\*\.domain\.\*\.description | string | 
action\_result\.data\.\*\.domain\.\*\.expiration | string |  `date` 
action\_result\.data\.\*\.domain\.\*\.expiration\_timestamp | string |  `date` 
action\_result\.data\.\*\.domain\.\*\.expired | boolean | 
action\_result\.data\.\*\.domain\.\*\.from\_parent | boolean | 
action\_result\.data\.\*\.domain\.\*\.host\_groups\.\* | string |  `crowdstrike host group id` 
action\_result\.data\.\*\.domain\.\*\.id | string |  `crowdstrike indicator id` 
action\_result\.data\.\*\.domain\.\*\.metadata\.filename | string | 
action\_result\.data\.\*\.domain\.\*\.mobile\_action | string | 
action\_result\.data\.\*\.domain\.\*\.modified\_by | string |  `md5` 
action\_result\.data\.\*\.domain\.\*\.modified\_on | string | 
action\_result\.data\.\*\.domain\.\*\.modified\_timestamp | string |  `date` 
action\_result\.data\.\*\.domain\.\*\.platforms\.\* | string |  `crowdstrike indicator platforms` 
action\_result\.data\.\*\.domain\.\*\.severity | string |  `severity` 
action\_result\.data\.\*\.domain\.\*\.source | string | 
action\_result\.data\.\*\.domain\.\*\.tags | string | 
action\_result\.data\.\*\.domain\.\*\.type | string |  `crowdstrike indicator type` 
action\_result\.data\.\*\.domain\.\*\.value | string |  `domain` 
action\_result\.data\.\*\.ipv4 | string |  `ip` 
action\_result\.data\.\*\.ipv4\.\*\.action | string |  `crowdstrike indicator action` 
action\_result\.data\.\*\.ipv4\.\*\.applied\_globally | boolean | 
action\_result\.data\.\*\.ipv4\.\*\.created\_by | string |  `md5` 
action\_result\.data\.\*\.ipv4\.\*\.created\_on | string |  `date` 
action\_result\.data\.\*\.ipv4\.\*\.created\_timestamp | string |  `date` 
action\_result\.data\.\*\.ipv4\.\*\.deleted | boolean | 
action\_result\.data\.\*\.ipv4\.\*\.description | string | 
action\_result\.data\.\*\.ipv4\.\*\.expiration | string |  `date` 
action\_result\.data\.\*\.ipv4\.\*\.expiration\_timestamp | string |  `date` 
action\_result\.data\.\*\.ipv4\.\*\.expired | boolean | 
action\_result\.data\.\*\.ipv4\.\*\.from\_parent | boolean | 
action\_result\.data\.\*\.ipv4\.\*\.host\_groups\.\* | string |  `crowdstrike host group id` 
action\_result\.data\.\*\.ipv4\.\*\.id | string |  `crowdstrike indicator id` 
action\_result\.data\.\*\.ipv4\.\*\.metadata\.filename | string | 
action\_result\.data\.\*\.ipv4\.\*\.mobile\_action | string | 
action\_result\.data\.\*\.ipv4\.\*\.modified\_by | string |  `md5` 
action\_result\.data\.\*\.ipv4\.\*\.modified\_on | string | 
action\_result\.data\.\*\.ipv4\.\*\.modified\_timestamp | string |  `date` 
action\_result\.data\.\*\.ipv4\.\*\.platforms\.\* | string |  `crowdstrike indicator platforms` 
action\_result\.data\.\*\.ipv4\.\*\.severity | string |  `severity` 
action\_result\.data\.\*\.ipv4\.\*\.source | string | 
action\_result\.data\.\*\.ipv4\.\*\.tags | string | 
action\_result\.data\.\*\.ipv4\.\*\.type | string |  `crowdstrike indicator type` 
action\_result\.data\.\*\.ipv4\.\*\.value | string |  `ip` 
action\_result\.data\.\*\.ipv6 | string |  `ipv6` 
action\_result\.data\.\*\.ipv6\.\*\.action | string |  `crowdstrike indicator action` 
action\_result\.data\.\*\.ipv6\.\*\.applied\_globally | boolean | 
action\_result\.data\.\*\.ipv6\.\*\.created\_by | string |  `md5` 
action\_result\.data\.\*\.ipv6\.\*\.created\_on | string |  `date` 
action\_result\.data\.\*\.ipv6\.\*\.created\_timestamp | string |  `date` 
action\_result\.data\.\*\.ipv6\.\*\.deleted | boolean | 
action\_result\.data\.\*\.ipv6\.\*\.description | string | 
action\_result\.data\.\*\.ipv6\.\*\.expiration | string |  `date` 
action\_result\.data\.\*\.ipv6\.\*\.expiration\_timestamp | string |  `date` 
action\_result\.data\.\*\.ipv6\.\*\.expired | boolean | 
action\_result\.data\.\*\.ipv6\.\*\.from\_parent | boolean | 
action\_result\.data\.\*\.ipv6\.\*\.host\_groups\.\* | string |  `crowdstrike host group id` 
action\_result\.data\.\*\.ipv6\.\*\.id | string |  `crowdstrike indicator id` 
action\_result\.data\.\*\.ipv6\.\*\.metadata\.filename | string | 
action\_result\.data\.\*\.ipv6\.\*\.modified\_by | string |  `md5` 
action\_result\.data\.\*\.ipv6\.\*\.modified\_on | string | 
action\_result\.data\.\*\.ipv6\.\*\.modified\_timestamp | string |  `date` 
action\_result\.data\.\*\.ipv6\.\*\.platforms\.\* | string |  `crowdstrike indicator platforms` 
action\_result\.data\.\*\.ipv6\.\*\.severity | string |  `severity` 
action\_result\.data\.\*\.ipv6\.\*\.source | string | 
action\_result\.data\.\*\.ipv6\.\*\.tags | string | 
action\_result\.data\.\*\.ipv6\.\*\.type | string |  `crowdstrike indicator type` 
action\_result\.data\.\*\.ipv6\.\*\.value | string |  `ipv6` 
action\_result\.data\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.md5\.\*\.action | string |  `crowdstrike indicator action` 
action\_result\.data\.\*\.md5\.\*\.applied\_globally | boolean | 
action\_result\.data\.\*\.md5\.\*\.created\_by | string |  `md5` 
action\_result\.data\.\*\.md5\.\*\.created\_on | string |  `date` 
action\_result\.data\.\*\.md5\.\*\.created\_timestamp | string |  `date` 
action\_result\.data\.\*\.md5\.\*\.deleted | boolean | 
action\_result\.data\.\*\.md5\.\*\.description | string | 
action\_result\.data\.\*\.md5\.\*\.expiration | string |  `date` 
action\_result\.data\.\*\.md5\.\*\.expiration\_timestamp | string |  `date` 
action\_result\.data\.\*\.md5\.\*\.expired | boolean | 
action\_result\.data\.\*\.md5\.\*\.from\_parent | boolean | 
action\_result\.data\.\*\.md5\.\*\.host\_groups\.\* | string |  `crowdstrike host group id` 
action\_result\.data\.\*\.md5\.\*\.id | string |  `crowdstrike indicator id` 
action\_result\.data\.\*\.md5\.\*\.metadata\.av\_hits | numeric | 
action\_result\.data\.\*\.md5\.\*\.metadata\.filename | string | 
action\_result\.data\.\*\.md5\.\*\.metadata\.signed | boolean | 
action\_result\.data\.\*\.md5\.\*\.mobile\_action | string | 
action\_result\.data\.\*\.md5\.\*\.modified\_by | string |  `md5` 
action\_result\.data\.\*\.md5\.\*\.modified\_on | string | 
action\_result\.data\.\*\.md5\.\*\.modified\_timestamp | string |  `date` 
action\_result\.data\.\*\.md5\.\*\.platforms\.\* | string |  `crowdstrike indicator platforms` 
action\_result\.data\.\*\.md5\.\*\.severity | string |  `severity` 
action\_result\.data\.\*\.md5\.\*\.source | string | 
action\_result\.data\.\*\.md5\.\*\.tags | string | 
action\_result\.data\.\*\.md5\.\*\.type | string |  `crowdstrike indicator type` 
action\_result\.data\.\*\.md5\.\*\.value | string |  `md5` 
action\_result\.data\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sha256\.\*\.action | string |  `crowdstrike indicator action` 
action\_result\.data\.\*\.sha256\.\*\.applied\_globally | boolean | 
action\_result\.data\.\*\.sha256\.\*\.created\_by | string |  `md5` 
action\_result\.data\.\*\.sha256\.\*\.created\_on | string |  `date` 
action\_result\.data\.\*\.sha256\.\*\.created\_timestamp | string |  `date` 
action\_result\.data\.\*\.sha256\.\*\.deleted | boolean | 
action\_result\.data\.\*\.sha256\.\*\.description | string | 
action\_result\.data\.\*\.sha256\.\*\.expiration | string |  `date` 
action\_result\.data\.\*\.sha256\.\*\.expiration\_timestamp | string |  `date` 
action\_result\.data\.\*\.sha256\.\*\.expired | boolean | 
action\_result\.data\.\*\.sha256\.\*\.from\_parent | boolean | 
action\_result\.data\.\*\.sha256\.\*\.host\_groups\.\* | string |  `crowdstrike host group id` 
action\_result\.data\.\*\.sha256\.\*\.id | string |  `crowdstrike indicator id` 
action\_result\.data\.\*\.sha256\.\*\.metadata\.av\_hits | numeric | 
action\_result\.data\.\*\.sha256\.\*\.metadata\.company\_name | string | 
action\_result\.data\.\*\.sha256\.\*\.metadata\.file\_description | string | 
action\_result\.data\.\*\.sha256\.\*\.metadata\.file\_version | string | 
action\_result\.data\.\*\.sha256\.\*\.metadata\.filename | string | 
action\_result\.data\.\*\.sha256\.\*\.metadata\.original\_filename | string | 
action\_result\.data\.\*\.sha256\.\*\.metadata\.product\_name | string | 
action\_result\.data\.\*\.sha256\.\*\.metadata\.product\_version | string | 
action\_result\.data\.\*\.sha256\.\*\.metadata\.signed | boolean | 
action\_result\.data\.\*\.sha256\.\*\.mobile\_action | string | 
action\_result\.data\.\*\.sha256\.\*\.modified\_by | string |  `md5` 
action\_result\.data\.\*\.sha256\.\*\.modified\_on | string | 
action\_result\.data\.\*\.sha256\.\*\.modified\_timestamp | string |  `date` 
action\_result\.data\.\*\.sha256\.\*\.platforms\.\* | string |  `crowdstrike indicator platforms` 
action\_result\.data\.\*\.sha256\.\*\.severity | string |  `severity` 
action\_result\.data\.\*\.sha256\.\*\.source | string | 
action\_result\.data\.\*\.sha256\.\*\.tags | string | 
action\_result\.data\.\*\.sha256\.\*\.type | string |  `crowdstrike indicator type` 
action\_result\.data\.\*\.sha256\.\*\.value | string |  `sha256` 
action\_result\.summary\.alerts\_found | numeric | 
action\_result\.summary\.total\_domain | numeric | 
action\_result\.summary\.total\_ipv4 | numeric | 
action\_result\.summary\.total\_ipv6 | numeric | 
action\_result\.summary\.total\_md5 | numeric | 
action\_result\.summary\.total\_sha256 | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list put files'
Queries for files uploaded to Crowdstrike for use with the RTR \`put\` command

Type: **investigate**  
Read only: **True**

For additional information on FQL syntax see\: https\://falcon\.crowdstrike\.com/support/documentation/45/falcon\-query\-language\-feature\-guide\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** |  optional  | FQL query to filter results | string | 
**offset** |  optional  | Starting index of overall result set | string | 
**limit** |  optional  | Number of files to return | numeric | 
**sort** |  optional  | Sort results | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.filter | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.offset | string | 
action\_result\.parameter\.sort | string | 
action\_result\.data\.\*\.comments\_for\_audit\_log | string | 
action\_result\.data\.\*\.created\_by | string | 
action\_result\.data\.\*\.created\_by\_uuid | string | 
action\_result\.data\.\*\.created\_timestamp | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.file\_type | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.modified\_by | string | 
action\_result\.data\.\*\.modified\_timestamp | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.permission\_type | string | 
action\_result\.data\.\*\.run\_attempt\_count | numeric | 
action\_result\.data\.\*\.run\_success\_count | numeric | 
action\_result\.data\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.size | numeric | 
action\_result\.summary\.total\_files | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'on poll'
Callback action for the on\_poll ingest functionality

Type: **ingest**  
Read only: **True**

This action remembers the last event ID that was queried for\. The next ingestion carried out will query for later event IDs\. This way, the same events are not queried for in every run\. However, in the case of 'POLL NOW' queried event IDs will not be remembered\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start\_time** |  optional  | Parameter ignored in this app | numeric | 
**end\_time** |  optional  | Parameter ignored in this app | numeric | 
**container\_count** |  optional  | Parameter ignored in this app | numeric | 
**artifact\_count** |  optional  | Parameter ignored in this app | numeric | 

#### Action Output
No Output  

## action: 'list processes'
List processes that have recently used the IOC on a particular device

Type: **investigate**  
Read only: **True**

Given a file hash or domain, the action will list all the processes that have either recently connected to the domain or interacted with the file that matches the supplied hash\. Use the <b>query device</b> actions to get the device id to run the action on\.In case of count\_only set to true, keep the limit value larger to fetch count of all the devices\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  required  | File Hash or Domain to use for searching | string |  `hash`  `sha256`  `sha1`  `md5`  `domain` 
**id** |  required  | Crowdstrike Device ID to search on | string |  `crowdstrike device id` 
**limit** |  optional  | Maximum processes to be fetched \(defaults to 100\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `crowdstrike device id` 
action\_result\.parameter\.ioc | string |  `hash`  `sha256`  `sha1`  `md5`  `domain` 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.falcon\_process\_id | string |  `falcon process id` 
action\_result\.summary\.process\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'upload indicator'
Upload indicator that you want CrowdStrike to watch

Type: **contain**  
Read only: **False**

Valid values for the <b>action</b> parameter are\:<ul><li>no\_action<br> Save the indicator for future use, but take no action\. No severity required\.</li><li>allow<br> Applies to hashes only\. Allow the indicator and do not detect it\. Severity does not apply and should not be provided\.</li><li>prevent\_no\_ui<br> Applies to hashes only\. Block and detect the indicator, but hide it from <b>Activity &gt; Detections</b>\. Has a default severity value\.</li><li>prevent<br> Applies to hashes only\. Block the indicator and show it as a detection at the selected severity\.</li><li>detect<br> Enable detections for the indicator at the selected severity\.</li></ul>Valid values for the <b>host groups</b> parameter are\:<ul><li>Comma separated host group IDs for specific groups</li><li>Leave it blank for all the host groups</li></ul>The <b>platforms</b> parameter is the list of platforms that the indicator applies to\. You can enter multiple platform names, separated by commas\. Valid values are\: <b>mac, windows, and linux</b>\.<br>The CrowdStrike API accepts the standard timestamp format in the <b>expiration</b> parameter\. In this action, the number of days provided in the <b>expiration</b> parameter is internally converted into the timestamp format to match the API format\.<br>If the indicator with the same type and value is created again, the action will fail as duplicate type\-value combination is not allowed\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  required  | Input domain, ip, or hash ioc | string |  `sha256`  `md5`  `domain`  `ip`  `ipv6` 
**action** |  required  | Action to take when a host observes the custom IOC | string |  `crowdstrike indicator action` 
**platforms** |  required  | Comma separated list of platforms | string |  `crowdstrike indicator platforms` 
**expiration** |  optional  | Alert lifetime in days | numeric | 
**source** |  optional  | Indicator originating source | string | 
**description** |  optional  | Indicator description | string | 
**tags** |  optional  | Comma separated list of tags | string | 
**severity** |  optional  | Severity level | string |  `severity` 
**host\_groups** |  optional  | Comma separated list of host group IDs | string |  `crowdstrike host group id` 
**filename** |  optional  | Metadata filename | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.action | string |  `crowdstrike indicator action` 
action\_result\.parameter\.description | string | 
action\_result\.parameter\.expiration | numeric | 
action\_result\.parameter\.filename | string | 
action\_result\.parameter\.host\_groups | string |  `crowdstrike host group id` 
action\_result\.parameter\.ioc | string |  `sha256`  `md5`  `domain`  `ip`  `ipv6` 
action\_result\.parameter\.platforms | string |  `crowdstrike indicator platforms` 
action\_result\.parameter\.severity | string |  `severity` 
action\_result\.parameter\.source | string | 
action\_result\.parameter\.tags | string | 
action\_result\.data\.\*\.action | string |  `crowdstrike indicator action` 
action\_result\.data\.\*\.applied\_globally | boolean | 
action\_result\.data\.\*\.created\_by | string |  `md5` 
action\_result\.data\.\*\.created\_on | string |  `date` 
action\_result\.data\.\*\.created\_timestamp | string |  `date` 
action\_result\.data\.\*\.deleted | boolean | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.expiration | string |  `date` 
action\_result\.data\.\*\.expiration\_timestamp | string |  `date` 
action\_result\.data\.\*\.expired | boolean | 
action\_result\.data\.\*\.from\_parent | boolean | 
action\_result\.data\.\*\.host\_groups\.\* | string |  `crowdstrike host group id` 
action\_result\.data\.\*\.id | string |  `crowdstrike indicator id` 
action\_result\.data\.\*\.metadata\.av\_hits | numeric | 
action\_result\.data\.\*\.metadata\.filename | string | 
action\_result\.data\.\*\.metadata\.signed | boolean | 
action\_result\.data\.\*\.modified\_by | string |  `md5` 
action\_result\.data\.\*\.modified\_on | string | 
action\_result\.data\.\*\.modified\_timestamp | string |  `date` 
action\_result\.data\.\*\.platforms\.\* | string |  `crowdstrike indicator platforms` 
action\_result\.data\.\*\.severity | string |  `severity` 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.type | string |  `crowdstrike indicator type` 
action\_result\.data\.\*\.value | string |  `ip`  `ipv6`  `md5`  `sha256`  `domain` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete indicator'
Delete an indicator that is being watched

Type: **correct**  
Read only: **False**

In this action, either 'ioc' or 'resource\_id' should be provided\. The priority of 'resource\_id' is higher\. If both the parameters are provided then the indicator will be deleted based on the 'resource\_id'\. The CrowdStrike API returns success for the 'resource\_id' of the already deleted indicator\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  optional  | Hash, ip or domain IOC from previous upload | string |  `ip`  `ipv6`  `md5`  `sha256`  `domain` 
**resource\_id** |  optional  | The resource id of the indicator | string |  `crowdstrike indicator id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ioc | string |  `ip`  `ipv6`  `md5`  `sha256`  `domain` 
action\_result\.parameter\.resource\_id | string |  `crowdstrike indicator id` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update indicator'
Update an indicator that has been uploaded

Type: **generic**  
Read only: **False**

Valid values for the <b>host groups</b> parameter are\:<ul><li>Comma separated host group IDs for specific groups</li><li>The value '<b>all</b>' for all the host groups</li><li>Leave it blank if there is no change</li></ul>If no parameters are provided as input, the action would pass successfully\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  required  | Hash, ip or domain IOC to update | string |  `ip`  `md5`  `sha256`  `domain` 
**action** |  optional  | Action to take when a host observes the custom IOC | string |  `crowdstrike indicator action` 
**platforms** |  optional  | Comma separated list of platforms | string |  `crowdstrike indicator platforms` 
**expiration** |  optional  | Alert lifetime in days | numeric | 
**source** |  optional  | Indicator originating source | string | 
**description** |  optional  | Indicator description | string | 
**tags** |  optional  | Comma separated list of tags | string | 
**severity** |  optional  | Severity level | string |  `severity` 
**host\_groups** |  optional  | Comma separated list of host group IDs | string |  `crowdstrike host group id` 
**filename** |  optional  | Metadata filename | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.action | string |  `crowdstrike indicator action` 
action\_result\.parameter\.description | string | 
action\_result\.parameter\.expiration | numeric | 
action\_result\.parameter\.filename | string | 
action\_result\.parameter\.host\_groups | string |  `crowdstrike host group id` 
action\_result\.parameter\.ioc | string |  `ip`  `md5`  `sha256`  `domain` 
action\_result\.parameter\.platforms | string |  `crowdstrike indicator platforms` 
action\_result\.parameter\.severity | string |  `severity` 
action\_result\.parameter\.source | string | 
action\_result\.parameter\.tags | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'file reputation'
Queries CrowdStrike for the file info given a vault ID or a SHA256 hash, vault ID has higher priority than SHA256 hash if both are provided

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  optional  | Vault ID of file | string |  `vault id` 
**sha256** |  optional  | SHA256 hash of the file | string |  `sha256` 
**limit** |  optional  | Maximum reports to be fetched | numeric | 
**sort** |  optional  | Property to sort by | string | 
**offset** |  optional  | Starting index of overall result set from which to return ids \(defaults to 0\) | numeric | 
**detail\_report** |  optional  | Get the detailed report | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.detail\_report | boolean | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.offset | numeric | 
action\_result\.parameter\.sha256 | string |  `sha256` 
action\_result\.parameter\.sort | string | 
action\_result\.parameter\.vault\_id | string |  `vault id` 
action\_result\.data\.\*\.cid | string | 
action\_result\.data\.\*\.created\_timestamp | string | 
action\_result\.data\.\*\.id | string |  `crowdstrike resource id` 
action\_result\.data\.\*\.ioc\_report\_broad\_csv\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_broad\_json\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_broad\_maec\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_broad\_stix\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_strict\_csv\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_strict\_json\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_strict\_maec\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_strict\_stix\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.malquery\.\*\.input | string | 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.file\_size | numeric | 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.file\_type | string | 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.first\_seen\_timestamp | string | 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.label | string | 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.malquery\.\*\.type | string | 
action\_result\.data\.\*\.malquery\.\*\.verdict | string | 
action\_result\.data\.\*\.origin | string | 
action\_result\.data\.\*\.sandbox\.\*\.architecture | string | 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.address | string |  `ip` 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.associated\_runtime\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.associated\_runtime\.\*\.pid | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.country | string | 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.port | numeric |  `port` 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.protocol | string | 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.address | string |  `ip` 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.country | string | 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.domain | string |  `domain`  `ip` 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.registrar\_creation\_timestamp | string |  `date` 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.registrar\_name | string | 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.registrar\_name\_servers | string | 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.registrar\_organization | string | 
action\_result\.data\.\*\.sandbox\.\*\.environment | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.environment\_description | string |  `crowdstrike environment` 
action\_result\.data\.\*\.sandbox\.\*\.environment\_id | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.error\_message | string | 
action\_result\.data\.\*\.sandbox\.\*\.error\_origin | string | 
action\_result\.data\.\*\.sandbox\.\*\.error\_type | string | 
action\_result\.data\.\*\.sandbox\.\*\.exact\_deep\_hash | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.description | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.file\_path | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.file\_size | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.runtime\_process | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.threat\_level\_readable | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.filename | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.process | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.source | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.type | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.value | string | 
action\_result\.data\.\*\.sandbox\.\*\.file\_imports\.\*\.module | string | 
action\_result\.data\.\*\.sandbox\.\*\.file\_size | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.file\_type | string | 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.header | string | 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.host | string |  `domain`  `ip` 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.host\_ip | string |  `ip` 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.host\_port | numeric |  `port` 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.method | string | 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.url | string | 
action\_result\.data\.\*\.sandbox\.\*\.incidents\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.memory\_strings\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.sandbox\.\*\.mitre\_attacks\.\*\.attack\_id | string | 
action\_result\.data\.\*\.sandbox\.\*\.mitre\_attacks\.\*\.parent\.attack\_id | string | 
action\_result\.data\.\*\.sandbox\.\*\.mitre\_attacks\.\*\.parent\.attack\_id\_wiki | string | 
action\_result\.data\.\*\.sandbox\.\*\.mitre\_attacks\.\*\.parent\.technique | string | 
action\_result\.data\.\*\.sandbox\.\*\.mitre\_attacks\.\*\.tactic | string | 
action\_result\.data\.\*\.sandbox\.\*\.mitre\_attacks\.\*\.technique | string | 
action\_result\.data\.\*\.sandbox\.\*\.network\_settings | string | 
action\_result\.data\.\*\.sandbox\.\*\.packer | string | 
action\_result\.data\.\*\.sandbox\.\*\.pcap\_report\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.command\_line | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.file\_accesses\.\*\.mask | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.file\_accesses\.\*\.path | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.file\_accesses\.\*\.type | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.handles\.\*\.id | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.handles\.\*\.path | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.handles\.\*\.type | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.icon\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.normalized\_path | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.parent\_uid | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.pid | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.process\_flags\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.key | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.operation | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.path | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.status | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.status\_human\_readable | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.value | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.streams\.\*\.file\_name | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.streams\.\*\.human\_keywords | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.streams\.\*\.instructions\_artifact\_id | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.streams\.\*\.uid | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.uid | string | 
action\_result\.data\.\*\.sandbox\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.attack\_id | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.category | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.description | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.identifier | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.origin | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.relevance | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.threat\_level | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.threat\_level\_human | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.type | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.submission\_type | string | 
action\_result\.data\.\*\.sandbox\.\*\.submit\_name | string | 
action\_result\.data\.\*\.sandbox\.\*\.threat\_score | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.verdict | string | 
action\_result\.data\.\*\.sandbox\.\*\.version\_info\.\*\.id | string | 
action\_result\.data\.\*\.sandbox\.\*\.version\_info\.\*\.value | string | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_bitness | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_edition | string | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_name | string | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_service\_pack | string | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_version | string | 
action\_result\.data\.\*\.threat\_graph\.indicators\.\*\.customer\_prevalence | string | 
action\_result\.data\.\*\.threat\_graph\.indicators\.\*\.global\_prevalence | string | 
action\_result\.data\.\*\.threat\_graph\.indicators\.\*\.type | string | 
action\_result\.data\.\*\.threat\_graph\.indicators\.\*\.value | string | 
action\_result\.data\.\*\.user\_id | string | 
action\_result\.data\.\*\.user\_name | string | 
action\_result\.data\.\*\.user\_uuid | string | 
action\_result\.data\.\*\.verdict | string | 
action\_result\.summary\.total\_reports | numeric | 
action\_result\.summary\.verdict | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'url reputation'
Queries CrowdStrike for the url info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to query | string |  `url` 
**limit** |  optional  | Maximum reports to be fetched | numeric | 
**sort** |  optional  | Property to sort by | string | 
**offset** |  optional  | Starting index of overall result set from which to return ids \(defaults to 0\) | numeric | 
**detail\_report** |  optional  | Get the detailed report | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.detail\_report | boolean | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.offset | numeric | 
action\_result\.parameter\.sort | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.\*\.cid | string | 
action\_result\.data\.\*\.created\_timestamp | string | 
action\_result\.data\.\*\.id | string |  `crowdstrike resource id` 
action\_result\.data\.\*\.ioc\_report\_broad\_csv\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_broad\_json\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_broad\_maec\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_broad\_stix\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_strict\_csv\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_strict\_json\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_strict\_maec\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_strict\_stix\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.malquery\.\*\.input | string | 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.file\_size | numeric | 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.file\_type | string | 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.first\_seen\_timestamp | string |  `date` 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.label | string | 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.malquery\.\*\.type | string | 
action\_result\.data\.\*\.malquery\.\*\.verdict | string | 
action\_result\.data\.\*\.origin | string | 
action\_result\.data\.\*\.sandbox\.\*\.architecture | string | 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.address | string |  `ip` 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.associated\_runtime\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.associated\_runtime\.\*\.pid | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.country | string | 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.port | numeric |  `port` 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.protocol | string | 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.address | string | 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.country | string | 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.domain | string |  `domain`  `ip` 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.registrar\_creation\_timestamp | string |  `date` 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.registrar\_name | string | 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.registrar\_name\_servers | string | 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.registrar\_organization | string | 
action\_result\.data\.\*\.sandbox\.\*\.environment | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.environment\_description | string |  `crowdstrike environment` 
action\_result\.data\.\*\.sandbox\.\*\.environment\_id | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.error\_message | string | 
action\_result\.data\.\*\.sandbox\.\*\.error\_origin | string | 
action\_result\.data\.\*\.sandbox\.\*\.error\_type | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.description | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.file\_path | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.file\_size | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.runtime\_process | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.threat\_level\_readable | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.filename | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.process | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.source | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.type | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.value | string | 
action\_result\.data\.\*\.sandbox\.\*\.file\_type | string | 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.header | string | 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.host | string | 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.host\_ip | string |  `ip` 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.host\_port | numeric |  `port` 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.method | string | 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.url | string | 
action\_result\.data\.\*\.sandbox\.\*\.incidents\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.memory\_strings\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.sandbox\.\*\.mitre\_attacks\.\*\.attack\_id | string | 
action\_result\.data\.\*\.sandbox\.\*\.mitre\_attacks\.\*\.tactic | string | 
action\_result\.data\.\*\.sandbox\.\*\.mitre\_attacks\.\*\.technique | string | 
action\_result\.data\.\*\.sandbox\.\*\.network\_settings | string | 
action\_result\.data\.\*\.sandbox\.\*\.pcap\_report\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.command\_line | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.file\_accesses\.\*\.mask | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.file\_accesses\.\*\.path | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.file\_accesses\.\*\.type | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.handles\.\*\.id | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.handles\.\*\.path | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.handles\.\*\.type | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.icon\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.normalized\_path | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.parent\_uid | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.pid | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.process\_flags\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.key | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.operation | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.path | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.value | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.uid | string | 
action\_result\.data\.\*\.sandbox\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.attack\_id | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.category | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.description | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.identifier | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.origin | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.relevance | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.threat\_level | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.threat\_level\_human | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.type | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.submission\_type | string | 
action\_result\.data\.\*\.sandbox\.\*\.submit\_name | string | 
action\_result\.data\.\*\.sandbox\.\*\.submit\_url | string | 
action\_result\.data\.\*\.sandbox\.\*\.suricata\_alerts\.\*\.category | string | 
action\_result\.data\.\*\.sandbox\.\*\.suricata\_alerts\.\*\.description | string | 
action\_result\.data\.\*\.sandbox\.\*\.suricata\_alerts\.\*\.destination\_ip | string | 
action\_result\.data\.\*\.sandbox\.\*\.suricata\_alerts\.\*\.destination\_port | numeric |  `port` 
action\_result\.data\.\*\.sandbox\.\*\.suricata\_alerts\.\*\.protocol | string | 
action\_result\.data\.\*\.sandbox\.\*\.suricata\_alerts\.\*\.sid | string | 
action\_result\.data\.\*\.sandbox\.\*\.threat\_score | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.verdict | string | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_bitness | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_edition | string | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_name | string | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_service\_pack | string | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_version | string | 
action\_result\.data\.\*\.user\_id | string | 
action\_result\.data\.\*\.user\_name | string | 
action\_result\.data\.\*\.user\_uuid | string | 
action\_result\.data\.\*\.verdict | string | 
action\_result\.summary\.total\_reports | numeric | 
action\_result\.summary\.verdict | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'download report'
To download the report of the provided artifact id

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**artifact\_id** |  required  | Artifact id to be downloaded | string |  `crowdstrike artifact id` 
**file\_name** |  optional  | Filename to use for the file added to vault | string |  `filename` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.parameter\.file\_name | string |  `filename` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'detonate file'
Upload a file to CrowdStrike and retrieve the analysis results

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Vault ID of file | string |  `vault id` 
**environment** |  required  | Sandbox environment to be used for analysis | string |  `crowdstrike environment` 
**comment** |  optional  | A descriptive comment to identify the file | string | 
**limit** |  optional  | Maximum reports to be fetched | numeric | 
**offset** |  optional  | Starting index of overall result set from which to return ids \(Defaults to 0\) | numeric | 
**command\_line** |  optional  | Command line script passed to the submitted file at runtime \(Max length\: 2048 characters\) | string | 
**document\_password** |  optional  | Password of the document if password protected \(Max length\: 32 characters\) | string | 
**submit\_name** |  optional  | Name of the malware sample that's used for file type detection and analysis | string | 
**user\_tags** |  optional  | Comma seperated list of user tags \(Max length\: 100 characters per tag\) | string | 
**sort** |  optional  | Property to sort by | string | 
**action\_script** |  optional  | Runtime script for sandbox analysis | string | 
**detail\_report** |  optional  | Get the detailed report | boolean | 
**enable\_tor** |  optional  | To route the sandbox network traffic via TOR | boolean | 
**is\_confidential** |  optional  | Defines visibility of the file in Falcon MalQuery \(defaults to True\) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.action\_script | string | 
action\_result\.parameter\.command\_line | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.detail\_report | boolean | 
action\_result\.parameter\.document\_password | string | 
action\_result\.parameter\.enable\_tor | boolean | 
action\_result\.parameter\.environment | string |  `crowdstrike environment` 
action\_result\.parameter\.is\_confidential | boolean | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.offset | numeric | 
action\_result\.parameter\.sort | string | 
action\_result\.parameter\.submit\_name | string | 
action\_result\.parameter\.user\_tags | string | 
action\_result\.parameter\.vault\_id | string |  `vault id` 
action\_result\.data\.\*\.cid | string | 
action\_result\.data\.\*\.created\_timestamp | string |  `date` 
action\_result\.data\.\*\.id | string |  `crowdstrike resource id` 
action\_result\.data\.\*\.ioc\_report\_broad\_csv\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_broad\_json\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_broad\_maec\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_broad\_stix\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_strict\_csv\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_strict\_json\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_strict\_maec\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_strict\_stix\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.malquery\.\*\.input | string | 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.file\_size | numeric | 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.file\_type | string | 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.first\_seen\_timestamp | string |  `date` 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.label | string | 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.malquery\.\*\.type | string | 
action\_result\.data\.\*\.malquery\.\*\.verdict | string | 
action\_result\.data\.\*\.origin | string | 
action\_result\.data\.\*\.sandbox\.\*\.architecture | string | 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.address | string |  `ip` 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.associated\_runtime\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.associated\_runtime\.\*\.pid | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.country | string | 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.port | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.protocol | string | 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.address | string |  `ip` 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.country | string | 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.domain | string |  `domain`  `url` 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.registrar\_creation\_timestamp | string |  `date` 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.registrar\_name | string | 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.registrar\_name\_servers | string | 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.registrar\_organization | string | 
action\_result\.data\.\*\.sandbox\.\*\.environment | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.environment\_description | string |  `crowdstrike environment` 
action\_result\.data\.\*\.sandbox\.\*\.environment\_id | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.error\_message | string | 
action\_result\.data\.\*\.sandbox\.\*\.error\_origin | string | 
action\_result\.data\.\*\.sandbox\.\*\.error\_type | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.description | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.file\_path | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.file\_size | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.runtime\_process | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.threat\_level\_readable | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.filename | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.process | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.source | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.type | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.value | string | 
action\_result\.data\.\*\.sandbox\.\*\.file\_imports\.\*\.module | string | 
action\_result\.data\.\*\.sandbox\.\*\.file\_size | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.file\_type | string | 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.header | string | 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.host | string |  `hostname` 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.host\_ip | string |  `ip` 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.host\_port | numeric |  `port` 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.method | string | 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.url | string | 
action\_result\.data\.\*\.sandbox\.\*\.incidents\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.memory\_strings\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.sandbox\.\*\.mitre\_attacks\.\*\.attack\_id | string | 
action\_result\.data\.\*\.sandbox\.\*\.mitre\_attacks\.\*\.tactic | string | 
action\_result\.data\.\*\.sandbox\.\*\.mitre\_attacks\.\*\.technique | string | 
action\_result\.data\.\*\.sandbox\.\*\.network\_settings | string | 
action\_result\.data\.\*\.sandbox\.\*\.pcap\_report\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.command\_line | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.file\_accesses\.\*\.mask | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.file\_accesses\.\*\.path | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.file\_accesses\.\*\.type | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.handles\.\*\.id | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.handles\.\*\.path | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.handles\.\*\.type | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.icon\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.normalized\_path | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.parent\_uid | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.pid | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.process\_flags\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.key | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.operation | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.path | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.status | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.status\_human\_readable | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.value | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.uid | string | 
action\_result\.data\.\*\.sandbox\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.attack\_id | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.category | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.description | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.identifier | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.origin | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.relevance | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.threat\_level | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.threat\_level\_human | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.type | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.submission\_type | string | 
action\_result\.data\.\*\.sandbox\.\*\.submit\_name | string | 
action\_result\.data\.\*\.sandbox\.\*\.suricata\_alerts\.\*\.category | string | 
action\_result\.data\.\*\.sandbox\.\*\.suricata\_alerts\.\*\.description | string | 
action\_result\.data\.\*\.sandbox\.\*\.suricata\_alerts\.\*\.destination\_ip | string |  `ip` 
action\_result\.data\.\*\.sandbox\.\*\.suricata\_alerts\.\*\.destination\_port | numeric |  `port` 
action\_result\.data\.\*\.sandbox\.\*\.suricata\_alerts\.\*\.protocol | string | 
action\_result\.data\.\*\.sandbox\.\*\.suricata\_alerts\.\*\.sid | string | 
action\_result\.data\.\*\.sandbox\.\*\.threat\_score | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.verdict | string | 
action\_result\.data\.\*\.sandbox\.\*\.version\_info\.\*\.id | string | 
action\_result\.data\.\*\.sandbox\.\*\.version\_info\.\*\.value | string | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_bitness | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_edition | string | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_name | string | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_service\_pack | string | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_version | string | 
action\_result\.data\.\*\.threat\_graph\.indicators\.\*\.global\_prevalence | string | 
action\_result\.data\.\*\.threat\_graph\.indicators\.\*\.type | string | 
action\_result\.data\.\*\.threat\_graph\.indicators\.\*\.value | string | 
action\_result\.data\.\*\.user\_id | string | 
action\_result\.data\.\*\.user\_name | string | 
action\_result\.data\.\*\.user\_tags | string | 
action\_result\.data\.\*\.user\_uuid | string | 
action\_result\.data\.\*\.verdict | string | 
action\_result\.summary\.total\_reports | numeric | 
action\_result\.summary\.verdict | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'detonate url'
Upload an url to CrowdStrike and retrieve the analysis results

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to query | string |  `url` 
**environment** |  required  | Sandbox environment to be used for analysis | string |  `crowdstrike environment` 
**limit** |  optional  | Maximum reports to be fetched | numeric | 
**offset** |  optional  | Starting index of overall result set from which to return ids \(Defaults to 0\) | numeric | 
**document\_password** |  optional  | Password of the document if password protected \(Max length\: 32 characters\) | string | 
**command\_line** |  optional  | Command line script passed to the submitted file at runtime \(Max length\: 2048 characters\) | string | 
**user\_tags** |  optional  | Comma seperated list of user tags \(Max length\: 100 characters per tag\) | string | 
**sort** |  optional  | Property to sort by | string | 
**action\_script** |  optional  | Runtime script for sandbox analysis | string | 
**detail\_report** |  optional  | Get the detailed report | boolean | 
**enable\_tor** |  optional  | To route the sandbox network traffic via TOR | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.action\_script | string | 
action\_result\.parameter\.command\_line | string | 
action\_result\.parameter\.detail\_report | boolean | 
action\_result\.parameter\.document\_password | string | 
action\_result\.parameter\.enable\_tor | boolean | 
action\_result\.parameter\.environment | string |  `crowdstrike environment` 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.offset | numeric | 
action\_result\.parameter\.sort | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.parameter\.user\_tags | string | 
action\_result\.data\.\*\.cid | string | 
action\_result\.data\.\*\.created\_timestamp | string |  `date` 
action\_result\.data\.\*\.id | string |  `crowdstrike resource id` 
action\_result\.data\.\*\.ioc\_report\_broad\_csv\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_broad\_json\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_broad\_maec\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_broad\_stix\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_strict\_csv\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_strict\_json\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_strict\_maec\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.ioc\_report\_strict\_stix\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.malquery\.\*\.input | string | 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.family | string | 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.file\_size | numeric | 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.file\_type | string | 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.first\_seen\_timestamp | string |  `date` 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.label | string | 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.malquery\.\*\.resources\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.malquery\.\*\.type | string | 
action\_result\.data\.\*\.malquery\.\*\.verdict | string | 
action\_result\.data\.\*\.origin | string | 
action\_result\.data\.\*\.sandbox\.\*\.architecture | string | 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.address | string |  `ip` 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.associated\_runtime\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.associated\_runtime\.\*\.pid | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.country | string | 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.port | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.contacted\_hosts\.\*\.protocol | string | 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.address | string |  `ip` 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.country | string | 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.domain | string |  `domain`  `url` 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.registrar\_creation\_timestamp | string |  `date` 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.registrar\_name | string | 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.registrar\_name\_servers | string | 
action\_result\.data\.\*\.sandbox\.\*\.dns\_requests\.\*\.registrar\_organization | string | 
action\_result\.data\.\*\.sandbox\.\*\.environment | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.environment\_description | string |  `crowdstrike environment` 
action\_result\.data\.\*\.sandbox\.\*\.environment\_id | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.error\_message | string | 
action\_result\.data\.\*\.sandbox\.\*\.error\_origin | string | 
action\_result\.data\.\*\.sandbox\.\*\.error\_type | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.description | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.file\_path | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.file\_size | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.runtime\_process | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_files\.\*\.threat\_level\_readable | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.filename | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.process | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.source | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.type | string | 
action\_result\.data\.\*\.sandbox\.\*\.extracted\_interesting\_strings\.\*\.value | string | 
action\_result\.data\.\*\.sandbox\.\*\.file\_size | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.file\_type | string | 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.header | string | 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.host | string |  `hostname` 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.host\_ip | string |  `ip` 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.host\_port | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.method | string | 
action\_result\.data\.\*\.sandbox\.\*\.http\_requests\.\*\.url | string |  `url` 
action\_result\.data\.\*\.sandbox\.\*\.incidents\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.memory\_strings\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.sandbox\.\*\.mitre\_attacks\.\*\.attack\_id | string | 
action\_result\.data\.\*\.sandbox\.\*\.mitre\_attacks\.\*\.tactic | string | 
action\_result\.data\.\*\.sandbox\.\*\.mitre\_attacks\.\*\.technique | string | 
action\_result\.data\.\*\.sandbox\.\*\.network\_settings | string | 
action\_result\.data\.\*\.sandbox\.\*\.pcap\_report\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.command\_line | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.file\_accesses\.\*\.mask | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.file\_accesses\.\*\.path | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.file\_accesses\.\*\.type | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.handles\.\*\.id | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.handles\.\*\.path | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.handles\.\*\.type | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.icon\_artifact\_id | string |  `crowdstrike artifact id` 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.normalized\_path | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.pid | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.process\_flags\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.key | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.operation | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.path | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.registry\.\*\.value | string | 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sandbox\.\*\.processes\.\*\.uid | string | 
action\_result\.data\.\*\.sandbox\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.attack\_id | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.category | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.description | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.identifier | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.name | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.origin | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.relevance | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.threat\_level | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.threat\_level\_human | string | 
action\_result\.data\.\*\.sandbox\.\*\.signatures\.\*\.type | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.submission\_type | string | 
action\_result\.data\.\*\.sandbox\.\*\.submit\_name | string | 
action\_result\.data\.\*\.sandbox\.\*\.submit\_url | string |  `url` 
action\_result\.data\.\*\.sandbox\.\*\.threat\_score | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.verdict | string | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_bitness | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_edition | string | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_name | string | 
action\_result\.data\.\*\.sandbox\.\*\.windows\_version\_version | string | 
action\_result\.data\.\*\.user\_id | string | 
action\_result\.data\.\*\.user\_name | string | 
action\_result\.data\.\*\.user\_tags | string | 
action\_result\.data\.\*\.user\_uuid | string | 
action\_result\.data\.\*\.verdict | string | 
action\_result\.summary\.total\_reports | numeric | 
action\_result\.summary\.verdict | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'check status'
To check detonation status of the provided resource id

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**resource\_id** |  required  | Id of the resource | string |  `crowdstrike resource id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.resource\_id | string |  `crowdstrike resource id` 
action\_result\.data | string | 
action\_result\.data\.\*\.cid | string | 
action\_result\.data\.\*\.created\_timestamp | string |  `date` 
action\_result\.data\.\*\.id | string |  `crowdstrike resource id` 
action\_result\.data\.\*\.origin | string | 
action\_result\.data\.\*\.sandbox\.\*\.action\_script | string | 
action\_result\.data\.\*\.sandbox\.\*\.command\_line | string | 
action\_result\.data\.\*\.sandbox\.\*\.enable\_tor | boolean | 
action\_result\.data\.\*\.sandbox\.\*\.environment\_id | numeric | 
action\_result\.data\.\*\.sandbox\.\*\.network\_settings | string | 
action\_result\.data\.\*\.sandbox\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.sandbox\.\*\.submit\_name | string | 
action\_result\.data\.\*\.sandbox\.\*\.url | string |  `url` 
action\_result\.data\.\*\.state | string | 
action\_result\.data\.\*\.user\_id | string | 
action\_result\.data\.\*\.user\_name | string | 
action\_result\.data\.\*\.user\_uuid | string | 
action\_result\.summary\.state | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get device scroll'
Search for hosts in your environment by platform, hostname, IP, and other criteria with continuous pagination capability \(based on offset pointer which expires after 2 minutes with no maximum limit\)

Type: **investigate**  
Read only: **True**

More info can be found at <a href='https\://assets\.falcon\.crowdstrike\.com/support/api/swagger\.html\#/hosts/QueryDevicesByFilterScroll' target='\_blank'>here</a>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**offset** |  optional  | The offset to page from, for the next result set | string | 
**limit** |  optional  | The maximum records to return\. \[1\-5000\] | numeric | 
**sort** |  optional  | The property to sort by \(e\.g\. status\.desc or hostname\.asc\) | string | 
**filter** |  optional  | The offset to page from, for the next result set | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.filter | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.offset | string | 
action\_result\.parameter\.sort | string | 
action\_result\.data\.\*\.errors\.\*\.code | string | 
action\_result\.data\.\*\.errors\.\*\.id | string | 
action\_result\.data\.\*\.errors\.\*\.message | string | 
action\_result\.data\.\*\.meta\.pagination\.expires\_at | numeric | 
action\_result\.data\.\*\.meta\.pagination\.limit | string | 
action\_result\.data\.\*\.meta\.pagination\.offset | string | 
action\_result\.data\.\*\.meta\.pagination\.total | numeric | 
action\_result\.data\.\*\.meta\.powered\_by | string | 
action\_result\.data\.\*\.meta\.query\_time | numeric | 
action\_result\.data\.\*\.meta\.trace\_id | string | 
action\_result\.data\.\*\.resources | string |  `crowdstrike device id` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get zta data'
Get Zero Trust Assessment data for one or more hosts by providing agent IDs \(AID\)

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**agent\_id** |  required  | Agent ID to get zero trust assessment data about\. Comma\-separated list allowed | string |  `crowdstrike device id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.agent\_id | string |  `crowdstrike device id` 
action\_result\.data\.\*\.aid | string |  `crowdstrike device id` 
action\_result\.data\.\*\.assessment\.os | numeric | 
action\_result\.data\.\*\.assessment\.overall | numeric | 
action\_result\.data\.\*\.assessment\.sensor\_config | numeric | 
action\_result\.data\.\*\.assessment\.version | string | 
action\_result\.data\.\*\.assessment\_items\.os\_signals\.\*\.criteria | string | 
action\_result\.data\.\*\.assessment\_items\.os\_signals\.\*\.group\_name | string | 
action\_result\.data\.\*\.assessment\_items\.os\_signals\.\*\.meets\_criteria | string | 
action\_result\.data\.\*\.assessment\_items\.os\_signals\.\*\.signal\_id | string | 
action\_result\.data\.\*\.assessment\_items\.os\_signals\.\*\.signal\_name | string | 
action\_result\.data\.\*\.assessment\_items\.sensor\_signals\.\*\.criteria | string | 
action\_result\.data\.\*\.assessment\_items\.sensor\_signals\.\*\.group\_name | string | 
action\_result\.data\.\*\.assessment\_items\.sensor\_signals\.\*\.meets\_criteria | string | 
action\_result\.data\.\*\.assessment\_items\.sensor\_signals\.\*\.signal\_id | string | 
action\_result\.data\.\*\.assessment\_items\.sensor\_signals\.\*\.signal\_name | string | 
action\_result\.data\.\*\.cid | string |  `crowdstrike customer id` 
action\_result\.data\.\*\.event\_platform | string | 
action\_result\.data\.\*\.modified\_time | string | 
action\_result\.data\.\*\.product\_type\_desc | string | 
action\_result\.data\.\*\.sensor\_file\_status | string | 
action\_result\.data\.\*\.system\_serial\_number | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 