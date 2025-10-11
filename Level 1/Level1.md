# Level 1

Welcome to KustoCon! In level 1 we dive into the world of ClickFix, this growing social engineering technique is on the rise since this year. The technique abuses the windows run functionality to drop malware onto systems. It is your job to investigate this using **KQL** and to build a solid detection for it.

⚠️ This exercise uses real malware samples, do not download files unless you are sure you accept the risk of being hacked.

![Alt text](../Images/ClickFix.png)

Related links:
- https://kqlquery.com/posts/investigate-clickfix/
- https://clickfix.carsonww.com/
- https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/?msockid=226f755d7be7693e3414600b7a0a6869

### Host
| DeviceName  | DeviceId |
|-------|-----|
| kustocon-level1 | 6d99a2b880a14561f58d9b4d1292b63cbc9a51ec  |

# ClickFix Triage
The [ClickFix Triage Query](https://kqlquery.com/posts/investigate-clickfix/) has been published to help analyst triage clickfix incident. Investigate the query and understand how each part operates.

```KQL
// Input variables
let VictimDeviceId = "6d99a2b880a14561f58d9b4d1292b63cbc9a51ec";
let TopXEvents = 15;
let TimeFrame = 5m;
// Input parameters for the forensic hunting query
let Parameters = dynamic(['http', 'https', 'Encoded', 'EncodedCommand', '-e', '-eC', '-enc', "-w", 'iex']);
let Executables = dynamic(["cmd", "powershell", "curl", "mshta"]);
let FilteredSIDs = dynamic(["S-1-5-18"]);
let RegKeyEvents =
 DeviceRegistryEvents
 | where DeviceId =~ VictimDeviceId
 | where ActionType == "RegistryValueSet"
 | where RegistryKey has "RunMRU"
 | where RegistryValueData has_any (Parameters) and RegistryValueData has_any (Executables)
 | extend LogType = "☢️ RunMRU Event"
 | project Timestamp, DeviceId, DeviceName, RegistryValueData, RegistryKey, LogType;
let RegKeyEventTimestamp = toscalar (RegKeyEvents | summarize Timestamp = max(Timestamp));
let NetworkEventsParser = materialize (DeviceNetworkEvents
 | where DeviceId =~ VictimDeviceId
 | where not(InitiatingProcessAccountSid in~ (FilteredSIDs))
 | where isnotempty(RemoteUrl)
 | extend MatchTimeStamp = RegKeyEventTimestamp
 | project Timestamp, RemoteIP, RemoteUrl, ReportId, DeviceId, DeviceName, MatchTimeStamp, InitiatingProcessCommandLine);
let PreInfectionNetworkEvents =
 NetworkEventsParser
 | where Timestamp between ((MatchTimeStamp - TimeFrame) .. MatchTimeStamp)
 | top TopXEvents by Timestamp desc
 | extend LogType = "🛜 Pre Infection Network Event";
let PostInfectionNetworkEvents =
 NetworkEventsParser
 | where Timestamp between (MatchTimeStamp .. (MatchTimeStamp + TimeFrame))
 | top TopXEvents by Timestamp asc
 | extend LogType = "🛜 Post Infection Network Event";
let PostInfectionProcessEvents = DeviceProcessEvents
 | where DeviceId =~ VictimDeviceId
 | where Timestamp between (RegKeyEventTimestamp .. (RegKeyEventTimestamp + TimeFrame))
 | top TopXEvents by Timestamp asc
 | where not(InitiatingProcessAccountSid in~ (FilteredSIDs))
 | extend LogType = "♻️ Post Infection Process Event"
 | project Timestamp, ReportId, LogType, DeviceId, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine;
let PostInfectionFileEvents = DeviceFileEvents
 | where DeviceId =~ VictimDeviceId
 | where Timestamp between (RegKeyEventTimestamp .. (RegKeyEventTimestamp + TimeFrame))
 | top TopXEvents by Timestamp asc
 | where not(InitiatingProcessAccountSid in~ (FilteredSIDs))
 | extend LogType = "📁 Post Infection File Event"
 | project Timestamp, ReportId, LogType, DeviceId, DeviceName, ActionType, InitiatingProcessCommandLine, FolderPath;
union isfuzzy=false PreInfectionNetworkEvents,RegKeyEvents, PostInfectionNetworkEvents, PostInfectionProcessEvents, PostInfectionFileEvents
| sort by Timestamp asc
| project-reorder Timestamp, DeviceId, DeviceName, LogType, RemoteUrl, RegistryValueData, ProcessCommandLine, FolderPath, InitiatingProcessCommandLine
```

# Persitence 

## .lnk file on desktop from AppData
A user called the servicedesk because a new item appeared on his desktop. You have been called to investigate what happened.

<details>
<summary>Tip 1</summary>
Find the table that has the ActionType *ShellLinkCreateFileEvent* - A specially crafted link file (.lnk) was generated. The link file contains unusual attributes that might launch malicious code along with a legitimate file or application.
</details>

<details>
<summary>Tip 2</summary>
The application in installed in the AppData folder, this has its reasons. Use this information to build a detection.
</details>

<details>
<summary>Answer</summary>

```KQL
let Threshold = 1000;
DeviceEvents
| where ActionType =~ "ShellLinkCreateFileEvent"
| where FolderPath has "Desktop"
| extend ShellLinkIconPath = parse_json(AdditionalFields).ShellLinkIconPath, ShellLinkWorkingDirectory = parse_json(AdditionalFields).ShellLinkWorkingDirectory
| where ShellLinkWorkingDirectory has "AppData"
// Enrich data with FileProfile
| invoke FileProfile(InitiatingProcessSHA256, 10000)
| where GlobalPrevalence <= Threshold
```
</details>

## Another Persitence Mechanism
The threat actor managed to install a persitence mechanism on the endpoint. Build a query to list this persitence mechanism.

<details>
<summary>Tip 1</summary>
Have a look at the created scheduled tasks on this device.
</details>

# Extend more and with SCAN for advanced

<details>
<summary>Answer</summary>

```KQL
let Filters = dynamic(['AppData', '%localappdata%', '%appdata%']);
DeviceEvents
| where ActionType in ('ScheduledTaskCreated', 'ScheduledTaskUpdated')
| where AdditionalFields has_any (Filters)
| extend ParsedAdditionalFields = parse_json(AdditionalFields)
| extend ScheduledTaskName = ParsedAdditionalFields.TaskName, Details = parse_json(ParsedAdditionalFields.TaskContent)
| project-reorder Timestamp, DeviceName, ActionType, InitiatingProcessAccountUpn, ScheduledTaskName, Details
```
</details>

WMI operations