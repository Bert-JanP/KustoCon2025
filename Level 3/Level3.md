# Level 3

In the third level we dive into the world of the intial infection. The starting point is the below image your Threat Intelligence team has recieved from the national NCSC. It is your job to hunt down the compromised workstation and determine what happened using some Kusto queries. The initial access broker is selling the access to the highest, make sure you hunt them down before someone buys the access.

![Alt text](../Images/Sliver.png)

Related links:
- https://sliver.sh/docs?name=Getting+Started

### Host
| DeviceName  | DeviceId |
|-------|-----|
| kustocon-level3 | 8db4ea361ed781554b9abab944109acb99d14022  |

# Defense Evasion 

The attacker managed to land a beacon on kustocon-level3. EDR would not allow default sliver beacons to be installed. Investigate the logs to find out why the beacon could be downloaded. Build a detection to list the tamper events used in this attack chain.

<details>
<summary>Tip 1</summary>
Attackers try to exclude their malware to evade detection. This can for example be done using Set-MpPreference and Add-MpPreference.

Links:
- https://learn.microsoft.com/en-us/powershell/module/defender/add-mppreference?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2025-ps
- 
</details>

<details>
<summary>Tip 2</summary>
The code snippet below could be used to list exclusion attempts, however in this case the exclusion was not added directly in the commandline. The data is stored in a different table than the DeviceProcessEvents.

```KQL
let ExclusionOptions = dynamic(['ExclusionPath', 'ExclusionExtension', 'ExclusionProcess', 'ExclusionIpAddress']);
DeviceProcessEvents
| where ProcessCommandLine has_any ('Add-MpPreference','Set-MpPreference') and ProcessCommandLine has_any (ExclusionOptions)
```

Make sure that both methods are covered in your hunting query.
</details>

<details>
<summary>Answer</summary>

```KQL
let ExclusionOptions = dynamic(['ExclusionPath', 'ExclusionExtension', 'ExclusionProcess', 'ExclusionIpAddress']);
let Modules = dynamic(['Add-MpPreference','Set-MpPreference']);
let CommandLineExecutions = DeviceProcessEvents
| where ProcessCommandLine has_any (Modules) and ProcessCommandLine has_any (ExclusionOptions);
let PowerShellExecutions = DeviceEvents
| where ActionType == 'PowerShellCommand' 
| where AdditionalFields  has_any (Modules) and AdditionalFields has_any (ExclusionOptions);
union PowerShellExecutions, CommandLineExecutions
```
</details>

# Alerts
Based on the [triggered incident](https://security.microsoft.com/incident2/129/overview?tid=a4be6261-d211-4df1-852e-c597a96ad887) it seems that malware was installed and we have the following indicators:
- Malware was installed from a ZIP Archive
- Suspicious Scheduled Task was created
- SuspGoLang malware was identified

# Persitence 
You may already have identified that *kustocon-level3* showed up in the scheduled task results. Run the query from [level2](../Level%202/Level2.md) again to identify what scheduled task was used here to establish persitence.

# Sliver Beacon Detection
The alerts from EDR do not indicate that a beacon has been installed, malware was detected but outbound traffic is not mapped to the incident. A sliver beacon performs a specific sequience of activities when it is executed for the first time on a device. Use the KQL [scan](https://learn.microsoft.com/en-us/kusto/query/scan-operator?view=microsoft-fabric) operator to detect the sequence of activities.

1. Outbound connection to C2 Server
2. \wkssvc namedpipe created
3. Security Access Manager loaded (samlib.dll)

<details>
<summary>Tip 1</summary>
Start with the following queries and filter based on the name of the Sliver Beacon.

```KQL
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"

DeviceImageLoadEvents
| where ActionType == 'NamedPipeEvent'

DeviceEvents
| where ActionType == 'NamedPipeEvent'
```

</details>


<details>
<summary>Tip 2</summary>

Add filters to the sub queries to make them filter only on the desired activities. Use union to combine the three different results and sort them by time.

</details>

<details>
<summary>Tip 3</summary>

Some examples of how to use scan can be found here: https://sandyzeng.gitbook.io/kql/kql-quick-guide/need-to-learn-later/scan

</details>

<details>
<summary>Answer</summary>

```KQL
let ImageLoads = DeviceImageLoadEvents
| where ActionType == 'ImageLoaded'
| where FileName =~ "samlib.dll"
| invoke FileProfile(InitiatingProcessSHA256, 1000)
| where GlobalPrevalence <= 50 or isempty(GlobalPrevalence)
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessAccountSid;
let NamedPipes = DeviceEvents
| where ActionType == 'NamedPipeEvent'
| where parse_json(AdditionalFields).PipeName == @"\Device\NamedPipe\wkssvc"
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessAccountSid, PipeName = parse_json(AdditionalFields).PipeName;
let Connection = DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| project Timestamp, DeviceId, DeviceName, ActionType, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessAccountSid;
union NamedPipes, ImageLoads, Connection
| sort by Timestamp asc, DeviceId, InitiatingProcessSHA256
| scan with_match_id=Id declare (Step:string, Delta:timespan) with (
    step InitialConnection: ActionType == "ConnectionSuccess" => Step = "s1";
    step NamedPipe: ActionType == 'NamedPipeEvent' and DeviceId == InitialConnection.DeviceId and InitiatingProcessSHA256 == InitialConnection.InitiatingProcessSHA256 and Timestamp between (Timestamp .. datetime_add('second', 1, InitialConnection.Timestamp)) and InitiatingProcessAccountSid == InitialConnection.InitiatingProcessAccountSid => Step = 's2', Delta = Timestamp - InitialConnection.Timestamp;
    step ImageLoad: ActionType == 'ImageLoaded' and DeviceId == NamedPipe.DeviceId and InitiatingProcessSHA256 == NamedPipe.InitiatingProcessSHA256 and Timestamp between (Timestamp .. datetime_add('second', 1, NamedPipe.Timestamp)) and InitiatingProcessAccountSid == NamedPipe.InitiatingProcessAccountSid  => Step = 's3', Delta = Timestamp - NamedPipe.Timestamp;
)
| where Step == 's3'
```
</details>


