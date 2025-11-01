# Level 4

Another device has been infected, the actor managed to keep a sliver beacon running on the workstation *kustocon-level4*. In this level you will be task to detect beaconing activities.

![Alt text](../Images/Sliver.png)

Related links:
- https://sliver.sh/docs?name=Getting+Started
- https://academy.bluraven.io/blog/beaconing-detection-using-mde-aggregated-report-telemetry

### Host
| DeviceName  | DeviceId |
|-------|-----|
| kustocon-level4 | 52a24fa6e782b7525c769c84bc1b02d453a0deae |

# Beacons Beacons Beacons
Start by running the *C2 Beaconing Detection with MDE Aggregated Report Telemetry* query from Mehmet Ergene:
- [Query Link](https://academy.bluraven.io/blog/beaconing-detection-using-mde-aggregated-report-telemetry)

## Visualize Connections
By now you know that the beaconing activity did not only originate from *kustocon-level4* but also from *kustocon-level3*. Filter on *kustocon-level4* only and visualize when the beaconing activities appeared.

<details>
<summary>Tip 1</summary>

Use the DeviceNetworkEvents table and filter on the C2 IP.

</details>

<details>
<summary>Tip 2</summary>
Use the *ConnectionSuccessAggregatedReport* ActionType to extract the number of connections for every hour, this data is located in the *AdditionalFields* column.

```KQL
DeviceNetworkEvents
| where DeviceId == "52a24fa6e782b7525c769c84bc1b02d453a0deae"
| where RemoteIP == "20.80.88.35"
| where ActionType == "ConnectionSuccessAggregatedReport"
```

</details>

<details>
<summary>Answer</summary>

```KQL
DeviceNetworkEvents
| where DeviceId == "52a24fa6e782b7525c769c84bc1b02d453a0deae"
| where RemoteIP == "20.80.88.35"
| where ActionType == "ConnectionSuccessAggregatedReport"
| extend Connections = toint(parse_json(AdditionalFields).uniqueEventsAggregated)
| summarize TotalConnections = sum(Connections) by bin(Timestamp, 1h)
| render columnchart with(title="C2 Connections", xtitle="Time", ytitle="Number of connections")
```
</details>









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
| where isnotempty(InitiatingProcessSHA256)
| invoke FileProfile(InitiatingProcessSHA256, 1000)
| where GlobalPrevalence <= 50 or isempty(GlobalPrevalence)
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessAccountSid;
let NamedPipes = DeviceEvents
| where ActionType == 'NamedPipeEvent'
| where isnotempty(InitiatingProcessSHA256)
| join kind=inner (ImageLoads | distinct InitiatingProcessSHA256) on InitiatingProcessSHA256
| where parse_json(AdditionalFields).PipeName == @"\Device\NamedPipe\wkssvc"
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessAccountSid, PipeName = parse_json(AdditionalFields).PipeName;
let Connection = DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where isnotempty(InitiatingProcessSHA256)
| join kind=inner (ImageLoads | distinct InitiatingProcessSHA256) on InitiatingProcessSHA256
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


