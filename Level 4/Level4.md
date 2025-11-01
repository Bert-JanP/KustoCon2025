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

# Beacon Hunting
There is no one size fits all when it comes to detection beaconing activities, there are a couple reasons for this:
1. Beacons can be configured with different timeframes to call home
2. Beacons have different jitters to make sure that the interval between the calls is different
3. C2 connections can be configured to a single IP/Domain or to multiple forwarders, making it even harder to detect beaconing activities.
4. Depending on the time a threat actor has they can have very few connections per day, for example only calling home once every day would be very hard to detect.


## Rare Executables Beaconing

Use the variables below as starting point to detect beaconing activities from rare executables.

```KQL
let DeviceThreshold = 5;
let TimeFrame = 10d;
let ConnectionThreshold = 25;
let GlobalPrevalanceThreshold = 250;
```

<details>
<summary>Tip 1</summary>

Use the device events and only filter on public IPv4 addresses.

```KQL
DeviceNetworkEvents
| where Timestamp > ago(TimeFrame)
| where not(ipv4_is_private(RemoteIP))
| where ActionType == "ConnectionSuccessAggregatedReport"
```

</details>

<details>
<summary>Tip 2</summary>

Summarize the results by day while keeping the variables mentioned above in mind.

</details>


<details>
<summary>Tip 3</summary>

Join the baseline with the ConnectionSuccess events in the DeviceNetworkEvents to get SHA256 information needed to enrich the results to find rare executables.

```KQL
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
```

</details>


<details>
<summary>Answer</summary>

```KQL
let DeviceThreshold = 5;
let TimeFrame = 10d;
let ConnectionThreshold = 25;
let GlobalPrevalanceThreshold = 250;
DeviceNetworkEvents
| where Timestamp > ago(TimeFrame)
| where not(ipv4_is_private(RemoteIP))
| where ActionType == "ConnectionSuccessAggregatedReport"
| extend Connections = toint(parse_json(AdditionalFields).uniqueEventsAggregated)
| summarize Total = count(), Devices = dcount(DeviceId), Domains = make_set(RemoteUrl), AvgConnections = avg(Connections) by RemoteIP, bin(TimeGenerated, 1d)
| where AvgConnections >= ConnectionThreshold and Devices <= DeviceThreshold
| join kind=inner (DeviceNetworkEvents
    | where ActionType == "ConnectionSuccess"
    | distinct RemoteIP, InitiatingProcessSHA256) on RemoteIP
    | invoke FileProfile(InitiatingProcessSHA256)
    | where GlobalPrevalence <= GlobalPrevalanceThreshold
```

</details>


