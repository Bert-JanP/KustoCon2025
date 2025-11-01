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