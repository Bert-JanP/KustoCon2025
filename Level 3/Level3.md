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