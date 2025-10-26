# Level 2

In the second level fake pdf converter software is installed on a worksation. It is your job to figure out what this software does and how you can detect such and other potentially malicious/unwanted applications.

⚠️ This exercise uses real malware samples, do not download files unless you are sure you accept the risk of being hacked.

![Alt text](../Images/ManualFinder.png)

Related links:
- https://www.trendmicro.com/en_us/research/25/i/evilai.html
- https://www.ncsc.nl/actueel/nieuws/2025/08/29/nieuwe-malwarecampagne-ontdekt-via-manualfinder
- https://www.truesec.com/hub/blog/tamperedchef-the-bad-pdf-editor
- https://expel.com/blog/you-dont-find-manualfinder-manualfinder-finds-you/

### Host
| DeviceName  | DeviceId |
|-------|-----|
| kustocon-level2 | 0dc945819ed7b009e2a6c943dd1008e8524734da  |

# Persitence 

## .lnk file on desktop from AppData
A user called the servicedesk because a new item appeared on his desktop. You have been called to investigate what happened.

<details>
<summary>Tip 1</summary>
Find the table that has the ActionType ShellLinkCreateFileEvent - A specially crafted link file (.lnk) was generated. The link file contains unusual attributes that might launch malicious code along with a legitimate file or application.
</details>

<details>
<summary>Tip 2</summary>
The application in installed in the AppData folder, this has its reasons. Use this information to build a detection.
</details>

<details>
<summary>Answer</summary>

```KQL
let Threshold = 2500; //The number has been increased from 1000 to 2500, due to the large amount of infections. Normally you want to keep it at 1000 or lower to prevent FPs.
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
The threat actor managed to install a persitence mechanism on the endpoint. Investiagte the activities of the threat actor. Build a query to list this persitence mechanism.

<details>
<summary>Tip 1</summary>
A quick way to investigate what a file did is to combine all EDR logs and list based on Table, ActionType, ProcessCommandLine and InitiatingProcessCommandLine. Note that this query does not scale well if you have large scale infections ;). 

The malware consists out of two executables pdfclick.exe and PDFClickUpdater.exe. Use the results below to hunt down the persitence mechanism.

```KQL
let SuspiciousFileNames = dynamic(['pdfclick.exe', 'PDFClickUpdater.exe']);
union Device*
| where FileName in~ (SuspiciousFileNames) or InitiatingProcessFileName in~ (SuspiciousFileNames)
| project-reorder Timestamp, Type, ActionType, ProcessCommandLine, InitiatingProcessCommandLine
| sort by Timestamp asc 
```

If you do not find you answer here, you may want to have a look at the device timeline. Yes there are events/data in the timeline that is not forwarded to advanced hunting.

</details>

<details>
<summary>Tip 2</summary>
Have a look at the created scheduled tasks on this device.
</details>


<details>
<summary>Tip 3</summary>
Parse the fiels from the AdditionalFields column to get a good understanding of the contents of the scheduled task.
</details>


<details>
<summary>Tip 4</summary>
Parsed AdditionalFields

```KQL
| extend TaskName = parse_json(AdditionalFields).TaskName, TaskContent = tostring(parse_json(AdditionalFields).TaskContent), SubjectUserName = parse_json(AdditionalFields).SubjectUserName
| extend Actions = extractjson("$.Actions", TaskContent), Triggers = extractjson("$.Triggers", TaskContent)
| extend Command =  parse_json(Actions).Exec.Command, Arguments = parse_json(Actions).Exec.Arguments
```
</details>

<details>
<summary>Answer</summary>

```KQL
let Filters = dynamic(['AppData', '%localappdata%', '%appdata%']);
DeviceEvents
| where ActionType in ('ScheduledTaskCreated', 'ScheduledTaskUpdated')
| where AdditionalFields has_any (Filters)
| extend TaskName = parse_json(AdditionalFields).TaskName, TaskContent = tostring(parse_json(AdditionalFields).TaskContent), SubjectUserName = parse_json(AdditionalFields).SubjectUserName
| extend Actions = extractjson("$.Actions", TaskContent), Triggers = extractjson("$.Triggers", TaskContent)
| extend Command =  parse_json(Actions).Exec.Command, Arguments = parse_json(Actions).Exec.Arguments
| project-reorder Timestamp, DeviceName, ActionType, InitiatingProcessAccountUpn, TaskName, Command, Arguments
```

</details>

## Bonus
It is not just a pdf converter, there is more to be found in this interesting case. The malware was able to modify its current access token. Can you identify what permissions were added to the *PDFClickUpdater.exe* process?

Related link: https://downloads.volatilityfoundation.org//omfw/2012/OMFW2012_Gurkok.pdf

<details>
<summary>Tip 1</summary>
Investigate the DeviceEvents table in combination with the ProcessPrimaryTokenModified ActionType.

```KQL
DeviceEvents
| where ActionType == "ProcessPrimaryTokenModified"
```

</details>

<details>
<summary>Tip 2</summary>
The application in installed in the AppData folder, this has its reasons. Use this information to build a detection.
</details>

<details>
<summary>Tip 3</summary>
The Privilege Data Model in the link below can be used to determine which privilige has been added to the token. The LUID column can be used to calculate the difference using [binary_shift_left(1, LUID)](https://learn.microsoft.com/en-us/kusto/query/binary-shift-left-function?view=microsoft-fabric).

Link:
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/1a92af76-d45f-42c3-b67c-f1dc61bd6ee1

</details>

<details>
<summary>Answer</summary>

```KQL
let SeDebugPriv = binary_shift_left(1, 20);
DeviceEvents
| where ActionType == "ProcessPrimaryTokenModified"
| extend CurrentTokenPrivEnabled = tolong(parse_json(AdditionalFields).CurrentTokenPrivEnabled), OriginalTokenPrivEnabled = tolong(parse_json(AdditionalFields).OriginalTokenPrivEnabled)
| extend PrivilegeDiff = binary_xor(OriginalTokenPrivEnabled, CurrentTokenPrivEnabled)
| where PrivilegeDiff == SeDebugPriv
```
</details>