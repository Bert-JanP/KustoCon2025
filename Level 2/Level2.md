# Level 2

## .lnk file on desktop from AppData

<details>
<summary>Tip 1</summary>
Find the table that has the ActionType *ShellLinkCreateFileEvent* - A specially crafted link file (.lnk) was generated. The link file contains unusual attributes that might launch malicious code along with a legitimate file or application.
</details>

<details>
<summary>Answer</summary>

```KQL
DeviceEvents
| where ActionType =~ "ShellLinkCreateFileEvent"
| where FolderPath has "Desktop"
| extend ShellLinkIconPath = parse_json(AdditionalFields).ShellLinkIconPath, ShellLinkWorkingDirectory = parse_json(AdditionalFields).ShellLinkWorkingDirectory
| where ShellLinkWorkingDirectory has "AppData"
```
</details>