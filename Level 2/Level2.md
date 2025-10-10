# Level 2

## .lnk file on desktop from AppData

<details>
<summary>Tip 1</summary>
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