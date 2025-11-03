# Stage 1 Tasks

## Task 1.1 – Identify the targeted mailbox and the phishing lure

Your goals in this task:
- Confirm which user was targeted (this becomes Target Account A).
- Capture basic metadata about the message.
- Get the correlation handle (`NetworkMessageId`) that you'll use in later pivots.

<details>
<summary>Tip 1.1.1</summary>

Use the `EmailEvents` table to locate the suspicious inbound message in the investigation window.

</details>

<details>
<summary>Tip 1.1.2</summary>

From `EmailEvents`, extract:

- RecipientEmailAddress → Target Account A.
- Subject → this should show urgency, e.g. "Emergency Password Reset".
- SenderDisplayName and SenderFromAddress.
- SenderFromDomain.
- Timestamp.
- NetworkMessageId.

This proves that a high-value user received an urgent reset-style mail from an external sender.
</details>

<details>
<summary>Tip 1.1.3</summary>

Suggested starting query (time-bounded):

```kql
EmailEvents
| where Timestamp between(datetime(20251101205500) .. datetime(20251101205700))
```
</details>

<details>
<summary>Tip 1.1.4</summary>
You can also pivot directly on the known ID:

```kql
EmailEvents
| where Timestamp between(datetime(20251101205500) .. datetime(20251101205700))
| where NetworkMessageId == "7af5e108-f816-4b19-ff4e-08de1988d35e"
```
</details>


<details>
<summary>Result 1.1.1</summary>

What you should be able to observe from the dataset:

- RecipientEmailAddress `charly@acompanylikeyours.com` → this will be `Target Account A`.
- Subject = `Emergency Password Reset`.
- SenderDisplayName = `Gianni Castaldi`.
- SenderFromAddress = `evilhacker@kustoworks.com`.
- SenderFromDomain = `kustoworks.com`.
- NetworkMessageId = `7af5e108-f816-4b19-ff4e-08de1988d35e`.

Notice how the display name looks trustworthy, but the domain is clearly external.
</details>


# Task 1.2 – Prove the user actually engaged (endpoint evidence)

Your goals in this task:

- Show that the targeted user actually interacted with the message on their endpoint.
- Show that the mail client caused a browser session to open.

<details>
<summary>Tip 1.2.1</summary>

Use the `DeviceEvents` table. Stay in (roughly) the same time window you used for `EmailEvents`.
</details>

<details>
<summary>Tip 1.2.2</summary>

From `DeviceEvents`, extract:

- `Timestamp` of the event.
- `DeviceName` (which endpoint was used).
- `ActionType` (what happened).
- `InitiatingProcessCommandLine` (which process caused it).
  
This shows the user opened content from the email and the system launched a browser to follow that link.
</details>

<details>
<summary>Tip 1.2.3</summary>

Suggested starting query:

```kql
DeviceEvents
| where Timestamp between(datetime(20251101205500) .. datetime(20251101205700))
```
</details> 


<details>
<summary>Result 1.2.1</summary>

What you should be able to observe from the dataset:

- DeviceName = `vm-w11.acompanylikeyours.com`.
- ActionType = `BrowserLaunchedToOpenUrl`.
- InitiatingProcessCommandLine includes `olk.exe` (Outlook).
- Timestamp around `2025-11-01 21:56:16`.

This ties the phishing email to live user interaction on a corporate endpoint: Outlook launched the browser as a result of the user engaging with the message.
</details>

# Task 1.3 – Prove the malicious link was clicked (mail telemetry evidence)

Your goals in this task:
-Show that the message from Task 1.1 led to a link click.
-Tie that click back to the exact same message using `NetworkMessageId`.


<details>
<summary>Tip 1.3.1</summary>

Use the `UrlClickEvents` table. Correlate using the `NetworkMessageId` you identified in Task 1.1. 
</details> 

<details> 
<summary>Tip 1.3.2</summary> 

From `UrlClickEvents`, extract:

- `Timestamp`.
- `ActionType` (for example `ClickAllowed`).
- `NetworkMessageId` (to prove it’s the same email).
- Any available `RemoteUrl` / `RemoteIP` for the clicked destination.

This proves the user followed the attacker’s link, not just opened Outlook.
</details>

<details> 
<summary>Tip 1.3.3</summary>

Suggested starting query:

```kql
UrlClickEvents
| where NetworkMessageId == "7af5e108-f816-4b19-ff4e-08de1988d35e"
| where Timestamp between(datetime(20251101205500) .. datetime(20251101205700))
```
</details>


<details>
<summary>Result 1.3.1</summary>

What you should be able to observe from the dataset:

- ActionType = `ClickAllowed`.
- Multiple clicks recorded within seconds (for example `21:56:21`, `21:56:22`, `21:56:32`).
- All tied to NetworkMessageId = `7af5e108-f816-4b19-ff4e-08de1988d35e`.
- The clicked URL: `https://login.m365-authentication.net/tCMwXwBx`

This confirms that:

- The user clicked the link from the phishing email.
- The destination was a fake login page hosted at login.m365-authentication.net.

IP resolution for this hostname is not part of the provided dataset and would normally be done using DNS/network tooling outside this KQL scope.

For reference in this incident:

- Hostname observed: `login.m365-authentication.net`.
- IP: `4.210.146.4`.
- This is not a Microsoft-owned or corporate-owned identity provider. It is attacker infrastructure.
</details>

# Task 1.4 – Detection engineering note

Your goals in this task:
- Decide if this sequence would trigger an alert today.
- Describe the shape of a high-fidelity analytic rule that would have caught it early.

<details> 
<summary>Notes</summary> 

Consider this timeline:

- A privileged admin mailbox receives an email with an urgent “password reset / security incident” subject from an external domain.
- Within about a minute, the same admin’s workstation launches a browser from Outlook.
- `UrlClickEvents` shows `ActionType = ClickAllowed` for that same `NetworkMessageId`.

Think in terms of joining tables, not single signals:

- `EmailEvents`
  - High-value recipient
  - Urgent security/reset subject
  - External sender domain

- `UrlClickEvents`
  - ClickAllowed
  - Same NetworkMessageId
  - Click within N seconds of delivery

`DeviceEvents`
- `BrowserLaunchedToOpenUrl`
- Initiating process `olk.exe` on the admin’s device

A mature analytic here would:

- Treat privileged recipients as a high-risk population.
- Look for:
  - Urgent security/reset subject lines from external domains in `EmailEvents`.
  - A `ClickAllowed` action in `UrlClickEvents` with the same `NetworkMessageId` within a short window (for example 60 seconds).
  - A corresponding `BrowserLaunchedToOpenUrl` from Outlook (`olk.exe`) on that user’s device in `DeviceEvents`.

This three-way correlation is rare and very high signal for:

```text
A privileged admin just clicked an urgent external reset link and opened a browser to attacker infrastructure.
```

When you have:

- Identified Target Account A,
- Proven that they clicked,
- Captured attacker infrastructure indicators,

proceed to [Stage 2](../Stage2/README.md).
