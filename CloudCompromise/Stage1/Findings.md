# Stage 1 – Findings (Trainer / Solution Reference)

## Narrative

In this stage you are proving that a high-value admin account was lured by a phishing mail and actually interacted with it from their corporate endpoint.

### 1. Targeted mailbox and lure

From **EmailEvents** in the Nov 5, 2025 08:32 timeframe you can see:

- **RecipientEmailAddress**: `charly@acompanylikeyours.com`  → this is **Target Account A**.
- **Subject**: `Emergency Password Reset`.
- **SenderDisplayName**: `Gianni Castaldi`.
- **SenderFromAddress**: `gianni@kustoworks.com`.
- **SenderFromDomain**: `kustoworks.com` (external, not the corporate mail domain).
- **NetworkMessageId**: `afb760df-808f-4ded-eb50-08de1c45ae82`.
- **TimeGenerated**: `2025-11-05 08:32:30`.

So a privileged user (Charly) receives an **urgent password/security reset mail** impersonating a trustworthy internal contact, but from an external domain.

### 2. Endpoint evidence – user actually opened the link

From **DeviceEvents** around the same time window (`~08:32`), you can see for host `vm-w11.acompanylikeyours.com`:

- **ActionType**: `BrowserLaunchedToOpenUrl`.
- **InitiatingProcessCommandLine**: ends with `olk.exe` (Outlook).
- **TimeGenerated**: `2025-11-05 08:32:39`.

This shows Outlook on Charly’s workstation directly launching a browser – a strong indicator that **the user interacted with email content containing a link**.

### 3. Mail telemetry – link clicks on the phishing URL

From **UrlClickEvents** pivoting on the **same NetworkMessageId**:

- `NetworkMessageId = "afb760df-808f-4ded-eb50-08de1c45ae82"`.
- `ActionType = "ClickAllowed"`.
- `TimeGenerated` around:
  - `2025-11-05 08:32:40`,
  - `2025-11-05 08:33:06`.
- `Url = "https://login.m365-authentication.net/tCMwXwBx"`.

This confirms that:

- The phishing message was not only delivered but **clicked**.
- The destination was an external site impersonating Microsoft sign-in: `login.m365-authentication.net`.
- The email click and the `BrowserLaunchedToOpenUrl` from Outlook are tightly clustered in time.

In the lab context, `login.m365-authentication.net` resolves to infrastructure controlled by the adversary (later correlated with IP `4.210.146.4` in Stage 2).

---

## MITRE ATT&CK mapping

- **T1566.002 – Spearphishing Link**  
  Tailored email to a privileged admin, using a malicious link to a fake M365 authentication site.

- **T1204.001 – User Execution: Malicious Link**  
  User interaction on the endpoint (`BrowserLaunchedToOpenUrl` from Outlook) leads to execution of the phishing flow.

---

## Key takeaways for students

By the end of Stage 1 they should be able to state:

1. **Who was targeted?**  
   - `charly@acompanylikeyours.com` (Target Account A), a privileged admin user.

2. **What was the lure?**  
   - A high-urgency “Emergency Password Reset” email, allegedly related to a security incident, sent by “Gianni Castaldi” from `kustoworks.com`.

3. **Did the user interact with it?**  
   - Yes. Outlook on `vm-w11.acompanylikeyours.com` launched a browser (`BrowserLaunchedToOpenUrl`), and `UrlClickEvents` show `ClickAllowed` for the malicious URL `https://login.m365-authentication.net/tCMwXwBx` for the same `NetworkMessageId`.

This sets up Stage 2, where you show how that click leads into real cloud sign-ins and token abuse.
