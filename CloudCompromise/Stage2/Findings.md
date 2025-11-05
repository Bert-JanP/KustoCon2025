# Stage 2 – Findings (Trainer / Solution Reference)

## Narrative

In this stage you are linking the phishing click to:

1. A cloud sign-in to a user-facing M365 resource from **phishing infrastructure IP**.
2. A subsequent reuse of the **same session** from a **different attacker IP** to access **Azure Resource Manager (ARM)**.
3. A short but intense burst of **Graph API discovery traffic** consistent with AzureHound.

### 1. From phishing click to OfficeHome sign-in

From **Stage 1**:

- Phishing URL click times: **08:32:40** and **08:33:06** (`UrlClickEvents`).
- Target Account A: `charly@acompanylikeyours.com`.

From **SigninLogs** and **AADSignInEventsBeta** shortly after:

- `UserPrincipalName = "charly@acompanylikeyours.com"`.
- `ResourceDisplayName = "OfficeHome"`.
- `IPAddress = "4.210.146.4"`.
- `SessionId = "00a8a3f9-feac-368d-3a84-178530ea5b8a"` on the key events.
- First appearances around **2025-11-05 08:33–08:34**.

Interpretation:

- Within a couple of minutes of the phishing click, Charly’s identity is used to sign in to **OfficeHome** from **4.210.146.4**.
- `4.210.146.4` is the infrastructure behind `login.m365-authentication.net`, tying the **fake login** directly to actual cloud sign-ins.

### 2. Session reuse from a different IP to Azure Resource Manager

From **AADNonInteractiveUserSignInLogs** and **SigninLogs** for the same identity:

- `UserPrincipalName = "charly@acompanylikeyours.com"`.
- `SessionId = "00a8a3f9-feac-368d-3a84-178530ea5b8a"` (same as OfficeHome).
- `ResourceDisplayName = "Azure Resource Manager"`.
- `IPAddress = "83.97.112.20"` (new IP, attacker workstation).
- Events at:
  - `2025-11-05 08:39:48`,
  - `2025-11-05 08:40:52` (SigninLogs),
  - and further non-interactive ARM calls at `08:59:07` and `08:59:44` (AADNonInteractiveUserSignInLogs).

Key points:

- The **same session** (`SessionId 00a8a3f9-feac-...`) appears first with interactive OfficeHome activity via `4.210.146.4`.
- Shortly after, that session is reused from **a different IP** (`83.97.112.20`) to obtain and use access tokens for **Azure Resource Manager**.
- This is **not** a normal user pattern; it is session / token replay.

### 3. Graph recon burst – AzureHound-style discovery

From **MicrosoftGraphActivityLogs** filtered on the attacker IP:

- `IPAddress = "83.97.112.20"`.
- `TimeGenerated` tightly clustered around **2025-11-05 08:38:09–08:38:13**.
- `AppId = "1950a258-227b-4e31-a9cf-717495945fc2"` (the AzureHound/AzureAD preview app ID).
- `UserAgent = "azurehound/v2.6.0"`.
- `SessionId = "00a8a3f9-feac-368d-3a84-178530ea5b8a"` (same compromised session).

Characteristics:

- Dozens of Graph calls within a ~4-second window.
- All from the **attacker IP** `83.97.112.20`.
- All tied to the same **compromised session id** as the OfficeHome sign-in and ARM usage.

This is characteristic of **AzureHound** running cloud discovery:

- Enumerating directory roles, role templates and members.
- Enumerating service principals and applications.
- Enumerating subscriptions and role assignments.

---

## Why MFA did not trigger

The critical point for students:

- MFA likely fired (or was satisfied) during the **initial phishing / interactive login** flow.
- What you see in the logs after that is **reuse of an already-issued refresh token / session**:
  - OfficeHome via phishing infra (`4.210.146.4`).
  - ARM and Graph via separate attacker IP (`83.97.112.20`).

MFA does **not** re-challenge on every access token mint:

- The attacker is using **T1528 – Steal Application Access Token** and
- **T1550 – Use Alternate Authentication Material** (refresh token / session replay),
- Not re-entering password & MFA each time.

---

## MITRE ATT&CK mapping

- **T1528 – Steal Application Access Token**  
  Stolen refresh token / session from the phishing site.

- **T1550 – Use Alternate Authentication Material**  
  Reusing that session from a different IP to mint tokens for ARM.

- **T1069.003 – Permission Group Discovery (Cloud)**  
  AzureHound-style enumerations of roles, members, and assignments.

- **T1526 – Cloud Service Discovery**  
  Broad discovery of subscriptions, resources, and directory configuration.

---

## Key takeaways for students

By the end of Stage 2 they should be able to state:

1. **The same user account (Charly) and session id are used from two IPs**:  
   - Phishing infrastructure (`4.210.146.4`) → OfficeHome.  
   - Attacker workstation (`83.97.112.20`) → Azure Resource Manager + Graph.

2. **The session (`00a8a3f9-feac-368d-3a84-178530ea5b8a`) is the glue** between:  
   - Phishing click → OfficeHome sign-in,  
   - ARM token usage,  
   - AzureHound Graph discovery from `83.97.112.20`.

3. **This is post-MFA token abuse, not a fresh password login**, which is why traditional MFA-centric thinking alone is insufficient.
