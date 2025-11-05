# Stage 4 Tasks

In Stage 3 you proved that:

- Target Account A’s session was compromised (`identity_claim_sid_g`),
- That session was used from `83.97.112.20` to access `kv-kustocon2025`,
- Secrets were retrieved which can act as credentials for an internal application identity.

In this stage, you will:

- Pivot from the **same attacker IP**,
- Find a **non-interactive service principal login** (Service Principal B),
- Show it is used against Graph / ARM,
- And show that permissions around it were changed.

---

## Task 4.1 – Pivot from attacker IP to identify Service Principal B

Your goals in this task:

- Start from the known attacker infrastructure (`83.97.112.20`).
- Find sign-ins that are **not user-based** but **service principal / app-based**.
- Identify Service Principal B (name + AppId).

<details>
<summary>Tip 4.1.1</summary>

You already know from Stage 2/3 that `83.97.112.20` is attacker-controlled.

Now, instead of looking at user sign-ins, pivot to **service principal sign-in tables**, such as:

- `AADSpnSignInEventsBeta`
- `EntraIdSpnSignInEvents`
- `AADServicePrincipalSignInLogs`

Filter on:

- `IPAddress == "83.97.112.20"`

You’re looking for records where:

- The sign-in is by an app / service principal, not a user.
- A consistent `ServicePrincipalName` appears.

</details>

<details>
<summary>Tip 4.1.2</summary>

Example starting queries:

```kql
AADSpnSignInEventsBeta
| where IPAddress == "83.97.112.20"
| project TimeGenerated, IPAddress, ServicePrincipalName, ResourceDisplayName
| order by TimeGenerated asc
```

and:

```kql
AADServicePrincipalSignInLogs
| where IPAddress == "83.97.112.20"
| project TimeGenerated, IPAddress, ServicePrincipalName, AppId, ResourceDisplayName
| order by TimeGenerated asc
```

You should see **the same service principal** appear in both views.

</details>

<details>
<summary>Result 4.1.1</summary>

What you should be able to observe from the dataset:

- All relevant activity is from `IPAddress = "83.97.112.20"`.
- A single service principal identity is involved:

  - `ServicePrincipalName = "KustoCon2025-Automation"`
  - `ServicePrincipalId = "bad25341-0561-4d85-82b5-f14c0dc5d688"`
  - `AppId = "88ebe2cb-e139-4323-91b7-1b013b664432"`

- Resource targets in the sign-ins include:

  - `ResourceDisplayName = "Azure Resource Manager"`
  - `ResourceDisplayName = "Microsoft Graph"`

The key insight:

- The **same attacker IP** that reused Charly’s session for Key Vault access is now being used by a **non-interactive service principal** (`KustoCon2025-Automation`) with AppId `88ebe2cb-e139-4323-91b7-1b013b664432`.

This is **Service Principal B** in the lab narrative.

</details>

---

## Task 4.2 – Show what Service Principal B is doing

Your goals in this task:

- Show that Service Principal B is actively used to talk to **Graph** and **Azure Resource Manager**, not just existing passively.
- Tie its sign-ins and API activity back to the attacker IP.

<details>
<summary>Tip 4.2.1</summary>

Stick with:

- `AADServicePrincipalSignInLogs`
- `MicrosoftGraphActivityLogs`

Filter on:

- `AppId == "88ebe2cb-e139-4323-91b7-1b013b664432"`
- And focus on:
  - `IPAddress == "83.97.112.20"` for sign-ins.
  - `AppId == "88ebe2cb-e139-4323-91b7-1b013b664432"` in `MicrosoftGraphActivityLogs` for Graph usage.

</details>

<details>
<summary>Tip 4.2.2</summary>

Example query to show sign-ins by this SP:

```kql
AADServicePrincipalSignInLogs
| where AppId == "88ebe2cb-e139-4323-91b7-1b013b664432"
| project TimeGenerated, IPAddress, ServicePrincipalName, AppId, ResourceDisplayName
| order by TimeGenerated asc
```

And for Graph activity:

```kql
MicrosoftGraphActivityLogs
| where AppId == "88ebe2cb-e139-4323-91b7-1b013b664432"
| project TimeGenerated, IPAddress, AppId
| order by TimeGenerated asc
```

Even if `OperationName` is sparse in this dataset, you can still show **that the app is talking to Graph from this context**.

</details>

<details>
<summary>Result 4.2.1</summary>

What you should be able to observe:

From `AADServicePrincipalSignInLogs`:

- `ServicePrincipalName = "KustoCon2025-Automation"`
- `AppId = "88ebe2cb-e139-4323-91b7-1b013b664432"`
- `IPAddress = "83.97.112.20"`
- `ResourceDisplayName` includes:
  - `Microsoft Graph`
  - `Azure Resource Manager`

From `MicrosoftGraphActivityLogs`:

- Entries with:
  - `AppId = "88ebe2cb-e139-4323-91b7-1b013b664432"`
  - IPs including `83.97.112.20` (and some Microsoft-owned addresses).

Interpretation:

- Service Principal B is **actively calling Graph and ARM** from attacker infrastructure.
- This is a classic “machine identity takeover”: the attacker has stolen client credentials from Key Vault (Stage 3) and is now using them to operate as a non-interactive app identity.

</details>

---

## Task 4.3 – Show that permissions were changed for / around this app

Your goals in this task:

- Prove that, around the same time, **service principal / application permissions were modified**.
- Identify the key administrative operations.

<details>
<summary>Tip 4.3.1</summary>

Use:

- `AuditLogs`

and look for operations related to apps and service principals, for example:

- `"Update service principal"`
- `"Update application"`
- `"Add app role assignment to service principal"`
- `"Add app role assignment grant to user"`
- `"Consent to application"`

You don’t need to decode every field; the **operation names and timing** are the key.

</details>

<details>
<summary>Tip 4.3.2</summary>

Example:

```kql
AuditLogs
| where OperationName in (
    "Update service principal",
    "Update application",
    "Add app role assignment to service principal",
    "Add app role assignment grant to user",
    "Consent to application"
)
| project TimeGenerated, OperationName, Result
| order by TimeGenerated asc
```

Correlate this timeline with the Service Principal B sign-ins from Task 4.1 / 4.2.

</details>

<details>
<summary>Result 4.3.1</summary>

What you should be able to observe from `AuditLogs`:

Around the same time window as the Service Principal B activity, you see:

- `Update service principal`
- `Update application`
- Multiple `Add app role assignment to service principal`
- `Add app role assignment grant to user`
- `Consent to application`
- All with `Result = "success"`

Interpretation:

- The attacker is not only **using** Service Principal B, but also **modifying app/service principal configuration and role assignments**.
- This likely includes:
  - Granting the app additional Graph permissions or roles.
  - Assigning app roles or delegated permissions to users.
  - Strengthening persistence by giving the app broader reach.

Even though this lab dataset doesn’t show a huge recon burst at this point, the combination of:

- New SP sign-ins from attacker IP,
- Calls to Graph / ARM,
- And new app role assignments / consent

is already a strong indication of **cloud privilege manipulation and persistence via an app identity**.

</details>

---

## Task 4.4 – Detection engineering note

Your goals in this task:

- Describe how you would detect **service principal misuse** tied to known attacker infrastructure.
- Focus on IP pivot + new SP activity + permission changes.

<details>
<summary>Notes</summary>

Consider the pattern:

1. **Known-bad IP reuse**  
   - IP previously associated with:
     - Token replay,
     - Key Vault access (Stage 3).
   - Now appears in `AADSpnSignInEventsBeta` / `AADServicePrincipalSignInLogs`.

2. **New or unusual service principal sign-ins**  
   - Service principal logs in from that IP.
   - Targets `Microsoft Graph` and/or `Azure Resource Manager`.

3. **Near-simultaneous permission changes**  
   - `AuditLogs` shows:
     - `Update service principal` / `Update application`
     - `Add app role assignment to service principal`
     - `Consent to application`
   - All within a short window of the new SP sign-ins.

An analytic concept:

- **Scope**:
  - Service principals that:
    - Are used from IPs never seen before for that app.
    - Are used from IPs previously associated with suspicious user or token activity.

- **Trigger pattern**:

  1. SP sign-in (`AADServicePrincipalSignInLogs` or `AADSpnSignInEventsBeta`) from a **new / risky IP**.  
  2. Targets Graph / ARM (`ResourceDisplayName` contains `Microsoft Graph` or `Azure Resource Manager`).  
  3. Within a short window, `AuditLogs` shows **app role assignment / consent / update** operations involving that app.

- **Alert outcome**:

```text
High-confidence: service principal credentials likely stolen or abused,
used from attacker infrastructure, and granted/used for elevated access.
```

This should be treated similarly to a privileged user compromise: high severity, immediate investigation and credential rotation.

</details>

---

When you have:

- Pivoted from the attacker IP to identify Service Principal B,
- Shown that Service Principal B is being used from that IP to talk to Graph / ARM,
- Demonstrated that its permissions / assignments were modified in the same window,

you are ready to move to the next stage, where those privileges are used to modify roles and subscription ownership.

proceed to [Stage 5](../Stage5/README.md).
