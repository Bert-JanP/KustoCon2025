# Stage 3 Tasks

## Task 3.1 – Show secret store access (and tie it to the same session)

Your goals in this task:

- Prove that a cloud key vault was accessed.
- Identify which vault it was.
- Show that the same compromised session from Stage 2 was used for that access.

<details>
<summary>Tip 3.1.1</summary>

Use cloud resource / diagnostic logs such as:

- `AzureDiagnostics` (Key Vault data plane / audit logs)

</details>

<details>
<summary>Tip 3.1.2</summary>

Filter on:

- `ResourceProvider == "MICROSOFT.KEYVAULT"`
- `ResourceType == "VAULTS"`
- `Category == "AuditEvent"`

Focus on operations that indicate secret interaction:

- `OperationName` in:
  - `"SecretList"`
  - `"SecretGet"`

Project at least:

- `TimeGenerated`
- `_ResourceId`
- `OperationName`
- `identity_claim_upn_s`
- `identity_claim_appid_g`
- `identity_claim_sid_g`

This will show *which* vault, *who* (UPN) and *what client* was used.

</details>

<details>
<summary>Tip 3.1.3</summary>

From Stage 2 you have a cloud session ID / token context.

In this dataset, that value appears as:

- `identity_claim_sid_g`

Look for Key Vault events where:

```kql
identity_claim_sid_g == "afb760df-808f-4ded-eb50-08de1c45ae82"
```

This lets you prove that the **same compromised session** used to access the management plane is now being used to talk to the vault.

</details>

<details>
<summary>Result 3.1.1</summary>

What you should be able to observe from the dataset:

- `ResourceProvider = "MICROSOFT.KEYVAULT"`
- `ResourceType = "VAULTS"`
- `_ResourceId` ends with:

  ```text
  /providers/Microsoft.KeyVault/vaults/kv-kustocon2025
  ```

- Operations:

  - `OperationName = "SecretList"`
  - `OperationName = "SecretGet"`

- Identity context:

  - `identity_claim_upn_s = "charly@acompanylikeyours.com"`
  - `identity_claim_appid_g = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"` (Azure CLI public client)
  - `identity_claim_sid_g = "afb760df-808f-4ded-eb50-08de1c45ae82"`

There are two tight bursts of activity, each combining:

- One `SecretList`
- Two `SecretGet` calls

This proves:

- The vault **`kv-kustocon2025`** is being accessed.
- The calls are made in Charly’s **user context** via the Azure CLI public client.
- The same compromised session (`identity_claim_sid_g`) continues to be leveraged against the vault.

</details>

---

## Task 3.2 – Identify high-value material in the secret access

Your goals in this task:

- Isolate the **secret read** operations.
- Reason about which of those could represent credentials for an internal application identity (to be re-used in Stage 4 as "Service Principal B").

<details>
<summary>Tip 3.2.1</summary>

From the same `AzureDiagnostics` dataset, filter to:

- `OperationName == "SecretGet"`

Project:

- `TimeGenerated`
- `_ResourceId`
- `OperationName`
- `identity_claim_upn_s`
- `identity_claim_sid_g`

Optionally, summarize:

```kql
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where ResourceType == "VAULTS"
| where Category == "AuditEvent"
| where OperationName == "SecretGet"
| summarize Count = count() by _ResourceId, identity_claim_upn_s, identity_claim_sid_g
```

This shows how many secret reads per vault, per identity, per session.

</details>

<details>
<summary>Tip 3.2.2</summary>

Key idea:

- Key Vault logs **do not** show you the secret value.
- They do tell you that a secret was retrieved, when, and under what identity/session.

In a real tenant, you would:

- Map the secret identifier (from the request path or properties) to:
  - An app registration / service principal,
  - A specific application configuration,
  - Or infrastructure credentials.

For this lab, you can assume that **at least one of the `SecretGet` calls retrieved an AppId + TenantId + ClientSecret bundle** that will be re-used in Stage 4.

</details>

<details>
<summary>Result 3.2.1</summary>

What you should be able to observe:

- Multiple `SecretGet` operations against `kv-kustocon2025`.
- All of them in Charly’s user context (`identity_claim_upn_s`).
- All of them using the Azure CLI public client (`identity_claim_appid_g`).
- All of them bound to the same compromised session (`identity_claim_sid_g`).

Interpretation:

- The attacker is not just listing secrets – they are **actively retrieving** secret values from the vault.
- At least one of these retrieved values is later used as credentials for an internal application identity (Service Principal B) in Stage 4.

You’ve now demonstrated **cloud credential theft from a centralized secret store**.

</details>

---

## Task 3.3 – Detection engineering note

Your goals in this task:

- Describe how you’d detect a **user-context session** suddenly reading secrets from a vault it normally doesn’t touch.
- Think in terms of **baselines** and **privilege**.

<details>
<summary>Notes</summary>

Consider the pattern:

1. Actor type:  
   - `identity_claim_idtyp_s` indicates a **user context** (not a pure app-only service principal).
   - `identity_claim_upn_s` maps to a known human (e.g. `charly@acompanylikeyours.com`).

2. Action:  
   - `OperationName` in (`"SecretList"`, `"SecretGet"`)  
   - `ResourceProvider == "MICROSOFT.KEYVAULT"`  
   - `ResourceType == "VAULTS"`

3. Novelty:  
   - For that same `identity_claim_upn_s`, there has been **no activity against that vault** (`_ResourceId`) in the last *N* days.

4. Session context:  
   - Optionally include `identity_claim_sid_g` to correlate:
     - Recent unusual sign-in / token pivot (from Stage 2).
     - Followed by secret reads from a new vault.

A KQL-style analytic concept:

- **Scope**:  
  - Human accounts (user context)  
  - Optionally restricted to:
    - Privileged users  
    - High-sensitivity vaults (containing app credentials / production secrets)

- **Logic (high-level)**:

  ```text
  If a human account, using a new or unusual session,
  accesses a Key Vault (SecretList/SecretGet)
  that this account has never touched before,
  especially shortly after an unusual cloud sign-in,
  then raise a high-severity alert.
  ```

Key signals to combine:

- Actor: `identity_claim_upn_s`, `identity_claim_idtyp_s`
- Resource: `_ResourceId` ending in `/vaults/<name>`
- Operation: `SecretList` / `SecretGet`
- Novelty:
  - No prior Key Vault access for this (user, vault) pair in a baseline window.
- Optional correlation:
  - `identity_claim_sid_g` links this activity to a suspicious session from Stage 2.

A good starting point for a detection could be:

```kql
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where ResourceType == "VAULTS"
| where Category == "AuditEvent"
| where OperationName == "SecretGet"
| summarize Count = count() by _ResourceId, identity_claim_upn_s, identity_claim_sid_g
```

</details>

---

When you have:

- Proved that a vault was accessed in the compromised session,
- Shown that secrets were actively retrieved,
- Reasoned that at least one secret is an app credential that can be reused,

proceed to [Stage 4](../Stage4/README.md).