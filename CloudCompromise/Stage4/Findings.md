# Stage 4 – Findings (Trainer / Solution Reference)

## Narrative

In this stage you demonstrate that the attacker:

1. Uses credentials stolen from `kv-kustocon2025` in Stage 3.
2. Authenticates as an **application / service principal** instead of as Charly.
3. Operates that service principal from the same attacker IP (`83.97.112.20`) against Graph and Azure Resource Manager.

The key identity here is **Service Principal B**.

---

## 1. Identifying Service Principal B from attacker IP

From **AADServicePrincipalSignInLogs**:

Filter on `IPAddress == "83.97.112.20"`.

You will find sign-ins for:

- `ServicePrincipalName = "KustoCon2025-Automation"`.
- `ServicePrincipalId = "bad25341-0561-4d85-82b5-f14c0dc5d688"`.
- `AppId = "88ebe2cb-e139-4323-91b7-1b013b664432"`.
- `ResourceDisplayName` values including:
  - `Microsoft Graph`.
  - `Azure Resource Manager`.
- `TimeGenerated` around:
  - `2025-11-05 08:45:47`–`08:50:11`.

This confirms:

- A **non-interactive application identity** (service principal) is logging in.
- It is doing so **from the same attacker IP** (`83.97.112.20`) used for token replay and AzureHound in Stage 2.

In the lab narrative, this is **Service Principal B**.

---

## 2. Showing how Service Principal B is used

From **AADServicePrincipalSignInLogs** (same records):

- For `AppId = "88ebe2cb-e139-4323-91b7-1b013b664432"`:
  - Some entries show `ResourceDisplayName = "Microsoft Graph"`.
  - Others show `ResourceDisplayName = "Azure Resource Manager"`.
  - All with `IPAddress = "83.97.112.20"`.

From **MicrosoftGraphActivityLogs**:

- Filter on `AppId = "88ebe2cb-e139-4323-91b7-1b013b664432"`.
- You will see multiple requests from:
  - `IPAddress = "83.97.112.20"`.
  - Around `2025-11-05 08:49:37`–`08:49:40`.

Even though the operation names are not central in this stage, the combination of:

- Service principal sign-ins to Graph and ARM, and
- Graph API calls originating from the same app and IP,

is enough to conclude:

> The attacker is now **operating as the KustoCon2025-Automation app**,  
> talking to both Graph and the Azure management plane from 83.97.112.20.

---

## 3. Connecting Stage 3 → Stage 4

From Stage 3 you already know that:

- `kv-kustocon2025` was accessed via Azure CLI using Charly’s session.
- The attacker retrieved secrets from this vault.
- One of those secrets corresponds to:
  - `AppId = "88ebe2cb-e139-4323-91b7-1b013b664432"`.
  - `ServicePrincipalName = "KustoCon2025-Automation"`.

Stage 4 now shows:

- Shorty after Key Vault `SecretGet`, sign-ins appear for **KustoCon2025-Automation** from `83.97.112.20`.
- These sign-ins are **service principal sign-ins** (app identity), not user logons.
- They are used against:
  - **Microsoft Graph** (directory / identity plane),
  - **Azure Resource Manager** (resource management plane).

The most reasonable causal chain is:

```text
Charly’s session reused from 83.97.112.20 →
Key Vault kv-kustocon2025 SecretGet →
retrieved AppId + TenantId + ClientSecret →
service principal KustoCon2025-Automation starts
logging in from 83.97.112.20 to Graph and ARM.
```

---

## MITRE ATT&CK mapping

- **T1552.007 – Credentials in Configuration Stores (Cloud Secrets)**  
  Use of Key Vault as a source of long-lived app credentials (Stage 3).

- **T1550 – Use Alternate Authentication Material**  
  Instead of using Charly’s user credentials, the attacker now uses **app credentials** (client ID + secret).

- **T1098 / T1098.004 – Account Manipulation / Cloud Accounts**  
  Abuse of a service principal account to operate in the tenant.

(Heavier role manipulation and subscription ownership changes are handled in later stages.)

---

## Key takeaways for students

By the end of Stage 4 they should be able to state:

1. **Which service principal was abused?**  
   - `ServicePrincipalName = "KustoCon2025-Automation"`,  
   - `AppId = "88ebe2cb-e139-4323-91b7-1b013b664432"`.

2. **Where was it operated from?**  
   - `IPAddress = "83.97.112.20"`, the same attacker IP seen in Stage 2 and Stage 3.

3. **What did it talk to?**  
   - Microsoft Graph and Azure Resource Manager (control plane access).

4. **How does it fit into the kill chain?**  
   - It’s the **pivot from user-context compromise (Charly) → app identity abuse**,  
   - Enabled by secrets stolen from `kv-kustocon2025`.

This sets the stage for the later levels where this app identity and other privileges are used to create new global admins and eventually take subscription ownership.
