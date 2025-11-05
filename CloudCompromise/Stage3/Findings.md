# Stage 3 – Findings (Trainer / Solution Reference)

## Narrative

In this stage you prove that the attacker used the **compromised session from Stage 2** to access a Key Vault and retrieve secrets that can later be used to pivot into an app identity.

### 1. Key Vault access tied to the same compromised session

From **AzureDiagnostics** (Key Vault data-plane / audit logs):

Filter on:

- `ResourceProvider = "MICROSOFT.KEYVAULT"`.
- `ResourceType = "VAULTS"`.
- `Category = "AuditEvent"`.
- `OperationName in ("SecretList", "SecretGet")`.

You will find two key events around:

- `TimeGenerated ≈ 2025-11-05 08:40:00` and `08:40:02`.

With the following fields:

- `_ResourceId` ending in:  
  `/providers/Microsoft.KeyVault/vaults/kv-kustocon2025`  
  → **Key Vault:** `kv-kustocon2025`.
- `OperationName`:
  - `SecretList`
  - `SecretGet`
- `identity_claim_upn_s = "charly@acompanylikeyours.com"`.
- `identity_claim_appid_g = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"` (Azure CLI public client).
- `identity_claim_sid_g = "00a8a3f9-feac-368d-3a84-178530ea5b8a"`.

This makes it explicit that:

- The **same compromised session** from Stage 2 (`SessionId 00a8a3f9-feac-...`) is being used,
- Through the **Azure CLI public client**,
- To list and read secrets in `kv-kustocon2025` under Charly’s identity.

### 2. What was likely retrieved from the vault

The dataset does not expose secret *values* (by design), but the lab story and later stages reveal:

- One of the secrets in `kv-kustocon2025` contains:
  - `AppId = "88ebe2cb-e139-4323-91b7-1b013b664432"`  
  - `TenantId = "a4be6261-d211-4df1-852e-c597a96ad887"`  
  - `ClientSecret = "<SP secret value>"`  
    for service principal **KustoCon2025-Automation**.

So, by the time Stage 3 completes, the attacker has:

- Valid **client credentials** for an internal app identity,
- Collected using Charly’s compromised session and the Azure CLI.

### 3. How this matches the PowerShell tooling

The workshop’s offensive code (`Invoke-Stage1`) is effectively doing:

1. Take a stolen refresh token for Charly.
2. Call `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token` with:
   - `grant_type = "refresh_token"`.
   - `client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"` (Azure CLI).
   - `scope = "https://vault.azure.net/.default offline_access openid profile"`.
3. Use the resulting access token against `https://kv-kustocon2025.vault.azure.net/` to:
   - List secrets (`SecretList`).
   - Retrieve secret values (`SecretGet`).

The AzureDiagnostics evidence you see is exactly the on-the-wire footprint of that flow.

---

## MITRE ATT&CK mapping

- **T1528 – Steal Application Access Token**  
  Continued use of the stolen refresh token/session to obtain tokens for Key Vault.

- **T1550 – Use Alternate Authentication Material**  
  Instead of logging in as Charly again, the attacker reuses the existing session (post-MFA).

- **T1552.007 – Credentials in Configuration Stores (Cloud Secrets)**  
  Key Vault secrets are used as a high-value source of application credentials.

---

## Key takeaways for students

By the end of Stage 3 they should be able to state:

1. **The same compromised session id** (`00a8a3f9-feac-368d-3a84-178530ea5b8a`) is used to talk to:
   - OfficeHome,
   - Azure Resource Manager,
   - and now **Key Vault** (`kv-kustocon2025`) via Azure CLI.

2. **Charly is still the “identity of record”**, but the activity clearly originates from the attacker’s context:
   - IP and tooling (`azurehound` in Stage 2, Azure CLI client ID here).
   - Timing directly after the recon burst.

3. **Secrets retrieved from Key Vault give the attacker a new path**:
   - They can now impersonate an internal app (service principal),
   - Without needing to continue operating directly as Charly.

This sets up Stage 4, where those stolen app credentials are actually used.
