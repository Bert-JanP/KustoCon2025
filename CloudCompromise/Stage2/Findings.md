# Stage 2 – Findings (Trainer / Solution Reference)

## Replay Details
Shortly after the phishing in Stage 1, the attacker:
- Used Charly Clicker’s (Target Account A’s) refresh token.
- Redeemed it from attacker infrastructure tied to `4.210.146.4` (the phishing landing IP).
- Used a public client ID commonly associated with automated tooling:
  - ClientId: `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI public client).
- Requested an access token for the `vault.azure.net` scope.

This is exactly what the `Invoke-Stage1` PowerShell function does: it takes the stolen refresh token, calls `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`, and asks for `https://vault.azure.net/.default`.

---

## Why MFA did not fire
The attacker did not "log in with username/password."  
They replayed an already-issued refresh token. That refresh token was obtained when Charly legitimately authenticated earlier. In Azure AD / Entra ID, refresh tokens are long-lived and can be exchanged for new access tokens without another MFA prompt.

This maps to:
- **T1528 – Steal Application Access Token** (token theft)
- **T1550 – Use Alternate Authentication Material** (reusing that token instead of authenticating interactively)

---

## Detection engineering commentary
This stage is where you want continuous conditional access / anomaly detection for high-value identities:
- Privileged identity
- Refresh token redemption from unfamiliar IP/ASN/geo
- Immediate scope request for sensitive resources (Key Vault)

A KQL-based analytic could look for:
- Principal in a high-privileged group or role
- `grant_type=refresh_token`
- `Resource == vault.azure.net` (or other high-value management plane)
- IP not previously associated with that principal in the last N days

This is a very high-signal alert.
