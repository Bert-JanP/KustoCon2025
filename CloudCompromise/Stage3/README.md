# Stage 3

## Scenario
After obtaining access tokens in Stage 2, the actor interacted with a secrets store in the cloud.

Observed behavior:
- Listing secrets within a vault used by the organization.
- Reading individual secret values.
- Extracting credentials for a non-human identity inside the tenant.

This is credential harvesting from cloud-managed secret storage.

---

## Investigation Goal
Prove that:
1. A vault (or equivalent secret store) was accessed using Target Account A’s compromised session.
2. Secrets were enumerated and retrieved.
3. At least one of the retrieved secrets can be used to authenticate as an internal application identity (what we will later call Service Principal B).

You are documenting cloud credential theft.

---

## MITRE ATT&CK
- **T1552 / T1555 – Credentials from Secret Stores**  
  Harvesting secrets (API keys, client secrets, etc.) from centralized vaults.

---

## Deliverable for this stage
By the end of Stage 3 you should be able to answer:
- Which secret store / vault was accessed?
- Which identity context made the calls?
- Did that access expose credentials for an application identity?

---

Now continue with the investigation tasks:  
[Go to Stage 3 Tasks →](Tasks.md)

After that continue with [Stage 4](../Stage4/README.md).
