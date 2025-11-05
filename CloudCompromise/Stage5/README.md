# Stage 5

## Scenario
Using control obtained in Stage 4, the actor moved from reconnaissance to persistence.

Observed behavior:
- A brand-new cloud user account (Account C) was created.
- Account C was immediately added to a high-impact directory role (tenant-wide admin).

This creates a durable backdoor. Even if Target Account A changes credentials or is offboarded, Account C remains.

---

## Investigation Goal
Prove that:
1. Account C was created during the incident timeline.
2. Account C did not exist before the incident.
3. Account C was granted a powerful tenant-level role (for example, Global Administrator / Company Administrator).
4. The actor performing these actions is linked to the activity you saw in Stage 4 (Service Principal B), not a normal HR/helpdesk workflow.

You are documenting long-term persistence.

---

## MITRE ATT&CK
- **T1136.003 – Create Cloud Account**  
  Creating a new tenant identity for persistence.
- **T1098.003 – Account Manipulation: Add Global Admin role**  
  Assigning that identity to a high-privilege directory role.

---

## Deliverable for this stage
By the end of Stage 5 you should be able to answer:
- What is Account C (UPN, displayName)?
- Who created Account C?
- Which role was Account C granted, and when?

---

Now continue with the investigation tasks:  
[Go to Stage 5 Tasks →](Tasks.md)

After that continue with [Stage 6](../Stage6/README.md).
