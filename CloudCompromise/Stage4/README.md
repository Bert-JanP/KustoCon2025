# Stage 4

## Scenario
At this point the attacker stops impersonating Target Account A and begins operating as a non-interactive application identity. We refer to this application identity as **Service Principal B**.

Observed behavior:
- Service Principal B authenticates using the credentials taken in Stage 3.
- It connects to the cloud control plane and to directory/Graph APIs.
- It enumerates roles, directory objects, assignments, subscriptions, and other high-value configuration data.

This is lateral movement into machine identity plus broad reconnaissance of privileges.

---

## Investigation Goal
Prove that:
1. Service Principal B authenticated after the secret theft in Stage 3.
2. Service Principal B performed wide discovery of roles, assignments, subscriptions, etc.
3. This activity is unusual for that service principal (i.e. it was not just "business as usual automation").

You are documenting cloud recon and privilege mapping.

---

## MITRE ATT&CK
- **T1550 – Use Alternate Authentication Material**  
  Logging in as Service Principal B with stolen credentials.
- **T1069.003 – Permission Group Discovery (Cloud)**  
  Enumerating who has which roles and where.
- **T1526 – Cloud Service Discovery**  
  Mapping subscriptions, resources, and control surfaces.

---

## Deliverable for this stage
By the end of Stage 4 you should be able to answer:
- What is Service Principal B (AppId / object)?
- When did it first authenticate in this incident?
- What discovery actions did it run?

---

Now continue with the investigation tasks:  
[Go to Stage 4 Tasks →](Tasks.md)

After that continue with [Stage 5](../Stage5/README.md).