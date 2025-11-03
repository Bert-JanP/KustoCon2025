# Stage 2

## Scenario

In Stage 1 you established that a privileged administrator (`Target Account A`) received a high-pressure message and followed a link to an external sign-in–like page.

Shortly after that click, activity begins to appear in cloud identity and control-plane telemetry:

- Sign-in events for Target Account A from network locations that do not look like their normal workstation or corporate ranges.
- Non-interactive use of that identity to access cloud management functionality.
- A short burst of scripted discovery that maps identities, roles, and resources in the tenant.

In this stage, you will connect the endpoint-level phishing event to this new cloud-level activity.

---

## Investigation Goal

Prove, using telemetry, that:

1. Target Account A’s cloud identity was accessed from an unusual location after the phishing click in Stage 1.
2. Existing session material (token/refresh token) for Target Account A was reused to access cloud management APIs without further user interaction.
3. An automated discovery phase ran under that access, focused on enumerating identities, permissions, and cloud resources.

You should be able to build a short timeline that links:

**click → unusual cloud sign-in → non-interactive access to management plane → automated discovery.**

---

## MITRE ATT&CK

- **T1528 – Steal Application Access Token**  
  Capturing usable tokens or session material via the phishing flow.

- **T1550 – Use Alternate Authentication Material**  
  Reusing that token/session from a different location instead of prompting the real user again.

- **T1069.003 – Permission Group Discovery (Cloud)**  
  Enumerating roles, groups, and assignments in the tenant.

- **T1526 – Cloud Service Discovery**  
  Mapping subscriptions, services, and management endpoints.

---

## Deliverable for this stage

By the end of Stage 2 you should be able to answer:

- When did Target Account A first authenticate to cloud services after clicking the phishing link, and from what kind of location?
- What evidence shows that existing session material for Target Account A was reused non-interactively to reach the cloud management plane?
- What discovery pattern did the actor run (what was being enumerated, and how)?
- Why does this sequence differ from normal behavior for a legitimate administrator?

---

Now continue with the investigation tasks:  
[Go to Stage 2 Tasks →](Tasks.md)

After that continue with [Stage 3](../Stage3/README.md).
