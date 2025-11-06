# Stage 6

## Scenario
After establishing Account C and assigning tenant-wide admin rights, the actor extended that control into the cloud control plane.

Observed behavior:
1. Account C was granted a high-impact role scoped at the subscription level that allows modification of access.
2. Account C was then granted full ownership rights on that subscription.
3. The initial "stepping stone" role assignment was removed, reducing obvious evidence of escalation.

End state:
- Account C is both tenant-level admin and subscription-level owner.
- The visible audit trail has been partially cleaned.

This is the point of full cloud compromise.

---

## Investigation Goal
Prove that:
1. Account C received an access-management role on a subscription.
2. Account C then received full ownership rights on that subscription.
3. The temporary assignment was removed shortly after.
4. This sequence represents deliberate privilege escalation and cleanup.

You are documenting final takeover and anti-forensics.

---

## MITRE ATT&CK
- **T1098 – Account Manipulation**  
  Assigning high-impact RBAC roles (e.g. Owner) to attacker-controlled identities.
- **T1562 / T1070 – Defense Evasion / Indicator Removal**  
  Removing temporary assignments / noisy roles to hide the escalation path.

---

## Deliverable for this stage
By the end of Stage 6 you should be able to answer:
- Which subscription or scope was affected?
- Which roles were granted to Account C, in what order, and at what times?
- Which assignments were later removed?

---

Now continue with the investigation tasks:  
[Go to Stage 6 Tasks →](Tasks.md)

At this point you should be able to produce a complete timeline for leadership.

When you’ve completed these tasks, return to the main overview and build your final incident timeline and detection recommendations:  
[Back to index](../CloudCompromise.md)
