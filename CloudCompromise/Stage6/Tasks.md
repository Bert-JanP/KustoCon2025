# Stage 6 Tasks

In previous stages you established that:

- Account C is a newly created cloud user with **Global Administrator** (tenant-wide) privileges.
- The attacker is operating via Service Principal B and from attacker IP space (e.g. `83.97.112.20`).

In this stage, you will show how that control is extended into the **Azure control plane** (subscription level) and partially cleaned up.

---

## Task 6.1 – Show that Account C elevated to User Access Administrator

Your goals in this task:

1. Prove that Account C elevated to **User Access Administrator** over Azure resources.
2. Confirm that this elevation happened during the incident window.
3. Link the elevation to attacker infrastructure (IP, identity context).

<details>
<summary>Tip 6.1.1 – Find the elevation event</summary>

Use Entra ID / Azure RBAC audit logs, for example:

- `AuditLogs`
- or a view where `Category == "AzureRBACRoleManagementElevateAccess"`

Filter on:

- `ActivityDisplayName` containing `"User has elevated their access to User Access Administrator for their Azure Resources"`.
- The Stage 6 incident window.

Example pattern (adjust table to your environment):

```kql
AuditLogs
| where TimeGenerated between(datetime(2025-11-05 09:50:00) .. datetime(2025-11-05 09:55:00))
| where ActivityDisplayName == "User has elevated their access to User Access Administrator for their Azure Resources"
```
</details>

<details>
<summary>Tip 6.1.2 – Extract who and from where</summary>

From the matching event, extract:

- `TimeGenerated`
- `InitiatedBy.user.userPrincipalName`  → this should be **Account C**
- `InitiatedBy.user.id`                 → Account C objectId
- `InitiatedBy.user.ipAddress`         → attacker IP
- Any scope / subscription context available in `TargetResources` or `AdditionalDetails`

You should observe that:

- The elevation is performed by Account C.
- The IP address matches attacker infrastructure (e.g. `83.97.112.20`), not a normal admin workstation.
</details>

<details>
<summary>Result 6.1.1 – What you should observe</summary>

From the lab data, you should see an event around:

- `TimeGenerated ≈ 2025-11-05 09:53:11 (UTC)`
- `ActivityDisplayName = "User has elevated their access to User Access Administrator for their Azure Resources"`
- `InitiatedBy.user.userPrincipalName` = Account C (the same user you identified in Stage 5)
- `InitiatedBy.user.ipAddress` = `83.97.112.20`

This proves that **Account C** has temporarily elevated to **User Access Administrator** over Azure resources from attacker-controlled infrastructure.
</details>

---

## Task 6.2 – Prove Account C became subscription Owner

Your goals in this task:

1. Show that Account C received a **subscription-level RBAC role** with full control (Owner).
2. Tie that assignment to a specific subscription / scope.
3. Place it in time relative to the User Access Administrator elevation.

> Note: this evidence typically resides in Azure control-plane logs (e.g. `AzureActivity`, `AzureDiagnostics`, or a dedicated RBAC log). The queries below are **patterns / placeholders**; adjust to your actual logging table.

<details>
<summary>Tip 6.2.1 – Look for roleAssignments/write</summary>

Use your Azure control-plane telemetry, for example:

- `AzureActivity`
- or an RBAC-specific log

Filter on:

- `OperationNameValue` / `OperationName`:
  - `"Microsoft.Authorization/roleAssignments/write"`
- A time window shortly after the UAA elevation event from Task 6.1.
- Target or principal matching **Account C** (objectId or UPN).

Example pattern (placeholder):

```kql
AzureActivity
| where TimeGenerated between(datetime(2025-11-05 09:53:00) .. datetime(2025-11-05 10:05:00))
| where OperationNameValue == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where Properties has "<AccountC ObjectId or UPN>"
```
</details>

<details>
<summary>Tip 6.2.2 – Identify the Owner role and scope</summary>

From the role assignment event(s), extract:

- `properties.roleDefinitionName`  (should be `"Owner"`)
- `properties.scope`               (subscription or resource group, e.g. `/subscriptions/<subId>`)
- `properties.principalId`         (should match Account C’s objectId)
- `SubscriptionId` / `ResourceId` if available

Your objective:

- Prove that Account C was assigned the **Owner** role at **subscription scope**, not just a low-impact role.
</details>

<details>
<summary>Tip 6.2.3 – Place it in the timeline</summary>

Place the Owner assignment relative to:

- The UAA elevation event (Task 6.1).
- The later removal of UAA (Task 6.3).

Typical pattern you should see:

```text
09:53  – Account C elevates to User Access Administrator
09:5x  – Account C (or same context) writes an Owner role assignment for Account C on the subscription
10:01  – User Access Administrator role assignment is removed from Account C
```

This sequence is deliberate: use UAA to grant **Owner**, then clean up UAA.
</details>

---

## Task 6.3 – Show the cleanup (removal of User Access Administrator)

Your goals in this task:

1. Prove that the **User Access Administrator** assignment was removed.
2. Show that this removal happens **after** Owner has been granted.
3. Confirm it is performed from the same attacker context.

<details>
<summary>Tip 6.3.1 – Find the removal event</summary>

Again use `AuditLogs` / `EntraIdAuditLogs` (or `AzureRBACRoleManagementElevateAccess`) and look for:

- `ActivityDisplayName = "The role assignment of User Access Administrator has been removed from the user"`

Example pattern:

```kql
AuditLogs
| where TimeGenerated between(datetime(2025-11-05 09:59:00) .. datetime(2025-11-05 10:05:00))
| where ActivityDisplayName == "The role assignment of User Access Administrator has been removed from the user"
```
</details>

<details>
<summary>Tip 6.3.2 – Correlate identity, IP, and timing</summary>

From the event, extract:

- `TimeGenerated`
- `InitiatedBy.user.userPrincipalName`  → Account C
- `InitiatedBy.user.ipAddress`         → attacker IP (e.g. `83.97.112.20`)

Confirm:

- This removal occurs **after** the UAA elevation, and
- After the subscription Owner assignment identified in Task 6.2.
</details>

<details>
<summary>Result 6.3.1 – What you should observe</summary>

From the lab data, you should see a removal event around:

- `TimeGenerated ≈ 2025-11-05 10:01:02 (UTC)`
- `ActivityDisplayName = "The role assignment of User Access Administrator has been removed from the user"`
- `InitiatedBy.user.userPrincipalName` = Account C
- `InitiatedBy.user.ipAddress` = `83.97.112.20`

At this point:

- Account C still holds **Owner** on the subscription.
- The temporary UAA path used to get Owner has been removed, reducing obvious indicators of escalation.

This is a classic **“use-and-remove”** pattern for privilege escalation and cleanup.
</details>

---

## Task 6.4 – Detection engineering note

Your goals in this task:

- Describe how you would detect **subscription-level takeover** by an attacker-controlled identity.
- Include both **elevation** and **cleanup** in your logic.

<details>
<summary>Notes</summary>

Think about the full pattern:

1. **Event A – Temporary elevation**

   - Category: `AzureRBACRoleManagementElevateAccess`
   - `ActivityDisplayName = "User has elevated their access to User Access Administrator for their Azure Resources"`
   - Principal is a **user account** (Account C) already suspected/known to be attacker-controlled.
   - Source IP is **new/suspicious** for that user (e.g. `83.97.112.20`).

2. **Event B – Subscription Owner assignment**

   - In Azure control-plane logs (e.g. `AzureActivity`):
     - `OperationNameValue = "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"`
     - `roleDefinitionName = "Owner"`
     - `principalId` = Account C
     - `scope` = subscription-level.
   - Time window: within a few minutes of Event A.

3. **Event C – Cleanup**

   - Category: `AzureRBACRoleManagementElevateAccess`
   - `ActivityDisplayName = "The role assignment of User Access Administrator has been removed from the user"`
   - Same principal, same IP, after Event B.

A high-signal analytic could:

- Trigger when:

  ```text
  For a given user:

  A: UAA elevation (AzureRBACRoleManagementElevateAccess)
  B: Owner role assignment on a subscription
  C: UAA removal

  all occur within a short window (e.g. <= 1 hour),
  from unusual IPs for that user.
  ```

- Scope this to:

  - Identities already tagged as **privileged** or **sensitive** (e.g. Global Admins),
  - Or identities recently created / promoted (like Account C in Stage 5).

Treat this as **auto-severity-high**:

```text
High-confidence: attacker-controlled cloud identity has taken subscription-level ownership
and cleaned up the obvious stepping-stone role (UAA).
```

</details>

---

When you have:

- Shown UAA elevation for Account C,
- Proven a subscription-level Owner assignment for Account C,
- Demonstrated removal of UAA as cleanup,
- And thought through how to detect this pattern,

you have finished the **cloud compromise chain** and are ready to build your final incident timeline and recommendations.
