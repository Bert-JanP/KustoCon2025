# Stage 6 – Findings (Trainer / Solution Reference)

## 1. Account C elevated to User Access Administrator

From the Stage 6 audit export (Entra ID / Azure RBAC elevate access logs), there is an event where Account C elevates to **User Access Administrator**:

- `Category = "AzureRBACRoleManagementElevateAccess"`
- `ActivityDisplayName = "User has elevated their access to User Access Administrator for their Azure Resources"`
- `TimeGenerated ≈ 2025-11-05 09:53:11 (UTC)`
- `InitiatedBy.user.userPrincipalName = "riley@acompanylikeyours.com"` (Account C)
- `InitiatedBy.user.ipAddress = "83.97.112.20"`

This shows that:

- Account C, already a **Global Administrator** from Stage 5, has now elevated to **User Access Administrator** over Azure resources.
- The action originates from the same attacker IP range used earlier in the incident, not from a trusted admin workstation.

This satisfies **Investigation Goal 1** (Account C received an access-management role over a subscription / Azure resources).

---

## 2. Account C became subscription Owner

The Owner assignment itself is typically captured in Azure control-plane logs (e.g. `AzureActivity` with `Microsoft.Authorization/roleAssignments/write`). In the full lab environment, the expected record for this step will show:

- `OperationNameValue = "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"`
- `properties.roleDefinitionName = "Owner"`
- `properties.principalId = <objectId of Account C>`
- `properties.scope = "/subscriptions/<subscriptionId>"` (subscription-level scope)
- `TimeGenerated` shortly after the UAA elevation event.

Students should:

- Use Account C’s objectId or UPN to find this Owner role assignment.
- Confirm that:
  - The roleDefinitionName is `"Owner"`.
  - The scope is the targeted subscription.
  - The principal is Account C.

This satisfies **Investigation Goal 2** (Account C received full ownership rights on a subscription).

---

## 3. UAA assignment removed (cleanup)

In the same `AzureRBACRoleManagementElevateAccess` category, there is a later event:

- `ActivityDisplayName = "The role assignment of User Access Administrator has been removed from the user"`
- `TimeGenerated ≈ 2025-11-05 10:01:02 (UTC)`
- `InitiatedBy.user.userPrincipalName = "riley@acompanylikeyours.com"` (Account C)
- `InitiatedBy.user.ipAddress = "83.97.112.20"`

Interpretation:

- After using **User Access Administrator** to make the Owner assignment, the attacker (operating as Account C) removes the temporary UAA elevation.
- This leaves Account C as **subscription Owner** and tenant-level admin, but with one obvious stepping-stone role removed from view.

This satisfies **Investigation Goal 3** (the temporary assignment was removed shortly after).

---

## 4. This is deliberate privilege escalation and cleanup

Looking across stages:

1. **Stage 5**  
   - Account C is created and immediately added to **Global Administrator** by Service Principal B.

2. **Stage 6 – Event A**  
   - Account C elevates to **User Access Administrator** from attacker IP `83.97.112.20`.

3. **Stage 6 – Event B**  
   - Account C (or the same attacker context) writes a subscription-level **Owner** assignment for Account C.

4. **Stage 6 – Event C**  
   - Account C removes the **User Access Administrator** assignment from themselves at `10:01:02`.

This chain shows:

- **Deliberate escalation**:
  - Use UAA to grant Owner on the subscription to an attacker-controlled identity.
- **Anti-forensics / defense evasion**:
  - Remove the temporary UAA assignment, leaving a less obvious path in the audit trail.

This satisfies **Investigation Goal 4**: the sequence is clearly not normal admin provisioning but targeted **privilege escalation and cleanup** to reach full cloud compromise.

---

## Detection / discussion notes

For your own teaching / commentary:

- Emphasize the **three-step pattern**:

  ```text
  1. Temporary elevation to User Access Administrator (AzureRBACRoleManagementElevateAccess)
  2. Owner role assignment on a subscription (roleAssignments/write)
  3. Removal of the temporary UAA elevation (AzureRBACRoleManagementElevateAccess)
  ```

- Highlight why this is high-signal:

  - The principal (Account C) is already suspicious: newly created, made Global Admin (Stage 5).
  - Source IP is a known attacker IP (`83.97.112.20`).
  - The combination of elevation → Owner → cleanup within a tight time window is extremely unlikely to be normal operations.

- A strong SOC use-case:

  - Correlate these three events (A/B/C) for any user.
  - Limit to:
    - Identities with recent high-privilege changes, or
    - Identities coming from unusual IPs / sign-in patterns.
  - Treat any match as **auto-severity-high** and trigger full incident response.

At this point, students should be able to articulate a complete **cloud compromise path**:

```text
User phished → token replay → Key Vault access → Service Principal abuse →
Account C created as Global Admin → UAA elevation → subscription Owner →
cleanup of UAA.
```

That is the story leadership and IR leadership need from this exercise.
