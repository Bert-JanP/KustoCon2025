# Stage 5 – Findings (Trainer / Solution Reference)

## 1. Account C was created during the incident timeline

From `AuditLogs` / `EntraIdAuditLogs` (reflected in the Stage 5 CSV), there is a single user-creation event in the incident window:

- `ActivityDisplayName = "Add user"`
- `TimeGenerated ≈ 2025-11-05 08:49:37 (UTC)`
- `TargetResources[0].type = "User"`
- `TargetResources[0].userPrincipalName = "riley@acompanylikeyours.com"`
- `TargetResources[0].modifiedProperties` includes:
  - `DisplayName = "Riley the Raider"`
  - `AccountEnabled = true`, plus other initial attributes

This user is **Account C**.

There are no earlier audit records or sign-in records for this user in the supplied data, so students can reasonably conclude:

- Account C **did not exist** before this incident window.
- It was **introduced as part of the attacker’s activity**.

---

## 2. Account C did not exist before the incident

Students should confirm this by:

- Searching `AuditLogs` / `EntraIdAuditLogs` for that UPN / objectId **before** `2025-11-05 08:45:00`.
- Optionally checking `SigninLogs` for any sign-in activity for `riley@acompanylikeyours.com` prior to the creation time.

In the lab dataset, those searches return **no results** prior to the `"Add user"` event, supporting:

- **Goal 2** of the investigation: Account C was created **during**, not before, the incident.

---

## 3. Account C was granted a powerful tenant-level role

Immediately after the `"Add user"` event, another audit entry appears:

- `ActivityDisplayName = "Add member to role"`
- `TimeGenerated ≈ 2025-11-05 08:49:40 (UTC)` (about three seconds later)
- `TargetResources` includes:
  - The same user object as in the `"Add user"` event (Account C).
  - Role properties where:
    - `Role.DisplayName = "Global Administrator"`
    - `Role.TemplateId = "62e90394-69f5-4237-9190-012177145e10"`
    - `Role.WellKnownObjectName = "TenantAdmins"`

This shows:

- Account C is added as a **member** of the **Global Administrator / TenantAdmins** role immediately after creation.
- This satisfies **Goal 3**: Account C was granted a powerful, tenant-wide role.

Key teaching points:

- The time gap between creation and role assignment is **seconds**, not days.
- This is not typical for normal HR / helpdesk provisioning of a new user.

---

## 4. The actor is linked to Service Principal B (Stage 4)

In both the `"Add user"` and `"Add member to role"` events, the `InitiatedBy` block shows:

- `app.displayName = "KustoCon2025-Automation"`
- `app.servicePrincipalId = "bad25341-0561-4d85-82b5-f14c0dc5d688"`

From Stage 4, this is the same **Service Principal B** that:

- Signed in from attacker infrastructure (e.g. `83.97.112.20`)
- Talked to Microsoft Graph and Azure Resource Manager using credentials recovered from Key Vault.

So students should conclude:

- The **same app identity** used in Stage 4 for post-exploitation is now:
  - Creating Account C.
  - Immediately assigning Account C to the **Global Administrator** role.

This directly satisfies **Goal 4**:

> The actor performing these actions is linked to the activity you saw in Stage 4 (Service Principal B), not a normal HR/helpdesk workflow.

---

## Detection / discussion points (for Task 5.3)

A strong trainer summary for Task 5.3 can include:

- **Pattern**:

  ```text
  New user (Add user)
  → within seconds/minutes, Add member to role (Global/Company Administrator)
  → both operations initiated by the same service principal that was already tied to suspicious activity
  ```

- **Why this matters**:

  - Normal onboarding should not:
    - Create a random new user mid-incident.
    - Immediately grant Global Administrator.
  - When admins are created legitimately, it should:
    - Follow change management / approval.
    - Be performed by well-known automation or admin identities.

- **Detection idea**:

  - Analytic that:
    - Finds `"Add user"` events,
    - Joins to subsequent `"Add member to role"` events on the same user within 10–15 minutes,
    - Filters to tier-0 roles (Global/Company Admin, PRA, UAA, etc.),
    - Adds context if the same actor (user or SP) was previously flagged for suspicious behavior (as in Stages 2–4).



This is intended to be a “pager-worthy” signal in a mature SOC.
