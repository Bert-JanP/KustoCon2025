# Stage 5 Tasks

In previous stages you showed that:

- A user session was compromised and reused from attacker infrastructure.
- Key Vault secrets were accessed and used to operate a **service principal** (Service Principal B).
- That service principal is now a fully attacker-controlled app identity.

In this stage, you will show how that control is used to **plant a new tenant-level admin account** (Account C).

---

## Task 5.1 – Identify Account C (newly created cloud user)

Your goals in this task:

1. Find the audit event where a **new user** is created during the incident window.
2. Capture its **display name** and **UPN**.
3. Confirm that this identity **did not exist before** the incident.
4. Mark it as **Account C** for the rest of the lab.

<details>
<summary>Tip 5.1.1 – Find the user creation event</summary>

Use Entra ID audit / directory audit logs, for example:

- `AuditLogs`
- `EntraIdAuditLogs`

Filter on:

- `ActivityDisplayName` / `OperationName` containing `"Add user"` or `"Create user"`.
- The incident time window for Stage 5.

Example pattern:

```kql
AuditLogs
| where TimeGenerated between(datetime(2025-11-05 08:45:00) .. datetime(2025-11-05 08:55:00))
| where ActivityDisplayName == "Add user"
```

You should end up with **exactly one** user that is created in this window – that is Account C.
</details>

<details>
<summary>Tip 5.1.2 – Extract Account C identity</summary>

For the matching event, extract from the `TargetResources` field (or equivalent expansion):

- New user **displayName**
- New user **userPrincipalName** (UPN)
- The new user’s **object ID**
- `InitiatedBy` (who created it – user, app, or service principal)

Do **not** over-focus on whether the name “looks fake”. In many real incidents, backdoor accounts are given **plausible admin-sounding names**. What matters is:

- The account appears **during the incident**, and
- It is very quickly granted high privilege (you will confirm that in Task 5.2).

Mark this new identity as **Account C**.
</details>

<details>
<summary>Tip 5.1.3 – Show that Account C did not exist before</summary>

Once you know Account C’s UPN or object ID, run a **backward search** to prove there is no earlier activity for this user.

For example:

```kql
let AccountC = "<UPN or ObjectId for Account C>";
AuditLogs
| where TimeGenerated < datetime(2025-11-05 08:45:00)  // adjust as needed
| where TargetResources has AccountC
```

You can also check sign-in logs to ensure there were **no sign-ins** for Account C prior to creation:

```kql
let AccountC = "<UPN for Account C>";
SigninLogs
| where TimeGenerated < datetime(2025-11-05 08:45:00)
| where UserPrincipalName == AccountC
```

In this lab dataset, you should see **no earlier events** for Account C, supporting the conclusion that it was created **during** the incident and did not exist before.
</details>

<details>
<summary>Result 5.1.1 – What you should observe</summary>

From the lab data, you should be able to observe that:

- There is a single `"Add user"` event in the incident window.
- `TargetResources[0].type == "User"` and contains:
  - A new user object ID.
  - A UPN in the `@acompanylikeyours.com` domain.
  - A display name you will record as Account C.
- `InitiatedBy` shows that the creator is **an application / service principal**, not an interactive human user.

This is **Account C** – a new cloud user created as part of the incident flow.
</details>

---

## Task 5.2 – Prove high-privilege assignment to Account C

Your goals in this task:

- Show that Account C was **added to a tenant-wide administrator role** shortly after creation.
- Correlate the **actor** (who granted the role) back to Service Principal B or attacker-controlled context.

<details>
<summary>Tip 5.2.1 – Find the role assignment event</summary>

Stay in the Entra ID audit logs (`AuditLogs` / `EntraIdAuditLogs`) and look for **directory role membership changes**.

Filter on:

- `ActivityDisplayName` / `OperationName` such as:
  - `"Add member to role"`
  - `"Add directory role member"`
  - `"Add member to directory role"`
- A time window **shortly after** the user creation event from Task 5.1.

Example pattern:

```kql
AuditLogs
| where TimeGenerated between(datetime(2025-11-05 08:49:00) .. datetime(2025-11-05 08:51:00))
| where ActivityDisplayName == "Add member to role"
```

Then narrow down to entries where the **target user** is Account C.
</details>

<details>
<summary>Tip 5.2.2 – Inspect the target role</summary>

For the matching role assignment event, inspect `TargetResources` and the `modifiedProperties` inside it. You are looking for properties such as:

- `Role.DisplayName`
- `Role.TemplateId`
- `Role.WellKnownObjectName`

You should be able to identify that the role is a **tenant-wide admin role**, for example:

- `"Global Administrator"`
- `"Company Administrator"`
- Well-known object name `"TenantAdmins"`

Also extract:

- `TimeGenerated` / `ActivityDateTime`
- Account C’s user ID / UPN from the same event
- `InitiatedBy` (who performed the assignment)
</details>

<details>
<summary>Tip 5.2.3 – Link the actor back to Service Principal B</summary>

Compare the `InitiatedBy` block from:

- The `"Add user"` event (Task 5.1), and
- The `"Add member to role"` event (this task).

You should see that:

- Both actions are initiated by the **same application / service principal**.
- That principal’s identity (AppId / servicePrincipalId / displayName) matches **Service Principal B** from Stage 4.

This proves that:

- The same app identity you saw performing cloud reconnaissance and other actions in previous stages
- Is now being used to **create Account C** and **grant it tenant-level admin rights**.
</details>

<details>
<summary>Result 5.2.1 – What you should observe</summary>

From the lab data, you should observe that:

- Within a few seconds of the `"Add user"` event for Account C, there is an `"Add member to role"` audit event.
- The target role’s properties include:
  - `Role.DisplayName = "Global Administrator"`
  - and a well-known template associated with tenant admins.
- Account C is the **member** being added to that role.
- `InitiatedBy.app.displayName` (and the associated `servicePrincipalId`) are the same as for the user-creation event (Service Principal B).

This satisfies:

1. Account C was granted a powerful tenant-level role.  
2. The actor performing these actions is directly linked to the service principal from Stage 4, not a normal HR/helpdesk workflow.
</details>

---

## Task 5.3 – Detection engineering note

Your goals in this task:

- Describe how you would detect **suspicious new cloud admins**.
- Focus on the pattern: *“new user → high-privileged role within minutes”*.

No new KQL is strictly required, but you should think in terms of queries and correlations.

<details>
<summary>Notes</summary>

A robust analytic could:

1. **Detect new cloud users**

   - From `AuditLogs` / `EntraIdAuditLogs`:
     - `ActivityDisplayName` in (`"Add user"`, `"Create user"`).
   - Capture:
     - New user object ID / UPN.
     - Creation time.

2. **Look for rapid high-privilege role assignment**

   - Within a short window (for example, 10–15 minutes) after creation:
     - `ActivityDisplayName` in (`"Add member to role"`, `"Add directory role member"`).
     - Target user is the same new user.
     - Role is in a **high-privileged set**, e.g.:
       - Global Administrator / Company Administrator
       - Privileged Role Administrator
       - User Access Administrator
       - or your own list of tier-0 roles.

3. **Add context from earlier stages**

   - `InitiatedBy` is:
     - A service principal that recently started signing in from a new / risky IP, or
     - A user account you have already identified as compromised.

4. **Alerting outcome**

   Treat as **high-severity** when:

   ```text
   New cloud user
   → added to high-privileged role within minutes
   → action initiated by a suspicious principal (compromised user or SP).
   ```

This is almost never normal onboarding and should drive an immediate incident response playbook.
</details>

---

When you have:

- Identified Account C as a newly created user,
- Proven that Account C was quickly given tenant-wide admin privileges by the same malicious context as Stage 4,
- And thought through how to detect this pattern generically,

continue to [Stage 6](../Stage6/README.md).
