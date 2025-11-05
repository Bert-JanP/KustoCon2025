# Stage 2 Tasks

This window covers:
- The phishing click from Stage 1 (around `2025-11-05 08:33:06` UTC).
- The first unusual cloud sign-in.
- Token reuse to a different cloud resource.
- The short, intense discovery burst.

---

## Task 2.1 – Link the phishing click to an unusual cloud sign-in

Your goals in this task:
- Show that **Target Account A** authenticated to cloud services shortly after the phishing click.
- Demonstrate that the sign-in came from **unusual infrastructure** (not their normal endpoint `104.46.63.96` / network `8075`).
- Capture the **SessionId** that you will reuse in later tasks.

<details>
<summary>Tip 2.1.1</summary>

Use your cloud sign-in telemetry:

- `SigninLogs`
- and/or `AADSignInEventsBeta`

Filter on:

- The time window from `20251105083306` onward.
- The user you identified in Stage 1 (Target Account A).

</details>

<details>
<summary>Tip 2.1.2</summary>

From the sign-in logs, extract:

- `TimeGenerated`
- `UserPrincipalName` (should match Target Account A)
- `IPAddress`
- `ResourceDisplayName` (for example: `OfficeHome`)
- `SessionId`
- Any status / result fields indicating successful sign-in

You want the **first successful sign-in** that occurs shortly after the phishing click at `2025-11-05 08:38:06`.

Make sure you write down the `SessionId` for that sign-in, you will need it in Task 2.2.

</details>

<details>
<summary>Tip 2.1.3</summary>

One way to start is with `SigninLogs` and filter out the normal endpoint IP:

```kql
let Click = datetime(20251105083806);
SigninLogs
| where TimeGenerated between(Click .. (Click + 10m))
| where UserPrincipalName == "charly@acompanylikeyours.com"
| where IPAddress != "104.46.63.96"
| project TimeGenerated, UserPrincipalName, IPAddress, ResourceDisplayName, SessionId, Status
| order by TimeGenerated asc
```

Then pivot to `AADSignInEventsBeta` for more detail on that same sign-in.

</details>

<details>
<summary>Result 2.1.1</summary>

What you should be able to observe from the dataset:

- `UserPrincipalName = "charly@acompanylikeyours.com"` (Target Account A)  
- A successful sign-in shortly after the click, at `2025-11-05 08:34:12 (UTC)`  
- `IPAddress = "4.210.146.4"`  
- `ResourceDisplayName = "OfficeHome"`  
- `SessionId = "afb760df-808f-4ded-eb50-08de1c45ae82"`  

Interpretation:

- Within a few minutes of the phishing click at `08:38:06`, Target Account A’s identity is used to sign in from **4.210.146.4** at `08:34:12`.  
- `4.210.146.4` is associated with the phishing infrastructure (the host behind `login.m365-authentication.net`), not with the user’s workstation.  
- The `SessionId` `afb760df-808f-4ded-eb50-08de1c45ae82` represents this cloud session; you will use it to trace additional activity.

This is your first cloud-side proof that the phishing flow is being used to drive real sign-ins for this account.

</details>

---

## Task 2.2 – Prove token reuse to a different cloud resource

Your goals in this task:
- Using the **same SessionId** from Task 2.1, show that the session is reused for additional activity.
- Prove that this activity:
  - Comes from a **different IP address**, and
  - Targets a **different cloud resource** than `OfficeHome`.

You don’t need to know upfront what that resource is, let the data tell you.

<details>
<summary>Tip 2.2.1</summary>

Look at non-interactive sign-in / token usage logs, for example:

- `AADNonInteractiveUserSignInLogs`
- and/or additional entries in `AADSignInEventsBeta`

Filter on:

- The same `SessionId` you captured in Task 2.1.
- The time window immediately after the OfficeHome sign-in.

</details>

<details>
<summary>Tip 2.2.2</summary>

From these logs, extract:

- `TimeGenerated`
- `UserPrincipalName`
- `SessionId`
- `IPAddress`
- `ResourceDisplayName`
- `ClientAppUsed` / `AppDisplayName` if present

You are looking for an event where:

- `SessionId` matches the one from Task 2.1.
- `IPAddress` is different from `4.210.146.4`.
- `ResourceDisplayName` is **not** `OfficeHome`.

</details>

<details>
<summary>Tip 2.2.3</summary>

Example pattern using the known session id (strong hint):

```kql
let Click = datetime(20251105083806);
AADNonInteractiveUserSignInLogs
| where TimeGenerated between(Click .. (Click + 10m))
| where SessionId == "afb760df-808f-4ded-eb50-08de1c45ae82"
| project TimeGenerated, UserPrincipalName, IPAddress, ResourceDisplayName, ClientAppUsed, SessionId
| order by TimeGenerated asc
```

Check which IPs and resources appear for that `SessionId`.
</details>

<details>
<summary>Result 2.2.1</summary>

What you should be able to observe from the dataset:

- A non-interactive sign-in / token use event around `2025-11-05 08:36:31 (UTC)`  
- `UserPrincipalName` still tied to Target Account A’s context  
- `SessionId = "afb760df-808f-4ded-eb50-08de1c45ae82"` (same as Task 2.1)  
- `IPAddress = "83.97.112.20"` (a **different** IP than `4.210.146.4`)  
- `ResourceDisplayName = "Azure Resource Manager"`  

Interpretation:

- The initial interactive sign-in to `OfficeHome` from `4.210.146.4` established a session (`SessionId`) and refresh token.  
- Using that **same session**, from a **different IP** (`83.97.112.20`), the attacker exchanges the token for access to a **different resource**: Azure Resource Manager.  
- The real user is not involved here; this is the attacker replaying alternate authentication material from their own host.

You have now:

- Proved token/session reuse via `SessionId`.  
- Shown the pivot from a user-facing app (`OfficeHome`) to the cloud management plane (Azure Resource Manager).

</details>

---

## Task 2.3 – Explain the IP switch and why MFA didn’t save you

Your goals in this task:
- Explain why seeing `4.210.146.4` → `83.97.112.20` for the same `SessionId` is a strong indicator of token replay.
- Articulate why MFA did not block this activity.

No new KQL needed; this is a reasoning / narrative task.

<details>
<summary>Tip 2.3.1</summary>

Think about:

- Where the victim *clicked* and typed credentials (their endpoint → phishing site).  
- Where the **first** sign-in appears from (phishing infrastructure IP).  
- Where the **management-plane token** is minted from (another IP again).  
- What part of the flow MFA actually protects (initial sign-in versus token reuse).

</details>

<details>
<summary>Result 2.3.1</summary>

Expected explanation:

- The victim enters credentials (and possibly MFA) into the phishing page.  
- The phishing infrastructure at `4.210.146.4` uses those credentials/session to perform an interactive sign-in to `OfficeHome` as the victim.  
- The resulting refresh token / session (`SessionId = afb760df-808f-4ded-eb50-08de1c45ae82`) is then used from the attacker’s own system at `83.97.112.20` to mint an Azure Resource Manager token at `08:36:57`.

MFA doesn’t fire again because:

- The attacker is not logging in **from scratch**.  
- They are exchanging an already-issued **refresh token** for new access tokens.  
- Refresh tokens are "post-MFA" artifacts; reusing them typically bypasses MFA challenges.

So the sequence:

```text
Click (victim) → OfficeHome sign-in (4.210.146.4, SessionId X)
→ ARM token (83.97.112.20, same SessionId X)
```

is a classic example of stolen token / session reuse.

</details>

---

## Task 2.4 – Identify the cloud discovery burst

Your goals in this task:
- Show that from `83.97.112.20` there was a short, intense burst of discovery operations.
- Prove that those operations focus on **identities, roles, and resources**, not normal user activity.

<details>
<summary>Tip 2.4.1</summary>

Use Microosft Graph API logs such as:

- `MicrosoftGraphActivityLogs`

Filter on:
 
- `IPAddress == "83.97.112.20"`
- `SessionId == "afb760df-808f-4ded-eb50-08de1c45ae82"`

</details>

<details>
<summary>Tip 2.4.2</summary>

Example query:

```kql
let Click = datetime(20251105083806);
MicrosoftGraphActivityLogs
| where TimeGenerated between(Click .. (Click + 30m))
| where IPAddress == "83.97.112.20"
| where SessionId == "afb760df-808f-4ded-eb50-08de1c45ae82"

</details>

<details>
<summary>Tip 2.4.3</summary>

Example approach:

```kql
MicrosoftGraphActivityLogs
| where TimeGenerated between(datetime(20251105083809) .. datetime(20251105083813))
| where IPAddress == "83.97.112.20"
| where SessionId == "afb760df-808f-4ded-eb50-08de1c45ae82"
| summarize Count = count() by OperationName
| order by Count desc
```

Also look at:

- What identities / roles are being listed.  
- Whether multiple directories / subscriptions / assignments are being queried.

</details>

<details>
<summary>Result 2.4.1</summary>

What you should be able to observe from the dataset:

- All activity is from `IPAddress = "83.97.112.20"` in roughly a **2-second** window (`08:38:09`–`08:38:13`).  
- A high number of API calls, including operations such as:
  - Listing directory roles and role templates.  
  - Listing directory role members.  
  - Enumerating service principals / applications.  
  - Enumerating subscriptions / resource groups / assignments.  

Characteristics:

- Very short time window.  
- Many list/read operations, almost no writes.  
- Strong focus on **"who has which permissions where?"**.

This is consistent with automated tools like reconaisanse performing:

- **T1069.003 – Permission Group Discovery (Cloud)**  
- **T1526 – Cloud Service Discovery**  

This recon output forms the bridge into Stage 3, where the attacker will pick high-value targets (for example, a Key Vault with useful secrets).

</details>

---

## Task 2.5 – Detection engineering note

Your goals in this task:
- Sketch a high-signal analytic that would catch this pattern early for privileged identities.
- Explain what you would alert on.

<details>
<summary>Notes</summary>

Look at the whole sequence:

1. A privileged identity signs in from an unusual / new IP associated with suspicious infrastructure.  
2. Shortly after, the **same SessionId** appears in a non-interactive sign-in for a different cloud resource from a **different**, also unusual IP (management plane).  
3. Within minutes, from that second IP, a burst of Graph / management-plane discovery operations is executed.

Ask yourself: how often does that combination happen for a normal admin performing routine work?

An analytic concept:

- **Scope**: focus on high-value identities  
  - Administrative accounts  
  - Break-glass / emergency access accounts  
  - Identities holding highly privileged roles (Global Admin, Owner, User Access Admin, etc.)

- **Trigger pattern**:

  1. **Event A – unusual interactive sign-in**  
     - Source: `SigninLogs` / `AADSignInEventsBeta`.  
     - Conditions:
       - Privileged user.  
       - Sign-in from an IP not seen for that user in the last *N* days (user/IP baseline).  
       - Resource: user-facing, such as `OfficeHome` / M365.  
       - Capture `SessionId`.

  2. **Event B – token reuse to management plane**  
     - Source: `AADNonInteractiveUserSignInLogs` (or equivalent non-interactive logs).  
     - Within a short time window of Event A (for example 5–10 minutes).  
     - Same `SessionId` (and/or same user) as Event A.  
     - Different IP from Event A.  
     - `ResourceDisplayName` in the cloud management plane (for example **Azure Resource Manager**).

  3. **Event C – recon burst**  
     - Source: `MicrosoftGraphActivityLogs` (or similar Graph / management-plane audit stream).  
     - Within a further short window after Event B.  
     - Same IP as Event B.  
     - Multiple list/read operations in a few seconds, targeting:
       - Directory roles / role templates  
       - Role members  
       - Service principals / applications  
       - Subscriptions / resource groups / assignments

- **Alerting logic (conceptual)**:

  - Correlate Event A, B, and C by:
    - `UserPrincipalName` and/or `SessionId`  
    - Time proximity (A → B → C within a small total window)  
    - New / unusual IPs for that identity  
  - Exclude:
    - Known-secure automation accounts  
    - Known management hosts or IP ranges (admin jump hosts, dedicated automation runners)

A good starting point for the MicrosoftGraphAuditing can be:

```kql
let WhitelistedObjects = dynamic(["obj1", "obj2"]);
let UniqueRequestThreshold = 500; // Depends on Entra ID tentant size. You can use the function 0.5 * TotalAzure Resources to get this number. KQL: arg("").Resources | count
let ResourceThreshold = 4;
let ReconResources = dynamic(["organization","groups","devices","applications","users","rolemanagement","serviceprincipals"]);
MicrosoftGraphActivityLogs
| where RequestMethod == "GET"
| where ResponseStatusCode == 200
| extend ParsedUri = tostring(parse_url(RequestUri).Path)
| extend GraphAPIPath = tolower(replace_string(ParsedUri, "//", "/"))
| extend GraphAPIResource = tostring(split(GraphAPIPath, "/")[2])
| where GraphAPIResource in (ReconResources)
| extend AccountObjectId = coalesce(UserId ,ServicePrincipalId)
// Filter whitelist
| where not(AccountObjectId in (WhitelistedObjects))
| summarize UniqueRequests = dcount(ClientRequestId), Requests = make_set(RequestUri, 1000), Paths = make_set(GraphAPIPath), Resources = make_set(GraphAPIResource), UniqueResourceCount = dcount(GraphAPIResource) by AccountObjectId, bin(TimeGenerated, 1h)
| where UniqueRequests >= UniqueRequestThreshold and UniqueResourceCount >= ResourceThreshold
```

</details>

---

When you have:

- Linked the phishing click to an unusual cloud sign-in,
- Shown session/token reuse from a different IP against a different cloud resource,
- Identified the short discovery burst and its purpose,

proceed to [Stage 3](../Stage3/README.md).