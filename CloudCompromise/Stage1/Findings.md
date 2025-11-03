# Stage 1 – Findings (Trainer / Solution Reference)

## Target Account A
Target Account A is:
- Display Name: Charly Clicker
- UPN: charly@acompanylikeyours.com
- Role/Context: Privileged IT admin, considered trusted

Charly is attractive because they can be socially engineered with urgency + authority.

---

## Lure Content
The message sent to Charly said (excerpt):

"Dear Charly,

We at KustoWorks manage the Cyber Security for A Company Like Yours and due to a Security Incident Bert-Jan asked us to make sure all IT Administrators reset their password.

Because of the criticality of this situation it is of the utmost importance that we do not publicly or internally discuss this incident. … We know you are in Switzerland at KustoCon, but could you please reset your password before 12:00. Through your personalized link:

https://login.m365-authentication.net/tCMwXwBx"

Key characteristics:
- Invokes leadership (“Bert-Jan asked us…”).
- Creates urgency (“before 12:00”).
- Imposes secrecy (“do not … discuss internally”).
- Uses travel context (“we know you are in Switzerland”) to build credibility.
- Provides a custom link to an external “login” page.

This matches MITRE ATT&CK **T1566.002 – Spearphishing Link**.

---

## Attacker Infrastructure
From the phishing link we have:

- Hostname: `login.m365-authentication.net`

This is not a Microsoft-owned login domain and not an internal identity provider.  
It is attacker-controlled infrastructure that mimics Microsoft 365 authentication.

(You can choose to resolve this hostname to an IP and pivot further in **Stage 2**, rather than here.)

---

## Detection engineering commentary
This stage exposes a high-value pre-alert opportunity:
- **Inbound** messages to admins demanding urgent password reset.
- Instructions to not involve internal IT.
- Links to non-corporate cloud login domains.
- Target is a known privileged admin (Charly).

A practical analytic rule could look for combinations of:
- Recipient in a high-privileged group (IT admin group / break-glass group).
- Body/subject language markers (“do not discuss internally”, “immediate reset”).
- Presence of non-approved identity domains in URLs.

This would likely become a “high-severity phishing of privileged identity” analytic.
