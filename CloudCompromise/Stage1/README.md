# Stage 1

## Scenario
A privileged administrator (Target Account A) received an urgent message instructing them to take immediate action on their account.

The message:
- Referenced an ongoing "security incident"
- Claimed it was requested by leadership
- Instructed the recipient not to involve internal IT or discuss the request internally
- Contained a "personalized link" where the user was asked to sign in

That link pointed to external infrastructure controlled by the adversary and was designed to capture credentials and/or session material.

This is believed to be the starting point of the activity sequence you are investigating.

---

## Investigation Goal
Prove that Target Account A:
1. Received a credential-harvesting style message.
2. Was pressured to act outside normal process (urgency, secrecy, authority pressure).
3. Was directed to authenticate using a non-corporate sign-in link.
4. Actually engaged with the message from their endpoint and followed the link.

You are **not** given the identity of Target Account A in advance. You must discover it based on telemetry.

---

## MITRE ATT&CK
- **T1566.002 – Spearphishing Link**  
  Tailored message using a malicious link to capture credentials or session tokens.

---

## Deliverable for this stage
By the end of Stage 1 you should be able to answer:
- Who is Target Account A (UPN / display name)?
- What was the lure (subject / purpose of the message)?
- What external hostname the user was sent to?

---

Now continue with the investigation tasks:  
[Go to Stage 1 Tasks →](Tasks.md)

After that continue with [Stage 2](../Stage2/README.md).