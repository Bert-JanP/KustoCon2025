# From User to Cloud Compromise

## Engagement Overview
You are acting as the internal threat hunting / detection engineering team for a high-impact cloud security incident.

Telemetry from multiple sources indicates a sequence of suspicious activities involving identity usage, access to sensitive resources, and changes to high-privilege roles in our environment.

Your objective is to:
- Reconstruct what happened, in which order, and under which identities.
- Prove each step with data.
- Translate those observations into hunt queries and potential detections.

You will do this primarily using KQL.

---

## What you deliver
By the end of this exercise, you must be able to:
1. Attribute key actions to specific identities.
2. Explain how access expanded over time (who gained what new capability).
3. Identify the exact points where detection content should exist but doesn’t yet.
4. Map each major action to relevant MITRE ATT&CK techniques.
5. Summarize the incident in language appropriate for leadership.

Your final output should contain both:
- **Detection engineering view** – "Here’s the query logic / signal we should operationalize."
- **Threat hunting view** – "Here’s how we found it and how we would find similar activity again."

---

## Identity model for this exercise
To avoid spoilers and to force evidence-based attribution, we will not give you real names up front.

Instead, the activity is described using neutral labels:

- **Target Account A**  
  The first human-facing account observed in the sequence.

- **Service Principal B**  
  A non-interactive application identity that appears later in the sequence.

- **Account C**  
  An additional account that did not exist at the start of the sequence.

As you progress, you will resolve these placeholders (UPN, AppId, role assignments, etc.) using telemetry.  
Do not assume intent or legitimacy until you can prove it.

A trainer-only glossary exists in `_Reference/Glossary.md`. You do not need it to complete the exercise.

---

## How the exercise is structured
The investigation is broken into six stages.

Each stage includes:
- **Scenario context**  
  What was observed during that phase of activity.
- **Investigation goal**  
  What you must prove with data.
- **MITRE ATT&CK techniques**  
  How to classify what the actor is doing.
- **Tasks**  
  Specific questions you must answer using KQL.
- **Hints (optional)**  
  Directional guidance, not full answers.
- **Findings.md**  
  An expected outcome for that stage. Treat this as a solution key, only open it if you are blocked.

For every stage, you are expected to think in terms of detections:
- "Would we alert on this today?"
- "If not, what would the analytic rule look like?"
- "Is this noisy or is this high signal?"

---

## Workflow expectation
For each stage:
1. Run targeted KQL to extract supporting evidence.
2. Capture the relevant identities, timestamps, resources, and role changes.
3. Write down:
   - How you found it (hunt query / pivot).
   - How you would detect it in production (detection logic / analytic rule idea).
   - Which MITRE ATT&CK technique applies.

Assume you will hand this to both IR leadership and the SOC content engineering team.

---

## Stages
1. [Stage 1](Stage1/README.md)  
2. [Stage 2](Stage2/README.md)  
3. [Stage 3](Stage3/README.md)  
4. [Stage 4](Stage4/README.md)  
5. [Stage 5](Stage5/README.md)  
6. [Stage 6](Stage6/README.md)  

Begin with [Stage 1 →](Stage1/README.md)
