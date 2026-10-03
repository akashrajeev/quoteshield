# Socio-cultural sensitivity

## Who is affected
Procurement, finance, HR and support staff who hand routine work to AI agents; the vendors whose documents the agent reads; and the people whose data may sit in those documents. In India this includes small and mid-size firms that work with vendors in several languages and formats.

## Benefits
- Staff keep the work moving while risky actions are stopped or sent to a person, instead of the agent being switched off.
- Each intervention shows a plain-language reason and the exact text that triggered it, so a reviewer can judge it without technical knowledge.
- Vendors are not blacklisted by the system: it reacts to instructions hidden in a document, not to who sent it.

## Risks and how the design handles them
- Over-blocking: legitimate documents that discuss security, or contain encoded data such as a base64 logo, could be flagged. Human review is the fallback and the false-positive rate is measured on benign tasks (target: no more than 10%).
- Review burden: asking a person too often causes approval fatigue. Ask Human is used only for ambiguous actions, and approvals are one-use and tied to the exact call (exact recipient and content).
- Language and script: the PS names base64, hex and zero-width characters. Attackers can also write instructions in Hindi, other Indian languages, or mixed-script text. The repo's decoder handles Unicode normalisation and common encodings, but the repo does not claim regional-language coverage. Multilingual attack and benign tests are a gap and should be listed as a limitation.
- Fairness: no claim is made about fairness across vendors or languages; no study has been done.
- Accessibility: the dashboard uses standard widgets and a dark theme. That is not an accessibility audit.
- Over-trust: a protection layer can make staff assume the agent is safe. The docs and UI state that this is layered risk reduction, not a guarantee, and that humans stay in the loop for consequential actions.

## What we do not claim
No stakeholder interviews, user studies, accessibility audit, regional-language validation or adoption evidence exist yet.

## Suggested next steps (not done)
Add Hindi and mixed-script attack and benign cases to the development set; test with two or three real procurement users for the clarity of block messages.
