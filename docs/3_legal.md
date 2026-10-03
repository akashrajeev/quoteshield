# Legal and regulatory requirements

This is an engineering summary, not legal advice. No compliance certification is claimed.

## Data used by the prototype
Only invented documents, example.test email addresses and a fake confidential file. No real personal data. When a remote model provider is selected, the mock prompts leave the machine for that provider; that does not make the setup safe for real supplier or customer data.

## India
- Digital Personal Data Protection Act, 2023 (assented 11 August 2023) and the DPDP Rules, 2025, which the government notified in November 2025. Source: PIB release "DPDP Rules, 2025 Notified" https://www.pib.gov.in/PressReleasePage.aspx?PRID=2190655 and MeitY https://www.meity.gov.in/documents/act-and-policies/digital-personal-data-protection-rules-2025-gDOxUjMtQWa . The Rules have commencement phases; check the PIB note for which duties apply on which date before relying on any date.
  Relevance to a deployed QuoteShield: an organisation using it would be a Data Fiduciary for personal data in vendor and employee documents. Design points that support this: the guard stops confidential data leaving through a hijacked agent (security safeguards against unauthorised disclosure); the audit log shows what was accessed and sent (accountability); the scope check enforces purpose limitation (the agent only does what the user asked). A real deployment would still need consent or another lawful basis, retention rules, breach processes and a data-processing agreement with any model provider. Cross-border transfer to a model provider also needs review.
- Information Technology Act, 2000 and CERT-In Directions of 28 April 2022: cyber incidents must be reported to CERT-In within 6 hours of noticing (CERT-In FAQ https://www.cert-in.org.in/PDF/FAQs_on_CyberSecurityDirections_May2022.pdf , Directions https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf ). A blocked exfiltration attempt is evidence that may feed an incident process; the audit log is designed to support that. Whether a given event is a reportable incident is for the organisation's security team.

## Contract and confidentiality
Procurement documents often sit under NDAs and vendor terms. The guard's rule that confidential data cannot flow to an external recipient supports NDA duties. Sending vendor documents to a third-party model provider may itself breach those terms; check before use.

## Other jurisdictions
If used with EU personal data, GDPR would apply; not analysed here.

## Audit log limits
The log is a local SHA-256 hash chain. It detects edits to a log file but is not signed, not anchored externally and not immutable. Do not describe it as tamper-proof evidence for legal use.

## Responsible testing
All tools are mocks. No real email is sent, no real file read. The attack corpus is synthetic.

## Not established
Legal opinion, DPIA, vendor terms review, retention policy, certification.
