# Legal and regulatory requirements

This is an engineering summary, not legal advice. No compliance certification is claimed.

## Data used by the prototype
Only invented documents, example.test email addresses and a fake confidential file. No real personal data. When a remote model provider is selected, the mock prompts leave the machine for that provider; that does not make the setup safe for real supplier or customer data.

## India
- Digital Personal Data Protection Act, 2023 (enacted 11 August 2023) and the DPDP Rules, 2025, notified on 14 November 2025. Sources: PIB press release "A Citizen-Centric Framework for Privacy Protection and Responsible Data Use", posted 17 November 2025 (https://www.pib.gov.in/PressReleasePage.aspx?PRID=2190655), and MeitY (https://www.meity.gov.in/documents/act-and-policies/digital-personal-data-protection-rules-2025-gDOxUjMtQWa). This document does not state commencement dates; check the Rules and the PIB note for which duties apply from which date.
  Relevance to a deployed QuoteShield: if an organisation uses it on documents that contain personal data (for example names or contact details in vendor or employee documents), it may be acting as a Data Fiduciary, or as a Data Processor for another organisation. That depends on the deployment and needs legal review. Design points that relate to the Act's principles: the guard stops confidential data leaving through a hijacked agent (security safeguards against unauthorised disclosure); the audit log shows what was accessed and sent (accountability); the scope check enforces purpose limitation (the agent only does what the user asked). A real deployment would still need a lawful basis for processing, retention rules, a breach process and a data-processing agreement with any model provider. Sending data to a model provider outside India also needs review.
- Information Technology Act, 2000 and CERT-In Directions of 28 April 2022 (Directions: https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf ; FAQ: https://www.cert-in.org.in/PDF/FAQs_on_CyberSecurityDirections_May2022.pdf ). The Directions require a service provider, intermediary, data centre, body corporate or Government organisation to report the cyber incident types listed in Annexure I of the Directions to CERT-In within 6 hours of noticing them. They do not make every cyber incident reportable. A blocked exfiltration attempt may be evidence for an incident process; the audit log is designed to support that. Whether an organisation is covered, and whether a given event is a listed incident, is for its security and legal team to decide.

## Contract and confidentiality
Procurement documents often sit under NDAs and vendor terms. The guard's rule that confidential data cannot flow to an external recipient supports NDA duties. Sending vendor documents to a third-party model provider may itself breach those terms; check before use.

## Other jurisdictions
GDPR may apply depending on whose personal data is processed and where; not analysed here.

## Audit log limits
The log is a local SHA-256 hash chain. It detects edits to a log file but is not signed, not anchored externally and not immutable. Do not describe it as tamper-proof evidence for legal use.

## Responsible testing
All tools are mocks. No real email is sent, no real file read. The attack corpus is synthetic.

## Not established
Legal opinion, DPIA, vendor terms review, retention policy, certification.
