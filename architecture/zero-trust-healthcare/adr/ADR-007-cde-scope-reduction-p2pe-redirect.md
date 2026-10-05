# ADR-007: CDE scope reduction through P2PE terminals and a payment service provider redirect

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

| Field | Value |
|---|---|
| Status | Accepted (reference design) |
| Date | 2026-10-03 |
| Decision owners (fictional roles) | CFO, VP Revenue Cycle, CISO, Compliance Officer |
| Scope | Card-present payments at registration desks and online payments through the patient portal |
| Related | `04-segmentation.md` section 7, assumptions A-15 and A-16 |

## Context

Contoso Regional Health (fictional) takes card payments at registration desks across 3 hospitals and 22 clinics, and online through the patient portal. Without design work, card data would touch registration workstations, the clinical and corporate network, and shared services such as Active Directory. That would pull much of the enterprise into PCI DSS v4.0.1 scope.

Verified facts (checked 2026-10-03):

- **P2PE reduces scope.** PCI SSC states that merchants using PCI-listed P2PE solutions have fewer applicable PCI DSS requirements. Each listed solution comes with a P2PE Instruction Manual that the merchant must follow. The current P2PE standard is v3.2, published 2025-06-30.
- **SAQ P2PE has narrow eligibility.** The merchant must use only terminals from a validated, PCI-listed P2PE solution, with no other electronic account data handling, and must implement every control in the Instruction Manual. SAQ P2PE does not cover e-commerce.
- **SAQ A changed in January 2025.** The revision removed Requirements 6.4.3 and 11.6.1 from SAQ A and added an eligibility criterion: the merchant confirms its site is not susceptible to attacks from scripts that could affect its e-commerce systems. PCI SSC FAQ 1588 says that criterion targets merchants that embed a provider's payment form in an iframe, and does not apply to merchants that redirect to the payment service provider.
- **Billing data is PHI regardless of PCI scope.** Payment records tied to a patient remain protected health information under HIPAA, because the definition of health information in 45 CFR 160.103 includes payment for the provision of health care.

## Decision

1. **Card-present payments use standalone terminals from a PCI-listed P2PE solution,** implemented per its Instruction Manual. The terminals are not integrated with registration workstations, and clerks key the amount on the terminal.
2. **The terminals sit in `Z-CDE`.** `PEP-CDE-BOUNDARY` allows only outbound traffic to the P2PE provider, with no inbound traffic and no path from any other zone. No Contoso account has access to the terminals; the P2PE provider manages them.
3. **Online payments use a full URL redirect** from `RES-PORTAL` to the payment service provider's hosted page (`EXT-PSP`). Contoso receives only a transaction reference.
4. **There are no phone or mail payments** (A-15).
5. **Validation path (A-16):** SAQ P2PE for registration desks and SAQ A for the redirect, as the acquirer decides. The `Z-CDE` network controls stay in place as defense in depth even where SAQ P2PE does not require them. They cost little, and they keep the design valid if the acquirer requires a full assessment.
6. **The portal page that starts the redirect** sits behind `PEP-WAF` and is change-monitored, because tampering with it could send patients to a counterfeit payment page.

## Alternatives considered

### A. Integrated terminals that pass card data through registration workstations (rejected)

Workstations, the network they sit on, and the services they depend on would enter scope. In a hospital that is most of the enterprise.

### B. Encrypting terminals that are not part of a PCI-listed P2PE solution (rejected)

Without listing, there is no P2PE scope reduction and no SAQ P2PE eligibility. The encryption still helps, but the assessment burden does not shrink.

### C. Provider payment fields embedded in the portal through an iframe (rejected)

An embedded iframe keeps patients on the portal, which is a better experience. However, it brings the SAQ A script-attack eligibility criterion into play. Contoso would have to keep showing that its portal is not susceptible to script attacks, which is ongoing work that a redirect avoids. The redirect is simpler to keep out of scope, and the experience cost is accepted.

### D. Tokenization with a Contoso-hosted payment page (rejected)

The portal would become an in-scope e-commerce system handling card entry.

### E. Segmentation alone without P2PE (rejected)

Workstations that touch card data would still be in scope. The segmentation itself would need penetration testing at least every 12 months (Requirement 11.4.5) to support any scope claim. Shrinking the data path is cheaper than defending a large one.

## Consequences

Positive:

- The CDE shrinks to payment terminals.
- No Contoso user or system administers anything inside it.
- Most PCI DSS requirements fall away under the assumed validation path.

Negative and residual:

- **Dependence on the P2PE provider and the payment service provider,** managed through Requirements 12.8.1 to 12.8.5 (upstream compromise is RR-12).
- **Patients leave the portal to pay.**
- **Terminal inspection and staff training** remain (Requirements 9.5.1 to 9.5.1.3).
- **The acquirer decides the validation path.** If it requires a full assessment, the defense-in-depth controls become requirements, and segmentation testing (11.4.5) and scope confirmation (12.5.2) apply.

## Compliance drivers

| Framework | Identifier | Why it matters here |
|---|---|---|
| PCI DSS v4.0.1 | Requirements 9.5.1, 9.5.1.1, 9.5.1.2, 9.5.1.3 | Terminal list, inspection, and training under every path |
| PCI DSS v4.0.1 | Requirements 12.8.1 to 12.8.5, 12.10.1 | Third-party service provider management and incident response under every path |
| PCI DSS v4.0.1 | Requirements 1.3.1, 1.3.2, 11.4.5, 12.5.2 | Required under a full assessment; kept or performed anyway under the SAQ path |
| HIPAA | 45 CFR 160.103 (definition of health information) | Billing records stay ePHI even when card data leaves PCI scope |
| NIST CSF 2.0 | ID.AM-03, PR.IR-01, GV.SC-05, GV.SC-07, DE.CM-02 | Data flows, network protection, supplier requirements and monitoring, terminal inspection |

## ZTMM mapping

Networks: Network Segmentation. Data: Data Inventory Management, Data Access.

## Revisit when

- The acquirer requires a different validation path.
- PCI SSC publishes P2PE v4.0, which it states is in development.
- A successor to PCI DSS v4.0.1 is published.
- The patient experience requires embedded payment fields.

## Sources

| Title | Publisher | URL | Date checked | Quality |
|---|---|---|---|---|
| Point-to-Point Encryption standards page | PCI SSC | https://www.pcisecuritystandards.org/standards/point-to-point-encryption-p2pe/ | 2026-10-03 | Primary |
| PCI SSC Releases Version 3.2 of the PCI P2PE Standard | PCI SSC | https://blog.pcisecuritystandards.org/pci-ssc-releases-version-3-2-of-the-pci-point-to-point-encryption-p2pe-standard | 2026-10-03 | Primary |
| Self-Assessment Questionnaire P2PE for PCI DSS v4.0, superseded by the v4.0.1 SAQs and used here for eligibility wording | PCI SSC | https://listings.pcisecuritystandards.org/documents/PCI-DSS-v4-0-SAQ-P2PE.pdf | 2026-10-03 | Primary |
| Important Updates Announced for Merchants Validating to Self-Assessment Questionnaire A | PCI SSC | https://blog.pcisecuritystandards.org/important-updates-announced-for-merchants-validating-to-self-assessment-questionnaire-a | 2026-10-03 | Primary |
| PCI SSC FAQ 1588 (SAQ A eligibility) | PCI SSC | https://www.pcisecuritystandards.org/faqs/1588/ | 2026-10-03 | Primary |
| FAQ Clarifies New SAQ A Eligibility Criteria for E-Commerce Merchants | PCI SSC | https://blog.pcisecuritystandards.org/faq-clarifies-new-saq-a-eligibility-criteria-for-e-commerce-merchants | 2026-10-03 | Primary |
| Guidance for PCI DSS Scoping and Network Segmentation, v1.1 (May 2017) | PCI SSC | https://listings.pcisecuritystandards.org/documents/Guidance-PCI-DSS-Scoping-and-Segmentation_v1_1.pdf | 2026-10-03 | Primary |
| PCI DSS v4.0.1 (document library) | PCI SSC | https://www.pcisecuritystandards.org/document_library/ | 2026-10-03 | Primary |
| 45 CFR 160.103 (definitions) | eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-160/subpart-A/section-160.103 | 2026-10-03 | Primary |
