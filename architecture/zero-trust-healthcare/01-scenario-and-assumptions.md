# Contoso Regional Health (fictional): scenario and assumptions

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

This design set is a reference Zero Trust architecture for a fictional regional health system. It is written for an architecture review rather than a sales deck: the scenario and assumptions come first, every non-obvious decision has an architecture decision record (ADR) that names the alternatives that lost, and residual risk is stated rather than implied away.

## Document map

| File | What it covers |
|---|---|
| `01-scenario-and-assumptions.md` | This file: the fixed scenario, the assumptions the design depends on, design principles, framework baseline, and what is out of scope |
| `02-reference-architecture.md` | Logical architecture per NIST SP 800-207, the component glossary that every companion artifact reuses, trust zones, key data flows, failure modes, and residual risk |
| `03-identity-and-access.md` | Identity populations, phishing-resistant MFA strategy, the reference Conditional Access policy set, privileged and emergency access, workload identities, and vendor and B2B access |
| `04-segmentation.md` | Zone catalog, IoMT segmentation, the legacy clinical enclave, ZTNA versus VPN, east-west controls, and CDE scope reduction |
| `05-ztmm-maturity-roadmap.md` | CISA ZTMM v2.0 current and target stages per pillar, function, and cross-cutting capability, with a phased roadmap and dependencies |
| `adr/ADR-001` to `adr/ADR-009` | One record per non-obvious decision, each with at least one rejected alternative |

The companion threat model, detection pack, and compliance crosswalk reuse the component IDs defined in section 11 of `02-reference-architecture.md`.

## Scenario (fixed)

These facts are given and do not change anywhere in the design set.

| Attribute | Scenario fact |
|---|---|
| Organization | Contoso Regional Health (fictional), a not-for-profit regional health system and HIPAA covered entity |
| Footprint | 3 hospitals and 22 outpatient clinics |
| Workforce | About 9,500 workforce members, including affiliated physicians and contractors |
| Clinical systems | A vendor-neutral EHR platform, PACS imaging, laboratory and pharmacy systems, and some legacy clinical applications that need Kerberos or NTLM |
| Medical devices | About 6,000 connected medical and IoMT devices, most unable to run an endpoint agent |
| Identity | Microsoft Entra ID P2, hybrid with on-premises Active Directory; Microsoft 365 E5; Intune |
| Security stack | Microsoft Defender XDR, with Microsoft Sentinel as the SIEM |
| Hosting | Some workloads in Azure, the rest in an on-premises datacenter |
| Third-party access | EHR vendor support, biomedical device vendors, and a revenue-cycle outsourcer acting as a business associate |
| Patient services | Patient portal and telehealth |
| Payments | Patient payments at registration desks and online, which creates a PCI DSS cardholder data environment (CDE) |
| Governance | NIST CSF 2.0 as the hub framework; HIPAA Security, Privacy, and Breach Notification Rules; PCI DSS v4.0.1 for the CDE; leadership is considering HITRUST certification |

## Assumptions

The scenario leaves gaps that any real design would have to close. Each gap is closed below with a labeled assumption, so a reader can see exactly what the design depends on and challenge it.

| ID | Area | Assumption | Where it matters |
|---|---|---|---|
| A-01 | Identity | On-premises Active Directory Domain Services is the source of authority for workforce accounts and synchronizes to Microsoft Entra ID with password hash synchronization. Entra ID uses managed (cloud) authentication. No federation service such as AD FS is in use. | Entra certificate-based authentication requires managed authentication (ADR-003). No extra Tier 0 federation server (ADR-004). |
| A-02 | Identity | Each hospital hosts writable domain controllers for its own Active Directory site. Clinics authenticate over the WAN to hospital or datacenter domain controllers. | The local clinical decision plane (ADR-001, ADR-008) |
| A-03 | Identity | Two systems of record drive workforce lifecycle: an HR system for employees and contractors (contractors carry a Contoso sponsor and an end date), and a medical staff credentialing system for affiliated physicians. | Joiner, mover, and leaver handling (03) |
| A-04 | Licensing | Accounts that Conditional Access governs are licensed for it. Microsoft 365 E5 includes Microsoft Entra ID P2. Capabilities outside E5 are treated as incremental purchases and flagged wherever the design uses them, for example Microsoft Entra Private Access, Microsoft Entra Workload ID Premium, Microsoft Entra ID Governance, and Defender for IoT site licenses. | ADR-002, ADR-006, 03 |
| A-05 | Endpoints | Windows endpoints are Intune managed and Microsoft Entra hybrid joined or Entra joined, and run Microsoft Defender for Endpoint. Some corporate staff use macOS. Clinicians use iOS and Android devices, both personal phones and Contoso-owned shared unit devices. | 03, 04 |
| A-06 | Clinical workflow | Shared clinical workstations (nursing stations, workstations on wheels) serve many staff per shift. Fast user switching is a patient-care requirement, not a convenience. | ADR-003 |
| A-07 | EHR platform | The EHR platform offers a full client for managed devices that authenticates with Integrated Windows Authentication (Kerberos), and a browser interface that supports SAML 2.0 federation. EHR administrators can terminate active sessions. EHR mobile access is out of scope. | Two authentication paths (ADR-001) and session revocation (02, section 9) |
| A-08 | Network | A private WAN connects clinics, hospitals, and the datacenter. Each hospital has its own internet circuit. The design does not depend on a specific WAN technology. | ADR-008 |
| A-09 | Hosting | The datacenter hosts the EHR platform (application and database tiers), the PACS archive, the laboratory information system, the pharmacy system, the clinical integration engine, file services, and the legacy clinical applications. Azure hosts the patient portal web tier, partner integration services, and analytics. | 02, 04 |
| A-10 | Patient services | The patient portal is a module of the EHR platform whose internet-facing tier runs in Azure behind a web application firewall. Telehealth video runs on a third-party SaaS service integrated with the EHR, under a business associate agreement. | 02, ADR-007 |
| A-11 | Medical devices | Clinical engineering owns medical devices. Many run operating systems that only the manufacturer may patch or reconfigure, and some need periodic manufacturer connectivity for service. | ADR-006 |
| A-12 | Third parties | EHR vendor support staff sign in through their employer's own Microsoft Entra tenant, which enforces phishing-resistant MFA. Contoso confirms this during vendor due diligence rather than assuming it. | 03, ADR-002 |
| A-13 | Third parties | Biomedical device vendors vary: some have Entra tenants, many do not. They need device-specific remote service sessions and occasional on-site work. Contoso treats a biomedical vendor as a business associate when its service can reach ePHI held on a device (imaging modalities, for example, hold patient images). Every vendor with access through the vendor broker is in that group: its sponsor approves the access package only when a signed business associate agreement is on file. A vendor whose work never reaches ePHI is not treated as a business associate. | 03, ADR-006 |
| A-14 | Third parties | The revenue-cycle outsourcer works in EHR billing work queues daily, exchanges claim and remittance files by managed file transfer, operates its own Entra tenant, and is a business associate under a signed agreement. It does not accept card payments for Contoso. | 03, 04 |
| A-15 | Payments | Registration desks use standalone payment terminals from a PCI-listed P2PE solution, not integrated with registration workstations. Online payments use a payment service provider's hosted payment page reached by full URL redirect from the portal. Contoso takes no card payments by phone or mail, and is a merchant, not a service provider. | ADR-007 |
| A-16 | Payments | Validation path: Contoso's acquirer accepts SAQ P2PE for the card-present channel and SAQ A for the e-commerce redirect. If the acquirer requires a different path, such as a full assessment, the CDE segment controls in 04 become validation requirements instead of defense in depth. | 04 section 7, ADR-007 |
| A-17 | Security operations | A 24x7 security operations function works in Defender XDR and Microsoft Sentinel. Defender XDR is connected to Sentinel. Sentinel also ingests Entra sign-in and audit logs, firewall, NAC, and IoMT sensor telemetry. Staffing and log retention are out of scope. | 02 |
| A-18 | Change control | Clinical systems have restricted change windows and clinical-safety review. Every enforcement change in clinical or device zones runs in report-only or monitor mode first. | 05 |
| A-19 | Recovery | Backup and recovery capability exists. ADR-009 states the requirements it must meet: immutable and offline copies, isolation from Tier 0 administrative reach, tested restores with evidence, and Tier 0 monitoring. This design set does not design it: products, topology, and recovery time and point objectives are Contoso's. Until restores are tested against ADR-009, recovery capability is unverified, and the companion threat model treats it that way. | ADR-009, 02, residual risk RR-11 |

## Design principles

| ID | Principle | What it rules out |
|---|---|---|
| P-1 | Patient care continuity is a security requirement. In clinical zones, losing a cloud service degrades to documented local controls, never to an open network. Remote and administrative paths fail closed. | Designs where an internet outage at a hospital stops medication administration, and designs that "fail open" to keep working |
| P-2 | Logical function first, product second. Every component is defined by its NIST SP 800-207 role. Products in the scenario stack appear as example implementations. | Vendor-shaped architecture where a product name stands in for a requirement |
| P-3 | Identity is the control plane where an identity exists. The network is the control plane where it does not, which is most medical devices. | Pretending agentless devices can take part in identity-based access decisions |
| P-4 | Reduce scope before adding controls. | Hardening the whole network to PCI DSS when the card data path can be shrunk instead |
| P-5 | Every exception has an owner, an expiry date, and a log entry. | Permanent exclusions from Conditional Access or firewall policy. The deliberate exception is the emergency access exclusion, which has no expiry; `03-identity-and-access.md` section 5 governs it instead. |
| P-6 | Measure before enforcing: report-only Conditional Access, NAC monitor mode, firewall logging before deny. | Enforcement changes in clinical zones without observed baselines |
| P-7 | Prefer controls Contoso already licenses. Where the design needs more, it says so and names an alternative. | Hidden licensing assumptions |

## Framework baseline

The versions in this table were checked 2026-10-03.

| Framework | Version used | Notes |
|---|---|---|
| NIST SP 800-207, Zero Trust Architecture | Final, August 2020 | Companion implementation guide: NIST SP 1800-35, final June 2025 |
| CISA Zero Trust Maturity Model | Version 2.0, April 2023 | 5 pillars, 3 cross-cutting capabilities, 4 stages (Traditional, Initial, Advanced, Optimal) |
| NIST Cybersecurity Framework | CSF 2.0, February 26, 2024 | Hub framework for the compliance crosswalk |
| HIPAA Security Rule | 45 CFR Part 164 Subpart C as in force | The January 2025 Security Rule NPRM is a proposed rule and is not final as of 2026-10-03. This design is built against the rule in force; the companion research note covers the proposal. |
| PCI DSS | v4.0.1, June 2024 | Applies to the CDE segment only |
| PCI P2PE | v3.2, published 2025-06-30 | Relevant to the registration desk terminals |
| HITRUST CSF | v11.9.0, released 2026-09-24 | Leadership is considering certification. This design set cites no HITRUST CSF identifiers; any HITRUST mapping is handled in the compliance crosswalk. |
| MITRE ATT&CK | v19 (sub-release v19.2) | Used by the companion threat model and detection pack. This design set cites no technique IDs. |

## Out of scope

Honest scoping is part of the design. These items are excluded on purpose, and anything excluded that still creates risk is listed as residual risk in section 13 of `02-reference-architecture.md`.

- Detailed network engineering: IP addressing, routing, WAN technology, wireless RF design, firewall rule bases, NAC product selection, sizing, and cost.
- Backup and recovery implementation: products, topology, recovery time and point objectives, and restore order. ADR-009 sets the requirements any recovery design must meet, and the glossary entry for `SVC-BACKUP` carries them.
- Key management products and key rotation intervals. Section 7 of `02-reference-architecture.md` sets key custody requirements only.
- Physical security, except the payment terminal inspection that PCI DSS requires.
- EHR application internals, such as role design and the configuration of clinical break-the-glass rules, and application security of vendor products.
- Patient identity proofing and customer identity configuration beyond the decision to keep patients out of the workforce tenant.
- Building management and facilities systems beyond assigning them a contained zone.
- Clinical AI tools, research networks, and mergers.
- State breach-notification law and legal advice.
- Detection content, the threat model, and the compliance crosswalk, which are companion artifacts.

## Sources

| Title | Publisher | URL | Date checked | Quality |
|---|---|---|---|---|
| NIST SP 800-207, Zero Trust Architecture | NIST | https://csrc.nist.gov/pubs/sp/800/207/final | 2026-10-03 | Primary |
| NIST SP 1800-35, Implementing a Zero Trust Architecture: High-Level Document | NIST | https://csrc.nist.gov/pubs/sp/1800/35/final | 2026-10-03 | Primary |
| Zero Trust Maturity Model Version 2.0 | CISA | https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf | 2026-10-03 | Primary |
| The NIST Cybersecurity Framework (CSF) 2.0, NIST CSWP 29 | NIST | https://doi.org/10.6028/NIST.CSWP.29 | 2026-10-03 | Primary |
| Windows smart card sign-in using Microsoft Entra certificate-based authentication | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/authentication/concept-certificate-based-authentication-smartcard | 2026-10-03 | Primary |
| Microsoft Entra licensing | Microsoft Learn | https://learn.microsoft.com/en-us/entra/fundamentals/licensing | 2026-10-03 | Primary |
| PCI SSC Releases Version 3.2 of the PCI P2PE Standard | PCI SSC | https://blog.pcisecuritystandards.org/pci-ssc-releases-version-3-2-of-the-pci-point-to-point-encryption-p2pe-standard | 2026-10-03 | Primary |
| Self-Assessment Questionnaire P2PE for PCI DSS v4.0, superseded by the v4.0.1 SAQs and used here for eligibility wording | PCI SSC | https://listings.pcisecuritystandards.org/documents/PCI-DSS-v4-0-SAQ-P2PE.pdf | 2026-10-03 | Primary |
| SAQs for PCI DSS v4.0.1 Now Available (bulletin) | PCI SSC | https://www.pcisecuritystandards.org/wp-content/uploads/2024/10/SAQs_for_PCI_DSS_v4.0.1_Bulletin.pdf | 2026-10-03 | Primary |
| PCI SSC FAQ 1588 (SAQ A eligibility) | PCI SSC | https://www.pcisecuritystandards.org/faqs/1588/ | 2026-10-03 | Primary |
