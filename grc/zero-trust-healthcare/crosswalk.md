# Contoso Regional Health (fictional): HIPAA Security Rule crosswalk

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

This crosswalk maps every standard and implementation specification in the HIPAA Security Rule (45 CFR 164.308, 164.310, 164.312, 164.314, and 164.316) to NIST CSF 2.0 subcategories. It also maps each provision to the components and documents of the Contoso Regional Health (fictional) reference architecture that implement it, to the detection rules, incident response playbooks, and tabletop exercise kit that support it, and to PCI DSS v4.0.1 requirements for the cardholder data environment (CDE) segment only. Each row states how strong the relationship is, cites its sources, and says how far the architecture covers it, including where it does not.

The machine-readable version is `crosswalk.yaml`, validated by `crosswalk.schema.json` and `validate-crosswalk.ps1` (section 9). The architecture lives in `architecture/zero-trust-healthcare/`; component IDs come from the glossary in section 11 of `02-reference-architecture.md`.

## 1. What this is and is not

- **A reference mapping** of published texts to a fictional design, written for a public portfolio. Relationship strengths are an analysis of the texts, not an official mapping by HHS, NIST, or PCI SSC.
- **Not an audit, an assessment, an attestation, or an evaluation** under 45 CFR 164.308(a)(8). It certifies nothing about any organization, and meeting a mapped CSF outcome does not by itself establish HIPAA compliance.
- **Built against the rule in force.** The January 6, 2025 HIPAA Security Rule notice of proposed rulemaking (90 FR 898) is a proposed rule, not final. The 2026 Unified Agenda lists it under Long-Term Actions with final action targeted for July 2027 (checked 2026-10-07). Nothing proposed in it appears here as a requirement.
- **Detections support rows; they do not cover them.** Rules, the incident response playbooks, and the tabletop exercise kit from the companion detection pack are linked where they carry out part of a provision (section 3). No link changes a coverage label.

## 2. Frameworks and versions

The Sources section at the end lists the source for each version and the date it was checked.

| Framework | Version used | Role here |
|---|---|---|
| HIPAA Security Rule | 45 CFR Part 164 Subpart C as in force (eCFR text current through 2026-09-30, read 2026-10-04) | Source rows: all 65 standards and implementation specifications |
| NIST Cybersecurity Framework | CSF 2.0, NIST CSWP 29 (February 26, 2024) | Hub. Outcome text checked against Appendix A of the NIST PDF on 2026-10-04 |
| PCI DSS | v4.0.1 (June 2024) | Targets for the Z-CDE segment only |
| HITRUST CSF | v11.9.0 (released 2026-09-24) | Not mapped; see section 4 |

Because this crosswalk traces the Security Rule's requirements, and PCI DSS requirements for the CDE, through the CSF 2.0 hub, it does not map two voluntary health-sector resources: the Health Industry Cybersecurity Practices (HICP, 2023 Edition), developed under section 405(d) of the Cybersecurity Act of 2015, and HHS's Healthcare and Public Health (HPH) Cybersecurity Performance Goals, which HHS aligns to HICP sub-practices in its own materials.

## 3. Method

**Hub and direction.** Each HIPAA provision is the source row. Its CSF 2.0 subcategories are the hub targets, and relationship strength is judged from the HIPAA provision toward the CSF outcome. PCI DSS rows connect through a shared CSF subcategory, so the two frameworks meet at the hub, not directly.

**Relationship strength.**

| Strength | Meaning |
|---|---|
| equivalent | Same objective at comparable scope for ePHI. Used twice in this crosswalk, and the HIPAA wording still governs. |
| partial | Substantial overlap, but one side has elements the other lacks: scope, specificity, or a required action. Meeting one does not establish the other. |
| related | Same subject area or a supporting relationship. Good for organizing evidence, not for claiming coverage. |

**Coverage by the reference architecture.**

| Coverage | Meaning |
|---|---|
| designed | The design set names components that implement the technical substance. The policies and procedures the provision also requires stay organizational work. |
| partial | The design implements part of the provision; the rest depends on procedures or on systems the design does not cover. |
| procedural | Met by policy, process, or people. The architecture supplies supporting evidence at most. |
| out-of-scope | Excluded from the design on purpose (`01-scenario-and-assumptions.md`, Out of scope). The gap is stated, not hidden. |
| not-applicable | Does not apply to Contoso as the scenario defines it. The row stays so that coverage of 164.308 to 164.316 is complete. |

**Required, addressable, and standards.** Every standard is mandatory (45 CFR 164.306(c)). Implementation specifications are marked R (required) or A (addressable). Addressable does not mean optional: under 45 CFR 164.306(d)(3) the entity assesses each addressable specification, implements it if reasonable and appropriate, and otherwise documents why and implements an equivalent alternative if one is reasonable and appropriate. Appendix A to Subpart C lists standards that have no separate specifications with an (R).

**PCI DSS for the CDE segment only.** PCI DSS targets appear only on rows flagged `cde_scope: true`, and each such row must reference zone `Z-CDE` or a CDE component (`RES-POI`, `PEP-CDE-BOUNDARY`, `EXT-P2PE`, `EXT-PSP`). The validator enforces this. The HIPAA and PCI scopes are disjoint by design: the CDE holds payment terminals and no ePHI. Most PCI links are therefore `related`, meaning a shared control objective carried out by the same architecture element on different data. The one `partial` link is 12.10.1, where one incident response plan can serve both regimes. Status columns follow assumption A-16 and `04-segmentation.md` section 7:
- On SAQ P2PE: SAQ P2PE for PCI DSS v4.0 (April 2022, superseded by the v4.0.1 SAQs) assesses Requirement 3 items for paper records only, 9.1.1, 9.4.x for paper media, 9.5.1, 9.5.1.1, 9.5.1.2, 9.5.1.3, 12.1.1 to 12.1.3, 12.6.1, 12.8.1 to 12.8.5, and 12.10.1.
- Not on it: 9.5.1.2.1 and 12.3.1, and nothing from Requirements 1, 7, 8, 10, or 11.
- PCI SSC's own copy of the v4.0.1 SAQ P2PE returned HTTP 403, so this list was checked against the v4.0 document and PCI SSC's statement that v4.0.1 added and deleted no requirements. A third-party copy of the v4.0.1 SAQ P2PE lists the same requirements, with 9.5.1.2.1 shown only as intentionally left blank for this SAQ (`research/zero-trust-healthcare/sources.md` section 2.6).

**Detections.** The companion detection pack in `detections/zero-trust-healthcare/` holds 22 rules (9 Defender XDR, 7 Sentinel, 6 Sigma), two incident response playbooks (identity compromise and ransomware), a ransomware tabletop exercise kit, and a coverage map; file names come from its `detections-index.md`. A rule, a playbook, or the kit is linked to a row where it carries out or documents part of what the provision's text requires, for example reviewing activity records (164.308(a)(1)(ii)(D)), examining recorded activity (164.312(b)), or monitoring log-in attempts (164.308(a)(5)(ii)(C)). Each link in `crosswalk.yaml` names the file and its purpose for that row. A link never raises a coverage label: detecting a problem is not the same as meeting the provision, every rule is an untested template, neither playbook has been exercised, and the tabletop kit has not been run.

**Citations.** HIPAA rows cite the eCFR section, CSF targets cite NIST CSWP 29 Appendix A, and PCI targets cite the v4.0.1 standard. Each PCI requirement number and paraphrase was checked against PCI SSC's own documents, listed per requirement in `crosswalk.yaml`: numbering and wording against the v4.0 SAQs and the Summary of Changes from v3.2.1 to v4.0, and wording also against PCI SSC's Summary of Changes from v4.0 to v4.0.1 (Revision 1, August 2024). That second check is why the 12.3.1 and 8.4.3 paraphrases follow the v4.0.1 wording. The v4.0.1 standard itself could not be retrieved, and PCI SSC says its summary does not detail every revision. PCI DSS text is copyrighted, so every PCI summary is paraphrased. Federal regulatory text and NIST text are quoted only where exact wording matters.

## 4. HITRUST CSF: license review and decision

The scenario says Contoso's leadership is considering HITRUST certification, so a HITRUST mapping would be a natural addition. The license terms were reviewed first, on 2026-10-04:

- **Who may use it.** The HITRUST CSF License Agreement (HITRUST CSF Version 11.9, effective September 24, 2026) authorizes access only for parties to specified HITRUST agreements and for qualified organizations and individuals. It lists IT security service providers, product providers, consultants, and vendors as not qualified.
- **What use is allowed.** The grant covers access to portions of the CSF for the licensee's internal educational and internal information-sharing purposes, for the licensee's sole use. It rules out any other purpose, external disclosure included.
- **What is prohibited.** The agreement prohibits disclosing a copy of the CSF, in whole or in part, or any data in it, to anyone who is not a licensee or authorized user. It also prohibits creating derivative works based on any part of the CSF without HITRUST's prior written consent, and its definition of derivative work covers compilations and adaptations.
- **Exceptions.** Carve-outs exist for information that is public knowledge, already known, independently developed, or lawfully obtained from a third party.
- **Site terms.** HITRUST's Terms of Use for its site (last modified January 8, 2024) prohibit republishing site material and using HITRUST names, logos, or other brand assets without written permission.

Nothing in either document clearly permits publishing HITRUST CSF identifiers or a mapping to them. A public crosswalk to HITRUST requirements would be a derivative work built from licensed content.

**Decision:** this crosswalk contains no HITRUST CSF identifiers and no HITRUST logo; HITRUST is named only to explain the decision. The decision is also recorded in `crosswalk.yaml` (`metadata.hitrust`), where the schema requires `identifiers_included: false`. A HITRUST mapping for Contoso would have to be built inside a licensed environment.

## 5. Summary

| Measure | Count |
|---|---|
| HIPAA rows (standards and implementation specifications) | 65 |
| Applicability | 60 applicable, 1 indirect, 4 not applicable |
| Coverage by the design | 16 designed, 25 partial, 13 procedural, 7 out of scope, 4 not applicable |
| CSF 2.0 links | 124: 2 equivalent, 66 partial, 56 related |
| Distinct CSF 2.0 subcategories used as targets | 57, plus 4 more reached only through PCI rows |
| PCI DSS v4.0.1 links | 30, on 12 rows scoped to Z-CDE |
| Detections linked | 94 links on 21 rows, to 26 files: all 22 rules, both incident response playbooks, the tabletop exercise kit, and the coverage map |

What the numbers say:
- The architecture carries most of the technical safeguards (164.312) and the technical parts of the administrative safeguards.
- Physical safeguards are mostly out of scope.
- Recovery rests on requirements without a design (ADR-009), so the data backup, disaster recovery, and testing rows are partial.
- Contracts, training, sanctions, documentation, and evaluation are organizational work that no architecture performs.
- Detection links cluster on activity review and audit controls, where every rule counts, and then on malicious software, authentication, log-in monitoring, and password safeguarding. Two rules (SN-06 and SN-07) also support the emergency access procedure. The two incident response playbooks support the security management process, security incident procedures, and documentation rows; the ransomware playbook also supports the contingency plan, disaster recovery, and emergency mode rows, and the tabletop kit supports the testing and revision row. No detection supports a physical safeguard (164.310) or an organizational requirement (164.314).

## 6. Crosswalk

Shorthand in the Architecture and Detections columns:
- **Documents.** "01" to "05" are the architecture documents, "s" means section, and ADR numbers refer to the decision records in `architecture/zero-trust-healthcare/adr/`.
- **IDs.** CA-xx, F-xx, and RR-xx are Conditional Access policies, data flows, and residual risks from the architecture.
- **Detections.** DX-xx (Defender XDR), SN-xx (Sentinel), and SG-xx (Sigma) are rule IDs from `detections-index.md` in `detections/zero-trust-healthcare/`. `ir-identity-compromise.md` and `ir-ransomware.md` are the incident response playbooks, `tabletop-ransomware.md` is the ransomware tabletop exercise kit, and `coverage-map.md` is the coverage map. `crosswalk.yaml` gives each linked file with its purpose for the row.
- **Citations.** Each HIPAA citation links to its eCFR section. CSF targets cite NIST CSWP 29, Appendix A.

### 6.1 Administrative safeguards (45 CFR 164.308)

| HIPAA | Standard or specification (R/A) | Summary (paraphrase) | CSF 2.0 targets | Architecture | Detections | Coverage | PCI DSS v4.0.1 (CDE only) |
|---|---|---|---|---|---|---|---|
| [164.308(a)(1)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Security management process (standard) | Have policies and procedures that prevent, detect, contain, and correct security violations. | GV.PO-01 (partial); GV.RM-01 (related) | `PIP-SIEM`, `PIP-XDR`, `PEP-HOST`, `PE-NETWORK`; 01 Design principles, 05 s4, 02 s13 | ir-identity-compromise.md, ir-ransomware.md (contain and correct) | partial | none |
| [164.308(a)(1)(ii)(A)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Risk analysis (R) | Accurately and thoroughly assess the risks and vulnerabilities to the confidentiality, integrity, and availability of the ePHI the entity holds. | ID.RA-05 (partial); ID.RA-01 (partial); ID.RA-03 (partial); ID.RA-04 (partial); ID.AM-07 (related) | `PIP-ASSET-INV`, `PIP-IOMT-SENSOR`, `PIP-VULN`, `PIP-DATA-CLASS`, `RES-POI`; 04 s3, ADR-006, 02 s13, 04 s7, risk-register.md; RR-14 | none | partial | 1.2.3, 1.2.4, 12.3.1, 12.5.2 |
| [164.308(a)(1)(ii)(B)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Risk management (R) | Put security measures in place that reduce risks and vulnerabilities to a reasonable and appropriate level. | ID.RA-06 (partial); GV.RM-02 (related); ID.RA-07 (related) | `PE-IDENTITY`, `IGA-ENTRA`, `PE-NETWORK`, `PEP-NET-ZONE`, `PEP-ENCLAVE-GW`; 05 s4, ADR-005, ADR-006, risk-register.md | DX-03, DX-04, SN-01, SN-03 (compensating detections) | partial | none |
| [164.308(a)(1)(ii)(C)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Sanction policy (R) | Apply appropriate sanctions to workforce members who do not follow the security policies and procedures. | GV.RR-04 (partial); GV.PO-01 (related) | None; an HR and compliance process | none | procedural | none |
| [164.308(a)(1)(ii)(D)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Information system activity review (R) | Regularly review records of system activity, such as audit logs, access reports, and security incident tracking reports. | DE.CM-03 (partial); DE.AE-02 (partial); PR.PS-04 (related); DE.AE-03 (related) | `PIP-SIEM`, `PIP-XDR`, `PIP-ID-RISK`, `PEP-NET-ZONE`, `PEP-VENDOR-BROKER`; 02 s3, 03 s4, 04 s6; RR-14 | All 22 rules (DX-01 to DX-09, SN-01 to SN-07, SG-01 to SG-06); coverage-map.md s4 | designed | none |
| [164.308(a)(2)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Assigned security responsibility (standard) | Name the security official responsible for developing and implementing the Security Rule policies and procedures. | GV.RR-02 (partial); GV.RR-01 (related) | 05 s4 (steering group, WP-0.1) | none | procedural | none |
| [164.308(a)(3)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Workforce security (standard) | Make sure workforce members have appropriate access to ePHI and that those without authorized access cannot obtain it. | PR.AA-05 (partial); PR.AA-01 (related) | `IDS-SOR`, `IGA-ENTRA`, `PE-IDENTITY`, `PEP-SSO-APP`; 03 s1, 03 s3 | none | designed | none |
| [164.308(a)(3)(ii)(A)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Authorization and/or supervision (A) | Authorize or supervise workforce members who work with ePHI or in places where it can be accessed. | PR.AA-05 (partial); DE.CM-03 (related) | `IGA-ENTRA`, `PEP-SSO-APP`; 03 s4 (vendor engineers: see section 8) | none | partial | none |
| [164.308(a)(3)(ii)(B)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Workforce clearance procedure (A) | Have a procedure to determine that a workforce member's access to ePHI is appropriate. | GV.RR-04 (partial); PR.AA-02 (related); PR.AA-05 (related) | `IDS-SOR`, `IGA-ENTRA`; 03 s1, 03 s2 | none | partial | none |
| [164.308(a)(3)(ii)(C)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Termination procedures (A) | End access to ePHI when employment or another arrangement ends, or when a clearance determination requires it. | PR.AA-01 (partial); PR.AA-05 (partial); GV.RR-04 (related) | `IDS-SOR`, `IDS-AD`, `IDS-SYNC`, `IDS-ENTRA`, `PA-IDENTITY`, `IGA-ENTRA`; 03 s1, 02 s9 | none | designed | none |
| [164.308(a)(4)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Information access management (standard) | Have policies and procedures for authorizing access to ePHI that are consistent with the Privacy Rule (Subpart E). | PR.AA-05 (partial); GV.PO-01 (related) | `PE-IDENTITY`, `IGA-ENTRA`, `PEP-SSO-APP`, `PE-NETWORK`; 03 s3, 04 s2 | none | designed | none |
| [164.308(a)(4)(ii)(A)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Isolating health care clearinghouse functions (R) | If a health care clearinghouse is part of a larger organization, protect the clearinghouse's ePHI from unauthorized access by the rest of the organization. | None; not applicable | 01 Scenario (fixed): no clearinghouse function | none | not-applicable | none |
| [164.308(a)(4)(ii)(B)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Access authorization (A) | Have policies and procedures for granting access to ePHI, for example through a workstation, transaction, program, or process. | PR.AA-05 (partial) | `IGA-ENTRA`, `PE-IDENTITY`, `PEP-SSO-APP`, `PEP-PAW`; CA-03, CA-07, CA-08, CA-11, CA-13; 03 s3, s4, s7, 04 s7 | SN-03 | designed | 7.2.1, 7.2.2 |
| [164.308(a)(4)(ii)(C)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Access establishment and modification (A) | Based on the access authorization policies, establish, document, review, and change each user's access rights. | PR.AA-05 (partial); PR.AA-01 (related) | `IGA-ENTRA`, `IDS-SOR`; 03 s4, s5, ADR-004, 04 s7; RR-16 | SN-02, SN-07 | designed | 7.2.4 |
| [164.308(a)(5)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Security awareness and training (standard) | Run a security awareness and training program for the whole workforce, management included. | PR.AT-01 (equivalent); PR.AT-02 (related) | None designed; 04 s7 names terminal tamper training only | none | procedural | 9.5.1.3 |
| [164.308(a)(5)(ii)(A)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Security reminders (A) | Give the workforce periodic security updates. | PR.AT-01 (partial) | None; part of the awareness program | none | procedural | none |
| [164.308(a)(5)(ii)(B)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Protection from malicious software (A) | Have procedures for guarding against, detecting, and reporting malicious software. | DE.CM-09 (partial); PR.PS-05 (partial); PR.AT-01 (related) | `PIP-EDR`, `PEP-HOST`, `SVC-EMAIL`, `PIP-XDR`, `PIP-TI`, `PIP-IOMT-SENSOR`; 02 s11, 04 s6, ADR-006; RR-14 | DX-01, DX-02, DX-08, DX-09, SG-01, SG-02, SG-03 | designed | none |
| [164.308(a)(5)(ii)(C)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Log-in monitoring (A) | Have procedures for monitoring log-in attempts and reporting discrepancies. | DE.CM-03 (partial); DE.AE-02 (related) | `PIP-ID-RISK`, `PE-IDENTITY`, `PIP-SIEM`; CA-17, CA-18; 03 s3, 03 s4 | DX-03, DX-07 (its logon signal needs Defender for Endpoint on `IDS-SYNC`; see section 8), SN-01, SN-04, SN-06 | designed | none |
| [164.308(a)(5)(ii)(D)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Password management (A) | Have procedures for creating, changing, and safeguarding passwords. | PR.AA-01 (partial); PR.AA-03 (related) | `IDS-AD`, `IDS-ENTRA`, `PA-IDENTITY`, `PIP-PKI`; CA-19; 03 s2, s4, s5, s6 | DX-05, DX-06, SG-05, SG-06 | designed | none |
| [164.308(a)(6)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Security incident procedures (standard) | Have policies and procedures to address security incidents. | ID.IM-04 (partial); RS.MA-01 (related) | `PIP-SIEM`, `PIP-XDR`; 04 s6, ADR-008, notification-clocks.md s4 | ir-identity-compromise.md, ir-ransomware.md | partial | 12.10.1 |
| [164.308(a)(6)(ii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Response and reporting (R) | Identify and respond to suspected or known security incidents, mitigate their harmful effects where practicable, and document incidents and their outcomes. | DE.AE-08 (partial); RS.MI-01 (partial); RS.AN-06 (partial); RS.CO-02 (related) | `PIP-XDR`, `PIP-SIEM`, `PEP-HOST`, `PA-IDENTITY`, `PE-NETWORK`, `PEP-NET-ZONE`; 04 s3, s6, ADR-008, notification-clocks.md s2 | ir-identity-compromise.md, ir-ransomware.md | designed | none |
| [164.308(a)(7)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Contingency plan (standard) | Establish, and implement as needed, policies and procedures for responding to an emergency or other occurrence that damages systems containing ePHI. | ID.IM-04 (partial); PR.IR-03 (related); RC.RP-01 (related) | `IDS-AD`, `PE-NETWORK`, `PEP-NET-ZONE`, `PIP-PKI`, `SVC-BACKUP`; ADR-008, ADR-009, 02 s10; RR-11, RR-13 | ir-ransomware.md (downtime and restore decisions) | partial | none |
| [164.308(a)(7)(ii)(A)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Data backup plan (R) | Establish and implement procedures to create and maintain retrievable exact copies of ePHI. | PR.DS-11 (partial) | `SVC-BACKUP` (requirements only), `IDS-AD`, `PIP-PKI`, `RES-EHR`, `RES-PACS`, `RES-LIS`, `RES-PHARM`, `RES-INTEGRATION`, `RES-LEGACY`, `RES-FILES`, `RES-AZ-WORKLOADS`; ADR-009, 01 Out of scope (implementation), 02 s13; RR-11 | DX-01, SG-01, SN-05 (where recovery points exist) | partial | none |
| [164.308(a)(7)(ii)(B)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Disaster recovery plan (R) | Establish, and implement as needed, procedures to restore any loss of data. | RC.RP-01 (partial); RC.RP-03 (related); RC.RP-05 (related) | `SVC-BACKUP`, `IDS-AD`, `PIP-PKI`; ADR-008, ADR-009, 03 s5; RR-10, RR-11 | ir-ransomware.md (restore decisions) | partial | none |
| [164.308(a)(7)(ii)(C)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Emergency mode operation plan (R) | Establish, and implement as needed, procedures that keep critical business processes running while protecting ePHI during emergency mode operation. | PR.IR-03 (partial); GV.OC-04 (related) | `IDS-AD`, `PE-NETWORK`, `PEP-NET-ACCESS`, `PEP-NET-ZONE`, `PIP-PKI`, `PEP-SSO-APP`; F-01; ADR-001, ADR-008, 02 s10; RR-02, RR-13 | ir-ransomware.md (downtime decisions) | designed | none |
| [164.308(a)(7)(ii)(D)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Testing and revision procedures (A) | Periodically test contingency plans and revise them. | ID.IM-02 (partial); ID.IM-04 (partial) | `SVC-BACKUP`; ADR-008 (failure-mode drills), ADR-009 (restore tests), 05 s4 (WP-3.4); RR-11 | tabletop-ransomware.md (discussion exercise, not a restore test; not run) | partial | none |
| [164.308(a)(7)(ii)(E)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Applications and data criticality analysis (A) | Assess how critical specific applications and data are, to support the other parts of the contingency plan. | ID.AM-05 (partial); GV.OC-04 (related) | `PIP-ASSET-INV`, `RES-EHR`, `RES-PACS`, `RES-LIS`, `RES-PHARM`, `RES-INTEGRATION`, `IDS-AD`, `PIP-PKI`; F-01, F-08; ADR-001, ADR-008 (local-first set), ADR-009 (scope floor); RR-11 | none | partial | none |
| [164.308(a)(8)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Evaluation (standard) | Periodically evaluate, technically and nontechnically, how well security policies and procedures meet the Security Rule, first against the standards and later after environmental or operational changes. | GV.OV-03 (partial); ID.IM-01 (partial); GV.PO-02 (related) | `PEP-CDE-BOUNDARY` (segmentation testing); 05 s6, ADR-001, 04 s7 | none | procedural | 11.4.5 |
| [164.308(b)(1)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Business associate contracts and other arrangements (standard) | Let a business associate create, receive, maintain, or transmit ePHI for the covered entity only after obtaining satisfactory assurances, under 164.314(a), that it will safeguard the information. | GV.SC-05 (partial); GV.SC-06 (related); GV.SC-07 (related) | `EXT-VENDOR-EHR`, `EXT-VENDOR-BIOMED`, `EXT-RCM-BA`, `EXT-TELEHEALTH`, `PEP-VENDOR-BROKER`, `PEP-APP-PROXY`, `RES-RCM-EXCHANGE`; F-06, F-07, F-09; 01 Assumptions (A-13), 03 s7, s9, ADR-002; RR-06, RR-12 | none | partial | none |
| [164.308(b)(3)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Written contract or other arrangement (R) | Document the satisfactory assurances in a written contract or other arrangement that meets 164.314(a). | GV.SC-05 (partial) | 03 s7 (business associate agreements) | none | procedural | none |

164.308(b)(2), which applies the same assurance rule between a business associate and its subcontractors, is covered in the 164.308(b)(1) row and in 164.314(a)(2)(iii).

### 6.2 Physical safeguards (45 CFR 164.310)

| HIPAA | Standard or specification (R/A) | Summary (paraphrase) | CSF 2.0 targets | Architecture | Detections | Coverage | PCI DSS v4.0.1 (CDE only) |
|---|---|---|---|---|---|---|---|
| [164.310(a)(1)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Facility access controls (standard) | Limit physical access to electronic information systems and the facilities that house them, while still allowing authorized access. | PR.AA-06 (partial) | 01 Out of scope | none | out-of-scope | none |
| [164.310(a)(2)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Contingency operations (A) | Allow facility access in support of restoring lost data under the disaster recovery and emergency mode operation plans. | PR.AA-06 (related); PR.IR-03 (related) | 01 Out of scope | none | out-of-scope | none |
| [164.310(a)(2)(ii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Facility security plan (A) | Safeguard the facility and the equipment in it from unauthorized physical access, tampering, and theft. | PR.AA-06 (partial); DE.CM-02 (related) | `RES-POI`, `PIP-ASSET-INV` (payment terminal inspection only); 01 Out of scope, 04 s7 | none | out-of-scope | 9.5.1, 9.5.1.2, 9.5.1.2.1 |
| [164.310(a)(2)(iii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Access control and validation procedures (A) | Control and validate each person's access to facilities by role or function, including visitor control and control of access to software programs for testing and revision. | PR.AA-06 (partial) | 01 Out of scope | none | out-of-scope | none |
| [164.310(a)(2)(iv)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Maintenance records (A) | Document repairs and changes to the security-related physical parts of a facility, such as hardware, walls, doors, and locks. | PR.AA-06 (related) | 01 Out of scope | none | out-of-scope | none |
| [164.310(b)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Workstation use (standard) | Specify the functions performed on each workstation or class of workstation that can access ePHI, how they are performed, and the physical surroundings. | PR.PS-01 (partial); GV.PO-01 (related) | `PEP-PAW`, `PIP-DEVICE-MGMT`, `PEP-HOST`; CA-04, CA-05, CA-12; 03 s3, 03 s4 | none | partial | none |
| [164.310(c)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Workstation security (standard) | Put physical safeguards on every workstation that accesses ePHI so that only authorized users can use it. | PR.AA-06 (partial); PR.AA-03 (related) | `PIP-PKI`, `PEP-HOST` (lock on badge removal); ADR-003, 01 Out of scope | none | partial | none |
| [164.310(d)(1)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Device and media controls (standard) | Govern how hardware and electronic media containing ePHI come into and leave a facility, and how they move within it. | ID.AM-08 (partial); ID.AM-01 (related) | `PIP-ASSET-INV`, `PIP-DEVICE-MGMT`; 04 s3, 02 s11; RR-15 | none | partial | none |
| [164.310(d)(2)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Disposal (R) | Address the final disposition of ePHI and of the hardware or electronic media that stores it. | ID.AM-08 (partial); PR.PS-03 (partial) | `PIP-ASSET-INV`, `RES-IOMT`; 04 s3 (decommissioning), ADR-006; RR-15 | none | partial | none |
| [164.310(d)(2)(ii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Media re-use (R) | Remove ePHI from electronic media before the media is made available for re-use. | ID.AM-08 (partial); PR.DS-01 (related) | `PIP-ASSET-INV`, `RES-IOMT`; 04 s3, ADR-006; RR-15 | none | partial | none |
| [164.310(d)(2)(iii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Accountability (A) | Keep a record of the movements of hardware and electronic media and of the person responsible. | ID.AM-01 (partial); ID.AM-08 (related) | `PIP-ASSET-INV`, `RES-POI`; 02 s11, 04 s3, 04 s7 | none | partial | 9.5.1.1 |
| [164.310(d)(2)(iv)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Data backup and storage (A) | When needed, create a retrievable, exact copy of ePHI before moving equipment. | PR.DS-11 (partial) | `SVC-BACKUP`; 01 Out of scope (ADR-009 does not cover a copy before equipment moves); RR-11 | none | out-of-scope | none |

### 6.3 Technical safeguards (45 CFR 164.312)

| HIPAA | Standard or specification (R/A) | Summary (paraphrase) | CSF 2.0 targets | Architecture | Detections | Coverage | PCI DSS v4.0.1 (CDE only) |
|---|---|---|---|---|---|---|---|
| [164.312(a)(1)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Access control (standard) | Use technical policies and procedures so that systems holding ePHI allow access only to the persons or software programs granted access rights under 164.308(a)(4). | PR.AA-05 (partial); PR.IR-01 (partial); PR.AA-03 (related) | `PE-IDENTITY`, `PA-IDENTITY`, `PEP-SSO-APP`, `PEP-APP-PROXY`, `PEP-SESSION-PROXY`, `PEP-ZTNA-BROKER`, `PEP-ZTNA-CONNECTOR`, `PEP-VENDOR-BROKER`, `PE-NETWORK`, `PEP-NET-ACCESS`, `PEP-NET-ZONE`, `PEP-ENCLAVE-GW`, `PEP-CLOUD-NET`, `PEP-CDE-BOUNDARY`; F-01, F-03, F-05, F-06, F-10; 02 s3, s6, 03 s3, 04 s1, s7, ADR-001, ADR-002 | SN-02 | designed | 1.3.1, 1.3.2, 1.3.3, 1.4.1, 1.5.1 |
| [164.312(a)(2)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Unique user identification (R) | Give each user a unique name or number for identifying and tracking user identity. | PR.AA-01 (partial) | `IDS-AD`, `IDS-ENTRA`, `IDS-SOR`, `PIP-PKI`; 03 s1, 03 s9, ADR-003 | none | designed | none |
| [164.312(a)(2)(ii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Emergency access procedure (R) | Establish, and implement as needed, procedures for obtaining necessary ePHI during an emergency. | PR.IR-03 (related); PR.AA-05 (related) | `PEP-SSO-APP`, `RES-EHR`, `IDS-ENTRA`, `IDS-AD`; 03 s5, ADR-004, ADR-008; RR-10, RR-16 | SN-06, SN-07 | partial | none |
| [164.312(a)(2)(iii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Automatic logoff (A) | Use electronic procedures that end a session after a set period of inactivity. | PR.AA-05 (related); PR.AA-03 (related) | `PEP-SSO-APP`, `RES-EHR`, `RES-M365`, `PA-IDENTITY`, `PEP-HOST`, `PIP-PKI`; CA-10, CA-12, CA-14; 02 s9, ADR-003; RR-03 | none | partial | none |
| [164.312(a)(2)(iv)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Encryption and decryption (A) | Put in place a mechanism to encrypt and decrypt ePHI. | PR.DS-01 (partial); PR.DS-10 (related) | `PEP-DATA`, `PIP-DATA-CLASS`, `PIP-DEVICE-MGMT`, `RES-M365`, `RES-FILES`, `RES-EHR`, `RES-PACS`, `RES-LIS`, `RES-PHARM`, `RES-INTEGRATION`, `RES-LEGACY`, `RES-AZ-WORKLOADS`, `RES-RCM-EXCHANGE`, `RES-IOMT`, `PIP-ASSET-INV`, `SVC-BACKUP`; 02 s7 (data at rest by data-store class), s12, 05 s4 (WP-2.8), ADR-006, ADR-009; RR-11, RR-15 (see section 8) | none | partial | none |
| [164.312(b)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Audit controls (standard) | Use hardware, software, or procedural mechanisms that record and examine activity in systems that contain or use ePHI. | PR.PS-04 (partial); DE.CM-03 (partial); DE.CM-09 (related) | `PIP-SIEM`, `PIP-XDR`, `PEP-NET-ZONE`, `PEP-VENDOR-BROKER`, `PEP-SSO-APP`, `PEP-CDE-BOUNDARY`; 02 s3, s12, 03 s4, s5, 04 s1, s6, ADR-004, ADR-009; RR-01, RR-14 | All 22 rules (DX-01 to DX-09, SN-01 to SN-07, SG-01 to SG-06); coverage-map.md s5 | designed | 10.2.1 |
| [164.312(c)(1)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Integrity (standard) | Have policies and procedures that protect ePHI from improper alteration or destruction. | PR.DS-01 (partial); PR.DS-02 (related) | `PEP-SSO-APP`, `PEP-HOST`, `PEP-WAF`, `SVC-BACKUP`; 02 s11, ADR-009, 01 Out of scope; RR-11 | DX-02 | partial | none |
| [164.312(c)(2)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Mechanism to authenticate electronic protected health information (A) | Use electronic mechanisms that confirm ePHI has not been altered or destroyed without authorization. | PR.DS-01 (partial); DE.CM-09 (related) | 01 Out of scope (EHR internals) | none | out-of-scope | none |
| [164.312(d)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Person or entity authentication (standard) | Have procedures to verify that a person or entity seeking access to ePHI is the one claimed. | PR.AA-03 (equivalent); PR.AA-02 (related); PR.AA-04 (related) | `PE-IDENTITY`, `PA-IDENTITY`, `IDS-AD`, `IDS-ENTRA`, `IDS-PARTNER`, `IDS-CIAM`, `PIP-PKI`, `PE-NETWORK`, `PEP-VENDOR-BROKER`, `RES-LEGACY`, `RES-PORTAL`; CA-02, CA-03, CA-07, CA-11, CA-14; F-14; 03 s2, s8, ADR-003, ADR-005, 04 s7; RR-02, RR-06 | DX-03, DX-05, DX-07, SN-01, SN-02, SN-04 | designed | 8.2.7, 8.4.1, 8.4.2, 8.4.3, 8.5.1 |
| [164.312(e)(1)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Transmission security (standard) | Use technical measures that guard against unauthorized access to ePHI sent over an electronic communications network. | PR.DS-02 (partial); PR.IR-01 (related) | `PEP-ZTNA-CLIENT`, `PEP-ZTNA-BROKER`, `PEP-ZTNA-CONNECTOR`, `PEP-APP-PROXY`, `PEP-CLOUD-NET`, `RES-AZ-WORKLOADS`, `RES-INTEGRATION`, `RES-RCM-EXCHANGE`; F-03, F-04, F-13; 04 s5, 03 s6, 02 s8 | none | designed | none |
| [164.312(e)(2)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Integrity controls (A) | Make sure ePHI sent electronically is not improperly modified without detection until it is disposed of. | PR.DS-02 (partial) | `PEP-ZTNA-BROKER`, `PEP-APP-PROXY`, `RES-INTEGRATION`, `PEP-NET-ZONE`; 05 s3, 04 s3; RR-04 | none | partial | none |
| [164.312(e)(2)(ii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Encryption (A) | Encrypt ePHI whenever this is judged appropriate. | PR.DS-02 (partial) | `PEP-ZTNA-CLIENT`, `PEP-ZTNA-BROKER`, `PEP-APP-PROXY`, `PEP-CLOUD-NET`, `RES-INTEGRATION`; 05 s3, 02 s12 | none | partial | none |

### 6.4 Organizational requirements (45 CFR 164.314)

| HIPAA | Standard or specification (R/A) | Summary (paraphrase) | CSF 2.0 targets | Architecture | Detections | Coverage | PCI DSS v4.0.1 (CDE only) |
|---|---|---|---|---|---|---|---|
| [164.314(a)(1)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.314) | Business associate contracts or other arrangements (standard) | The contract or other arrangement that 164.308(b)(3) requires must meet the content rules in 164.314(a)(2). | GV.SC-05 (partial) | `EXT-VENDOR-EHR`, `EXT-VENDOR-BIOMED`, `EXT-RCM-BA`, `EXT-TELEHEALTH`, `EXT-P2PE`, `EXT-PSP`; F-10, F-11; 03 s7, 04 s7, ADR-007; RR-12 | none | procedural | 12.8.1, 12.8.2, 12.8.3, 12.8.4, 12.8.5 |
| [164.314(a)(2)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.314) | Business associate contracts (R) | The contract must require the business associate to comply with the Security Rule, to bind subcontractors that handle ePHI to the same terms, and to report any security incident it becomes aware of, including breaches of unsecured PHI under 164.410. | GV.SC-05 (partial); GV.SC-08 (related) | `EXT-VENDOR-EHR`, `EXT-VENDOR-BIOMED`, `EXT-RCM-BA`, `EXT-TELEHEALTH`; notification-clocks.md s3, 03 s7 | none | procedural | none |
| [164.314(a)(2)(ii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.314) | Other arrangements (R) | A covered entity can instead rely on another arrangement that meets 164.504(e)(3). | None; not applicable | 01 Assumptions (A-10, A-13, A-14): business associates sign agreements | none | not-applicable | none |
| [164.314(a)(2)(iii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.314) | Business associate contracts with subcontractors (R, indirect) | The same contract requirements apply between a business associate and its subcontractor as between a covered entity and a business associate. | GV.SC-05 (related) | `EXT-RCM-BA`; 03 s7 | none | procedural | none |
| [164.314(b)(1)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.314) | Requirements for group health plans (standard) | A group health plan must make its plan documents require the plan sponsor to safeguard the ePHI it handles for the plan, except in limited Privacy Rule cases. | None; not applicable | 01 Scenario (fixed): no group health plan | none | not-applicable | none |
| [164.314(b)(2)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.314) | Implementation specifications (R) | The plan documents must require the sponsor to apply safeguards, support the required separation with security measures, bind its agents to the same measures, and report security incidents to the plan. | None; not applicable | 01 Scenario (fixed) | none | not-applicable | none |

### 6.5 Policies, procedures, and documentation (45 CFR 164.316)

| HIPAA | Standard or specification (R/A) | Summary (paraphrase) | CSF 2.0 targets | Architecture | Detections | Coverage | PCI DSS v4.0.1 (CDE only) |
|---|---|---|---|---|---|---|---|
| [164.316(a)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.316) | Policies and procedures (standard) | Implement reasonable and appropriate policies and procedures to comply with the Security Rule, and document any changes to them. | GV.PO-01 (partial); GV.PO-02 (partial) | 02 s14 (ADR index; design records, not policies) | none | procedural | none |
| [164.316(b)(1)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.316) | Documentation (standard) | Keep the policies and procedures in written form (electronic is allowed), and keep a written record of every action, activity, or assessment the Security Rule requires to be documented. | GV.PO-01 (related); ID.RA-07 (related) | 01 Design principles (P-5), 05 s4, 02 s14 | ir-identity-compromise.md, ir-ransomware.md (incident records) | partial | none |
| [164.316(b)(2)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.316) | Time limit (R) | Keep required documentation for 6 years from its creation or from the date it was last in effect, whichever is later. | GV.PO-01 (related) | 01 Assumptions (A-17 keeps log retention out of scope) | none | procedural | none |
| [164.316(b)(2)(ii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.316) | Availability (R) | Make the documentation available to the people responsible for carrying out the procedures it covers. | GV.PO-01 (partial) | None; a document-management practice | none | procedural | none |
| [164.316(b)(2)(iii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.316) | Updates (R) | Review the documentation periodically and update it when environmental or operational changes affect the security of ePHI. | GV.PO-02 (partial) | ADR-001 Revisit when (design-level triggers) | none | procedural | none |

## 7. CDE segment view (PCI DSS v4.0.1)

The same 30 PCI links, grouped by requirement. The status columns follow assumption A-16 (SAQ P2PE for registration desks, SAQ A for the e-commerce redirect, as the acquirer decides) and match `04-segmentation.md` section 7. Paraphrases are in the YAML's `metadata.pci_requirements`. Account data never enters the e-commerce channel's Contoso systems, so this view covers the terminal segment and the third-party providers.

| PCI DSS v4.0.1 | Requirement (paraphrase) | HIPAA row | Shared CSF 2.0 | Under the SAQ path (A-16) | Under a full assessment |
|---|---|---|---|---|---|
| 1.2.3 | Accurate network diagram of every connection to the CDE | 164.308(a)(1)(ii)(A) | ID.AM-03 | Performed anyway | Required |
| 1.2.4 | Accurate account data-flow diagram | 164.308(a)(1)(ii)(A) | ID.AM-03 | Performed anyway | Required |
| 1.3.1 | Only necessary inbound traffic into the CDE | 164.312(a)(1) | PR.IR-01 | Defense in depth | Required |
| 1.3.2 | Only necessary outbound traffic from the CDE | 164.312(a)(1) | PR.IR-01 | Defense in depth | Required |
| 1.3.3 | Controls between wireless networks and the CDE | 164.312(a)(1) | PR.IR-01 | Defense in depth | Required |
| 1.4.1 | Controls between trusted and untrusted networks | 164.312(a)(1) | PR.IR-01 | Defense in depth | Required |
| 1.5.1 | Controls on devices connected to both untrusted networks and the CDE | 164.312(a)(1) | PR.IR-01 | Defense in depth | Required |
| 7.2.1 | Defined access control model | 164.308(a)(4)(ii)(B) | PR.AA-05 | Not applicable by design | Required where access exists |
| 7.2.2 | Least-privilege access by job function | 164.308(a)(4)(ii)(B) | PR.AA-05 | Not applicable by design | Required where access exists |
| 7.2.4 | Account and privilege review at least every six months | 164.308(a)(4)(ii)(C) | PR.AA-05 | Not applicable by design | Required where access exists |
| 8.2.7 | Third-party remote access accounts enabled only when needed, and monitored | 164.312(d) | PR.AA-05, DE.CM-06 | Not applicable by design | Required where access exists |
| 8.4.1 | MFA for administrative non-console access into the CDE | 164.312(d) | PR.AA-03 | Not applicable by design | Required where access exists |
| 8.4.2 | MFA for all non-console access into the CDE | 164.312(d) | PR.AA-03 | Not applicable by design | Required where access exists |
| 8.4.3 | MFA for remote access that could reach the CDE | 164.312(d) | PR.AA-03 | Not applicable by design | Required where access exists |
| 8.5.1 | MFA systems resist replay and bypass and need every factor | 164.312(d) | PR.AA-03 | Not applicable by design | Required where access exists |
| 9.5.1 | Terminals protected from tampering and substitution | 164.310(a)(2)(ii) | PR.AA-06, DE.CM-02 | Required | Required |
| 9.5.1.1 | Up-to-date terminal list | 164.310(d)(2)(iii) | ID.AM-01 | Required | Required |
| 9.5.1.2 | Periodic terminal inspection | 164.310(a)(2)(ii) | DE.CM-02 | Required | Required |
| 9.5.1.2.1 | Inspection frequency from a targeted risk analysis | 164.310(a)(2)(ii) | ID.RA-04 | Performed anyway | Required |
| 9.5.1.3 | Tamper-awareness training for staff at terminals | 164.308(a)(5)(i) | PR.AT-01 | Required | Required |
| 10.2.1 | Audit logs enabled and active | 164.312(b) | PR.PS-04 | Defense in depth | Required |
| 11.4.5 | Segmentation penetration test every 12 months and after changes | 164.308(a)(8) | ID.IM-02 | Not on SAQ P2PE | Required when segmentation reduces scope |
| 12.3.1 | Targeted risk analysis where a requirement calls for one | 164.308(a)(1)(ii)(A) | ID.RA-04 | Performed anyway (with 9.5.1.2.1) | Required |
| 12.5.2 | Scope confirmed every 12 months and on significant change | 164.308(a)(1)(ii)(A) | ID.AM-03 | Performed anyway | Required |
| 12.8.1 | List of third-party service providers | 164.314(a)(1) | ID.AM-04 | Required | Required |
| 12.8.2 | Written agreements acknowledging security responsibility | 164.314(a)(1) | GV.SC-05 | Required | Required |
| 12.8.3 | Due diligence before engagement | 164.314(a)(1) | GV.SC-06 | Required | Required |
| 12.8.4 | Annual monitoring of provider compliance | 164.314(a)(1) | GV.SC-07 | Required | Required |
| 12.8.5 | Responsibility matrix per provider | 164.314(a)(1) | GV.SC-02 | Required | Required |
| 12.10.1 | Incident response plan ready to activate | 164.308(a)(6)(i) | ID.IM-04 | Required | Required |

Two things the table does not change:
- **The acquirer decides the validation path.** If it requires a full assessment, every defense-in-depth row becomes a validation requirement (ADR-007).
- **Billing records stay ePHI.** Payment records tied to a patient remain protected health information whatever their PCI scope (`04-segmentation.md` section 7).

## 8. Gaps, limits, and notes for the design set

- **Physical safeguards are mostly out of scope.** Seven rows are marked out-of-scope: six physical safeguards and the EHR's internal integrity mechanism (164.312(c)(2)). The one physical control the design includes, payment terminal inspection, protects terminals that hold no ePHI.
- **Recovery is unverified.** ADR-009 sets four requirements for `SVC-BACKUP`: immutable and offline copies, isolation from Tier 0 administrative reach, tested restores with evidence, and monitoring as Tier 0. The implementation (products, topology, recovery objectives, and restore order) is not designed, and no restore has been tested (A-19, RR-11). Requirements without a design support partial coverage at most, so the data backup plan, disaster recovery, and testing rows are partial. Data backup and storage before equipment moves is out of scope, because ADR-009 does not address it. A real program would design and restore-test recovery before anything else in this list.
- **Encryption at rest is required for every data-store class, with two gaps.** `02-reference-architecture.md` section 7 (Data at rest by data-store class) sets one requirement for each class: Microsoft 365 data, file services, managed endpoints, personal phones under app protection, the datacenter clinical stores, Azure workloads, managed file transfer, medical devices where the device supports it, and backup copies. Two gaps keep the 164.312(a)(2)(iv) row partial:
  - Medical devices that cannot encrypt the ePHI they store are owned, dated exceptions (RR-15). The design documents them as 45 CFR 164.306(d)(3) requires for an addressable specification; whether their compensating measures are adequate is a decision for Contoso's risk analysis.
  - Backup copy encryption depends on `SVC-BACKUP`, whose implementation is not designed (ADR-009).

  This matters beyond 164.312(a)(2)(iv). ePHI on a lost or stolen RR-15 device is unsecured PHI, and meeting a requirement elsewhere is not, on its own, a finding that ePHI is secured under the HHS guidance (`notification-clocks.md` section 2.2).
- **Automatic logoff is partial.** Sign-in frequency caps how long a session lasts, but it is not an inactivity timeout (`02-reference-architecture.md` section 9). The EHR's own inactivity timeout covers EHR sessions, and Microsoft 365 idle session timeout covers Microsoft 365 web apps on unmanaged browsers, within the limits that section states. On shared clinical workstations, a locked session, including one left behind by Switch User, is signed out after an idle period Contoso sets (ADR-003, Consequences). Inactivity controls for idle sessions that are not locked, for other clinical applications, and for desktop and mobile clients on other devices are not specified.
- **Vendor engineers are not Contoso workforce.** Under 45 CFR 160.103, workforce means people whose conduct is under the direct control of the covered entity or business associate they work for. Vendor engineers work for business associates, so they are their employers' workforce, not Contoso's. The crosswalk and the architecture (`03-identity-and-access.md` section 9, `02-reference-architecture.md` section 12) therefore map the vendor model to the business associate provisions, 164.308(b)(1) and 164.314(a)(1), and the recorded broker sessions to audit controls (164.312(b)). No vendor element is mapped to the workforce specifications, including authorization and/or supervision (164.308(a)(3)(ii)(A)).
- **EHR internals stay out of scope.** Integrity mechanisms inside the EHR (164.312(c)(2)) and minimum-necessary role design (Privacy Rule consistency in 164.308(a)(4)(i)) are EHR internals, excluded in 01. Per-record access monitoring is residual risk RR-01.
- **Organizational work no architecture does.** Sanctions, the security official, training, business associate agreements, evaluation, and documentation retention account for most of the 13 procedural rows.
- **Detection gaps that touch these rows.** No rule in the detection pack examines firewall, NAC, IoMT sensor, broker session, or EHR audit logs yet, so the activity review and audit control rows rest partly on manual review (`coverage-map.md` section 4). Managed identity sign-ins, which `03-identity-and-access.md` section 6 says need monitoring, have no rule yet (`coverage-map.md` section 3, item 11). The help-desk takeover rule (SN-01) lacks its banking-change link because payer, payroll, and ERP logs are not in Sentinel (A-17). DX-07's logon and process signals read DeviceLogonEvents and DeviceProcessEvents, which Microsoft documents as populated by Defender for Endpoint. The design does not yet state Defender for Endpoint on the `IDS-SYNC` servers (`threat-model.md` TM-A4 and section 9 item 8). Until it does, DX-07 contributes only its Defender for Identity sync-identity alert signal to the activity review, audit control, and authentication rows, and its link on the log-in monitoring row (164.308(a)(5)(ii)(C)), which rests on the logon signal, has no data (`coverage-map.md` section 3, item 9). SN-06 and SN-07 support the emergency access procedure row (164.312(a)(2)(ii); `coverage-map.md` section 3, item 19); purple-team exercises PX-19 and PX-20 (`threat-models/zero-trust-healthcare/purple-team-plan.md`) are their route to lab-tested status, and neither has been run.
- **Proposed rule not reflected.** The HIPAA Security Rule NPRM (90 FR 898, January 6, 2025) proposes new and restructured requirements, but it is not final. This crosswalk does not anticipate it. The companion research note covers what it proposes.

## 9. Machine-readable files and validation

| File | Purpose |
|---|---|
| `crosswalk.yaml` | The crosswalk. Holds metadata (frameworks, definitions, the HITRUST decision, source list, PCI requirement catalog, CSF outcome text), then one entry per HIPAA provision with CSF targets, PCI targets, architecture references, detection links (file and purpose), and notes. |
| `crosswalk.schema.json` | JSON Schema (draft-07) for the YAML structure. It lists all 106 CSF 2.0 subcategory identifiers and accepts no others. |
| `validate-crosswalk.ps1` | Validator for Windows PowerShell 5.1 with no modules. |

**Format.** The YAML uses a strict subset so the validator can read it without a YAML module:
- 2-space indentation, and block mappings and lists only.
- Every string value in double quotes. The only bare values are `true`, `false`, `null`, and `[]`.
- Flow lists contain only quoted strings, and comments go on their own lines.
- ASCII only.

Editors that read the `yaml-language-server` comment on the first line can validate against the schema as well.

**Running the validator.**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\validate-crosswalk.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\validate-crosswalk.ps1 -Json
```

**What it checks, in order:**
1. **Text.** Em dashes are failures; en dashes, non-ASCII characters, and open verification markers are warnings.
2. **Parse.** The YAML must parse under the subset.
3. **Structure.** The YAML is checked against the schema.
4. **Content.**
   - All 65 HIPAA standards and implementation specifications appear exactly once, with the right titles and R/A designations.
   - Applicability and coverage agree.
   - CSF and PCI identifiers come from the catalogs, and PCI targets appear only on Z-CDE rows.
   - Every citation resolves to a listed source and names the identifier it cites.
5. **Cross-file references.** Component, zone, policy, flow, and residual-risk IDs exist in the architecture; every referenced file and section heading exists; and every linked detection file exists in the detection pack.
6. **Agreement with this file.** Each table row here matches the YAML on CSF targets and relationships, coverage, and PCI targets.

**Exit codes.** 0 means no failures, 1 means one or more failures, and 2 means the validator could not run. Paths to companion folders are set in `metadata.paths`, so a different repository layout means editing that block or running with `-SkipFileChecks`.

## Sources

| Title | Publisher | URL | Date checked | Quality |
|---|---|---|---|---|
| 45 CFR 164.308, 164.310, 164.312, 164.314, 164.316 | Office of the Federal Register, eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C | 2026-10-04 | Primary |
| 45 CFR 164.304 and 164.306 (definitions; general rules, addressable specifications) | Office of the Federal Register, eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.306 | 2026-10-04 | Primary |
| Appendix A to Subpart C of Part 164, Security Standards: Matrix | Office of the Federal Register, eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C | 2026-10-04 | Primary |
| 45 CFR 160.103 (workforce, subcontractor, business associate) | Office of the Federal Register, eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-160/subpart-A/section-160.103 | 2026-10-04 | Primary |
| 45 CFR 164.504(e)(3), Other arrangements | Office of the Federal Register, eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E/section-164.504 | 2026-10-04 | Primary |
| The NIST Cybersecurity Framework (CSF) 2.0, NIST CSWP 29 | NIST | https://doi.org/10.6028/NIST.CSWP.29 | 2026-10-04 | Primary |
| PCI DSS v4.0.1 (document library; automated retrieval returned HTTP 403) | PCI Security Standards Council | https://www.pcisecuritystandards.org/document_library/ | 2026-10-04 | Primary |
| Just Published: PCI DSS v4.0.1 (no added or deleted requirements) | PCI Security Standards Council | https://blog.pcisecuritystandards.org/just-published-pci-dss-v4-0-1 | 2026-10-04 | Primary |
| Summary of Changes from PCI DSS Version 3.2.1 to 4.0, Revision 1 (May 2022), which describes changes from the superseded v3.2.1 | PCI Security Standards Council | https://listings.pcisecuritystandards.org/documents/PCI-DSS-v3-2-1-to-v4-0-Summary-of-Changes-r1.pdf | 2026-10-04 | Primary |
| Summary of Changes from PCI DSS Version 4.0 to 4.0.1, Revision 1 (August 2024), published in the PCI SSC document library. PCI SSC's own hosts did not return it on 2026-10-04, so the copy read is PCI SSC's PDF as posted at commerce.uwo.ca/documentation/PCI-DSS-v4-0-to-v4-0-1-Summary-of-Changes-r1-1.pdf | PCI Security Standards Council | https://www.pcisecuritystandards.org/document_library/ | 2026-10-04 | Primary |
| Self-Assessment Questionnaire P2PE for PCI DSS v4.0 (April 2022), superseded by the v4.0.1 SAQs | PCI Security Standards Council | https://listings.pcisecuritystandards.org/documents/PCI-DSS-v4-0-SAQ-P2PE.pdf | 2026-10-04 | Primary |
| Self-Assessment Questionnaire A-EP for PCI DSS v4.0, superseded by the v4.0.1 SAQs | PCI Security Standards Council | https://listings.pcisecuritystandards.org/documents/PCI-DSS-v4-0-SAQ-A-EP.pdf | 2026-10-03 | Primary |
| HITRUST CSF License Agreement (HITRUST CSF Version 11.9, effective September 24, 2026) | HITRUST Alliance | https://hitrustalliance.net/hubfs/Agreements/HITRUST%20CSF%20License%20Agreement.pdf | 2026-10-04 | Primary |
| HITRUST Terms of Use for Site and Services (last modified January 8, 2024) | HITRUST Alliance | https://hitrustalliance.net/terms-of-use | 2026-10-04 | Primary |
| Health Industry Cybersecurity Practices: Managing Threats and Protecting Patients, 2023 Edition, main document (voluntary guidelines under section 405(d) of the Cybersecurity Act of 2015) | HHS 405(d) Program, with the Health Sector Coordinating Council | https://hhscyber.hhs.gov/Documents/HICP/HICP-Main-508.pdf | 2026-10-04 | Primary |
| HPH Cybersecurity Performance Goals (voluntary; essential and enhanced goals) | HHS Cyber Gateway | https://hhscyber.hhs.gov/cybersecurity-performance-goals.html | 2026-10-04 | Primary |
| Aligning HICP to the HPH Cybersecurity Performance Goals (maps each goal to HICP sub-practices) | HHS 405(d) Program | https://hhscyber.hhs.gov/Documents/Posters_and_awareness/HHS-cpg-highlights-2024_R.pdf | 2026-10-04 | Primary |
| HIPAA Security Rule To Strengthen the Cybersecurity of Electronic Protected Health Information (proposed rule), 90 FR 898 | Federal Register | https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information | 2026-10-04 | Primary |
| Unified Agenda 2026, RIN 0945-AA22 (Long-Term Actions; final action 07/00/2027) | reginfo.gov | https://www.reginfo.gov/public/do/eAgendaViewRule?pubId=202510&RIN=0945-AA22 | 2026-10-07 | Primary |
| DeviceLogonEvents table in the advanced hunting schema (states that the table is populated by records from Microsoft Defender for Endpoint; section 8, DX-07 gap) | Microsoft Learn | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table | 2026-10-04 | Primary |
| DeviceProcessEvents table in the advanced hunting schema (states that the table is populated by records from Microsoft Defender for Endpoint; section 8, DX-07 gap) | Microsoft Learn | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table | 2026-10-04 | Primary |
