# Contoso Regional Health (fictional): reference risk register

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

This register is a reference example for Contoso Regional Health (fictional). It holds twelve risks, each tied to:
- the attack paths in `threat-models/zero-trust-healthcare/attack-paths.md` (AP-1 to AP-7) where one applies, or for R-12 the trust boundaries in `threat-model.md`,
- the residual risks the architecture names in `02-reference-architecture.md` section 13 (RR-01 to RR-16),
- the controls in the reference design.

The same data is in `risk-register.csv`.

## 1. Purpose and limits

- **What it shows.** A risk register format and scoring method, applied to a fictional design. It is not Contoso's risk analysis under 45 CFR 164.308(a)(1)(ii)(A), and it is not an assessment of any real organization.
- **Scores are judgments.** Every likelihood and impact score is an illustrative judgment for a fictional scenario. No measured data from any organization sits behind them.
- **Inherent versus residual.**
  - Inherent scores assume none of the reference design's controls are in place, a state close to the assumed starting point in `05-ztmm-maturity-roadmap.md` section 1.
  - Residual scores assume the 36-month target state with every control working as designed. Nothing in this design set has been tested, so residual scores describe intent, not evidence.

## 2. Scoring method

Risk score = likelihood x impact, each on a 1 to 5 scale. This is a standardized method of the kind CSF 2.0 GV.RM-06 describes. Inherent risk is scored first, and the risk response is chosen from it. In CSF 2.0 terms, ID.RA-05 uses threats, vulnerabilities, likelihoods, and impacts to understand inherent risk and inform risk response prioritization, and ID.RA-06 covers choosing, prioritizing, planning, tracking, and communicating risk responses.

**Likelihood, over the next 12 months**

| Score | Label | Meaning |
|---|---|---|
| 1 | Rare | Not expected; would need an unusual combination of conditions |
| 2 | Unlikely | Could occur, but not expected in a given year |
| 3 | Possible | Could occur in a given year; organizations like Contoso report it |
| 4 | Likely | Expected in a given year without further controls |
| 5 | Almost certain | Expected to occur more than once in a year |

**Impact.** Use the highest dimension that applies.

| Score | Label | Patient care | Data | Operations | Regulatory |
|---|---|---|---|---|---|
| 1 | Minimal | None | None exposed | Minutes of disruption to a non-clinical service | None |
| 2 | Minor | None | Limited non-sensitive data | A non-clinical service down for hours | Internal record only |
| 3 | Moderate | Workarounds needed, no harm expected | ePHI of fewer than 500 individuals, or a small number of payment cards | A clinical service degraded for hours on downtime procedures | Breach notification to individuals; annual log to HHS |
| 4 | Major | Care delayed at one site | ePHI of 500 or more individuals, or a card data compromise | A clinical service down at a hospital for more than a shift | Contemporaneous notice to HHS, possible media notice, card brand investigation |
| 5 | Severe | Risk of patient harm | Enterprise-wide data exposure | System-wide clinical disruption, or full identity compromise (Tier 0) | Multiple regulators and sustained enforcement exposure |

The breach-notification thresholds behind impact levels 3 and 4 are cited in `notification-clocks.md`.

**Rating bands**

| Score | Rating | Review cadence |
|---|---|---|
| 1 to 4 | Low | Annual |
| 5 to 9 | Medium | Semiannual |
| 10 to 16 | High | Quarterly |
| 20 to 25 | Critical | Monthly |

No product of two 1-to-5 scores falls between 17 and 19, so the bands leave no gaps.

**Treatment options** follow the response options in CSF 2.0 (NIST CSWP 29, section 5): mitigate, transfer, avoid, or accept. Every risk has a named owner (a fictional role), and its review date follows the cadence for its residual rating.

## 3. Register

| ID | Risk | Attack paths | Inherent (likelihood x impact) | Residual (likelihood x impact) | Treatment | Owner | Review |
|---|---|---|---|---|---|---|---|
| R-01 | Session theft against cloud and EHR browser access | AP-1 | 20 Critical (5 x 4) | 16 High (4 x 4) | Mitigate | Identity Engineering lead | 2027-01-15 |
| R-02 | Help-desk MFA enrollment fraud followed by payment diversion | AP-2 | 16 High (4 x 4) | 12 High (3 x 4) | Mitigate (technical and process) | Service Desk Manager | 2027-01-15 |
| R-03 | Ransomware that stops clinical systems | AP-4 | 25 Critical (5 x 5) | 20 Critical (4 x 5) | Mitigate; recovery requirements set (ADR-009); recovery design and restore tests required | CISO | 2026-11-15 |
| R-04 | Compromised partner tenant reaches the EHR or an imaging modality | AP-3 | 20 Critical (4 x 5) | 15 High (3 x 5) | Mitigate; transfer part through contracts | Director of Clinical Applications | 2027-01-15 |
| R-05 | Tier 0 compromise through the hybrid identity boundary | AP-5 | 20 Critical (4 x 5) | 15 High (3 x 5) | Mitigate | CISO | 2027-01-15 |
| R-06 | Illicit consent or workload identity abuse reaches ePHI in Microsoft 365 | AP-6 | 16 High (4 x 4) | 12 High (3 x 4) | Mitigate | Identity Engineering lead | 2027-01-15 |
| R-07 | Medical device compromise with availability and data impact | AP-7 | 20 Critical (4 x 5) | 12 High (3 x 4) | Mitigate; accept the residual with clinical engineering sign-off | Director of Clinical Engineering | 2027-01-15 |
| R-08 | Credential abuse through legacy Kerberos and NTLM paths | AP-4, AP-5 | 16 High (4 x 4) | 8 Medium (2 x 4) | Mitigate; avoid over time by retiring legacy applications | Director of Clinical Applications | 2027-04-15 |
| R-09 | Insider misuse of legitimate EHR access | none (RR-01) | 12 High (4 x 3) | 12 High (4 x 3) | Mitigate outside this design (EHR privacy monitoring) | Privacy Officer | 2027-01-15 |
| R-10 | Payment terminal tampering or substitution | none (CDE) | 12 High (3 x 4) | 6 Medium (2 x 3) | Mitigate; transfer part to the P2PE provider | VP Revenue Cycle | 2027-04-15 |
| R-11 | Upstream supplier compromise | AP-3 | 15 High (3 x 5) | 12 High (3 x 4) | Transfer through contracts; mitigate; accept the residual | Compliance Officer | 2027-01-15 |
| R-12 | Tampering with the patient portal payment redirect | none (TB-1, TB-8) | 12 High (3 x 4) | 8 Medium (2 x 4) | Mitigate | VP Revenue Cycle | 2027-04-15 |

**Distribution.** Inherent: 5 Critical, 7 High. Residual: 1 Critical, 8 High, 3 Medium.

**What the scores say.**
- **Likelihood falls more than impact.** The design mostly cuts likelihood and blast radius; it lowers consequence much less.
- **Recovery is the biggest impact lever: its requirements are set, and its implementation is not designed.** ADR-009 sets four requirements for the copies Contoso restores from, but recovery stays unverified until a design meets them and restore tests produce evidence (A-19, RR-11). That is why ransomware (R-03) stays Critical after every designed control.
  - Passing restore tests would let R-03's impact fall one band at most (`threat-model.md` TM-A1).
  - They would not lower R-05's impact: a Tier 0 compromise exposes every ePHI store whether or not restores succeed (RR-07).
- **Two risks barely move.**
  - Insider misuse of legitimate EHR access (R-09) keeps the same score, because the design does not address it.
  - Supplier compromise (R-11) drops only from 15 to 12 and stays High, because Contoso cannot enforce controls inside a supplier.

## 4. Risk detail

Every rule in the companion detection pack is an untested template, never run against data, so a rule named as a control shows intended detection, not tested coverage.

| ID | Assets | Threat | Vulnerability | Key controls in the design and the detection pack | Residual risks |
|---|---|---|---|---|---|
| R-01 | `IDS-ENTRA`, `PA-IDENTITY`, `RES-EHR`, `RES-M365`, `PEP-SESSION-PROXY` | Adversary-in-the-middle phishing and stolen session cookies replayed to read ePHI | Phishable MFA at the start. The third-party EHR browser path is not enforced by continuous access evaluation, so a stolen session lasts until the EHR's own timeout. | Phishing-resistant MFA by persona (ADR-003; CA-03, CA-07, CA-11); browser-only session controls on unmanaged devices (CA-10); risk-based policies (CA-17, CA-18); token protection on Windows (CA-21); short EHR sessions (02 section 9); detections DX-03, SN-04, and DX-04 | RR-03 |
| R-02 | `IDS-ENTRA`, `IGA-ENTRA`, `IDS-SOR`, `RES-M365` | The help desk is tricked into registering an attacker's method; the mailbox is then used to divert payments | Help-desk checks that rely on knowledge of identifiers; interim methods accepted during rollout | In-person or sponsor-verified identity proofing before any method registration (03 section 2); Temporary Access Pass only for registering a phishing-resistant method (CA-19); SMS and voice disabled; detections SN-01 and DX-04; callback verification and dual approval for bank changes (process) (note 1) | RR-01 |
| R-03 | `RES-EHR`, `RES-PACS`, `RES-LIS`, `RES-PHARM`, `RES-FILES`, `PEP-HOST`, `SVC-BACKUP` | Ransomware moves from a phished workstation, impairs defenses, destroys recovery points, and encrypts systems | Flat clinical networks and peer-to-peer workstation traffic at the start; recovery requirements set (ADR-009), implementation not designed, no restore tested | Host east-west blocking (`PEP-HOST`); micro-segmentation (`PEP-NET-ZONE`); application control, EDR, and attack disruption (`PIP-EDR`, `PIP-XDR`); tiering and PAWs (ADR-004); local-first failure modes (ADR-008); detections DX-01, DX-02, DX-08, DX-09, SN-05, SG-01, SG-02, and SG-03; recovery requirements for `SVC-BACKUP` (ADR-009 decisions 1 to 4; not designed) | RR-02, RR-11 |
| R-04 | `PEP-VENDOR-BROKER`, `IDS-PARTNER`, `IGA-ENTRA`, `RES-EHR`, `RES-IOMT`, `EXT-VENDOR-EHR`, `EXT-VENDOR-BIOMED`, `EXT-RCM-BA` | A partner identity trusted for MFA claims is used, through an approved session, to reach the EHR or, through a biomedical vendor's session (F-07), an imaging modality that holds ePHI | Inbound MFA trust; vendor VPN with standing access at the start | Broker-only, recorded vendor sessions (ADR-002); PIM for Groups activation with approval (F-06, F-07); CA-13, CA-14, CA-16; narrow targets through `PEP-NET-ZONE`; detection SN-02 (note 2) | RR-04, RR-06, RR-12, RR-14 |
| R-05 | `IDS-AD`, `IDS-ENTRA`, `IDS-SYNC`, `PIP-PKI` | Directory credentials harvested, then the synchronization boundary abused to control both planes | Tier 0 concentration; standing and synchronized privileged accounts at the start; RR-16, standing Tier 0 access that no approval gates (note 3) | Cloud-only administrator accounts; eligible-only PIM with approved Tier 0 activation; PAWs (ADR-004; CA-03 to CA-06); `grp-ca-emergency-access` as a role-assignable Tier 0 object with no owners (ADR-004 decision 9); emergency access passkeys in split custody at two hospitals, use only from a designated PAW, and 90-day validation of the group (03 section 5); Defender for Identity (`PIP-ID-RISK`); detections DX-01, DX-05, DX-06, DX-07, SN-02, SN-05, SN-06, SN-07, SG-04, and SG-06; recovery copies outside production Tier 0's reach and monitored as Tier 0 (ADR-009 decisions 2 and 4; not designed) (note 3) | RR-07, RR-09, RR-11, RR-16 |
| R-06 | `IDS-ENTRA`, `RES-M365`, `RES-AZ-WORKLOADS` | An application token obtained through illicit consent or a compromised app registration | Consent paths that bypass MFA; workload identity coverage gaps; RR-16, standing Tier 0 access held by Tier 0 workload identities (note 4) | Admin consent workflow and restricted user consent (03 section 6); certificate credentials (WP-3.6); CA-22 where licensed; no application holds the authentication-method permissions by default, and a grant of a Tier 0 permission needs a Tier 0 administrator or a Tier 0 workload identity, is made against a change record, and raises an alert (03 section 4); detection SN-03 (note 4) | RR-16 (Tier 0 workload identities); workload identity coverage gap (03 section 6) |
| R-07 | `RES-IOMT`, `PE-NETWORK`, `PEP-NET-ACCESS`, `PIP-IOMT-SENSOR`, `PIP-ASSET-INV`, `RES-PACS` | A compromised or rogue device uses its one allowed flow; or a device that cannot encrypt the ePHI it stores is lost or stolen | Unpatchable devices; MAC-based admission; one flat biomedical network at the start; no passive sensor at the 22 clinics; device storage that cannot be encrypted | Passive discovery and one inventory; device-class segments with no lateral traffic (ADR-006); NAC profiling on MAB ports; clinically gated containment (04 section 3); encryption of stored ePHI where supported (ADR-006 decision 6); for devices that cannot encrypt, physical safeguards, location records, and media sanitization (note 5) | RR-04, RR-05, RR-14, RR-15 |
| R-08 | `RES-LEGACY`, `PEP-ENCLAVE-GW`, `IDS-AD`, `PEP-ZTNA-CONNECTOR` | Kerberoasting, NTLM relay, or abuse of domain controllers published for remote single sign-on | Legacy NTLM dependence; fewer signals on the local plane | Gateway-enforced enclave (ADR-005); NTLM audit then restriction with dated exceptions; AES-only Kerberos and group managed service accounts; limited domain controller segment; Defender for Identity; Kerberoasting detections DX-05 and SG-05 | RR-02, RR-09 |
| R-09 | `RES-EHR`, `PEP-SSO-APP`, `PIP-SIEM` | An authorized user browses or bulk-pulls records without a care relationship | Session-level decisions only; EHR privacy monitoring out of scope | EHR audit logs in `PIP-SIEM`; minimum-necessary EHR roles and a privacy monitoring program (both outside this design); sanction policy | RR-01 |
| R-10 | `RES-POI`, `PEP-CDE-BOUNDARY`, `EXT-P2PE`, `PIP-ASSET-INV` | A terminal is tampered with or swapped to capture card data | Many terminals at registration desks across 3 hospitals and 22 clinics; terminals integrated with workstations at the start | PCI-listed P2PE terminals that encrypt at the terminal (ADR-007); terminal list, inspection at a risk-based frequency, and staff training; `PEP-CDE-BOUNDARY` isolation | RR-12 |
| R-11 | `EXT-VENDOR-EHR`, `EXT-VENDOR-BIOMED`, `EXT-PSP`, `EXT-P2PE`, `EXT-TELEHEALTH`, `EXT-RCM-BA` | A supplier's environment or software is compromised | Contoso cannot enforce controls inside a supplier | Business associate agreements with incident-reporting terms; PCI DSS 12.8 provider management; narrow integrations; redirect instead of embedded payment fields (ADR-007); per-manufacturer egress allow-lists for device connectivity (ADR-006) | RR-12 |
| R-12 | `RES-PORTAL`, `PEP-WAF`, `EXT-PSP` | The portal page that starts the payment redirect is altered, or a counterfeit page is substituted for the redirect target, so patients enter card data on a page the attacker controls | The portal sets the redirect target, so whoever can change that page decides where patients enter card data | Full URL redirect with no embedded payment fields (ADR-007, F-11); the redirecting page behind `PEP-WAF`, with its content change-monitored (ADR-007, 04 section 7); an incident response plan that includes card brand and acquirer notification | RR-12 (provider side) |

**Notes to the risk detail table.**

1. **R-02.** Detections SN-01 and DX-04 lack the banking-change link, because payer, payroll, and ERP logs are not in Sentinel (A-17).
2. **R-04.** PIM for Groups activation is approved by the Contoso system owner (F-06) or, for each biomedical vendor's own session group, by clinical engineering (F-07). For biomedical vendors, the narrow targets through `PEP-NET-ZONE` are limited to that vendor's devices in `Z-IOMT-IMAGING`. SN-02 is the detection for activations of any vendor session group outside expected hours.
3. **R-05.** RR-16: see the paragraph on RR-16 below. Tier 0 activation is approved by one of two named approvers. Defender for Identity is on domain controllers, AD CS, and Entra Connect servers. DX-07's logon and process signals need Defender for Endpoint on the `IDS-SYNC` servers, which the design does not yet state (`threat-model.md` TM-A4), so until it does DX-07 rests on its Defender for Identity alert signal.
4. **R-06.** RR-16: see the paragraph on RR-16 below. SN-03 watches consents and application and service principal credentials; `coverage-map.md` section 3, item 11 records what it scores High and that managed identity sign-in monitoring is not built.
5. **R-07.** Passive discovery is at the three hospital cores, and clinic devices are classified through NAC profiling and clinical engineering records. Encryption of stored ePHI: where the device supports it, and in new purchase contracts (ADR-006 decision 6). Media sanitization comes before disposal, re-use, or return to the manufacturer.

R-07 also carries RR-15, medical devices that cannot encrypt the ePHI they store. Its loss or theft scenario is a possible breach of unsecured PHI (`notification-clocks.md` section 2.2), and it is judged at or below R-07's inherent and residual scores, so it is not scored as a separate risk.

R-05 and R-06 both carry RR-16, standing Tier 0 access that no approval gates; where no approval gates the change, the alert is the only control (`02-reference-architecture.md` section 13; ADR-004 decisions 6 and 9).
- **R-05 carries both kinds of identity.** The two emergency access accounts, and Tier 0 workload identities that hold a permission for the change, can change `grp-ca-emergency-access` or an emergency account's credentials without approval. The threat model places these unapproved changes at AP-5 steps 8a and 8b.
- **R-06 carries the workload identity branch.** Which applications and managed identities are Tier 0 workload identities, and the permissions the design checks for, are in `03-identity-and-access.md` sections 4 and 6. An AP-6 compromise of a Tier 0 workload identity, for example a credential added at step 3, yields that standing access. The consequence is a Tier 0 compromise, the impact R-05 already scores, so it is not scored again under R-06 and does not raise R-06's scores, which follow AP-6.

Compliance anchors per risk (HIPAA citations, CSF 2.0 subcategories, and PCI DSS requirements) are in the `hipaa`, `csf`, and `pci_dss` columns of `risk-register.csv`. All of them also appear in `crosswalk.yaml` except two CSF 2.0 subcategories the crosswalk does not use: DE.CM-01 (R-07) and PR.PS-02 (R-08).

## 5. Links to the threat model

- **Scores against the threat model's ratings.** `attack-paths.md` sets each path's likelihood band partly by how much of the path the architecture already blocks, so its bands are comparable to residual scores.
  - **Paths that map one to one (R-01 to R-07).** Residual scores follow those bands: likelihood 4 for High, and 3 for Medium or Medium to High; impact 5 for Critical or Very High, and 4 for High.
  - **The one stated difference.** R-02's residual assumes the phishing-resistant rollout has finished, while `attack-paths.md` rates AP-2 High likelihood during rollout.
  - **Scored separately.** R-08 and R-11 draw on parts of paths. R-09, R-10, and R-12 have no attack path; R-12 comes from the threat model's trust boundaries TB-1 and TB-8.
- **Chaining.** AP-1, AP-2, AP-3, and AP-7 are footholds that often come before AP-4 and AP-5. So reducing R-01, R-02, R-04, and R-07 also lowers the likelihood of R-03 and R-05.
- **Architecture gaps.** The eight observations in `threat-model.md` section 9 line up with this register: recovery (R-03; requirements set in ADR-009, implementation not designed), the EHR browser token path (R-01), help-desk identity proofing (R-02), managed identities outside CA-22 (R-06), domain controllers published for remote Kerberos (R-08 and R-05), the emergency access exclusion group (R-05), application permissions that can issue a Temporary Access Pass (R-05), and endpoint telemetry from Tier 0 servers (R-05, AP-5). ADR-004 places the group and those applications in Tier 0 (decisions 9 and 1) and records the standing paths that no approval gates as RR-16, which R-05 carries; R-06 carries its workload identity branch.
  - **Item 8 is open.** The design does not yet state Defender for Endpoint on any `Z-T0` server (`threat-model.md` TM-A4). So DX-07's logon and process signals, which R-05 lists among its controls, have no data unless the design adds Defender for Endpoint to the `IDS-SYNC` servers. R-05's scores follow AP-5's rating, which `attack-paths.md` gives with that gap not shown closed (AP-5, key breaker).
- **Detections.** The controls of R-01 to R-06 and R-08 name rules from the companion detection pack (`detections/zero-trust-healthcare/`, listed in its `detections-index.md`). `coverage-map.md` section 2 maps each rule to these risk IDs, and its sections 3 and 4 list what the pack cannot see yet. R-07, R-09, R-10, R-11, and R-12 have no rule in the pack.

## Sources

| Title | Publisher | URL | Date checked | Quality |
|---|---|---|---|---|
| The NIST Cybersecurity Framework (CSF) 2.0, NIST CSWP 29 (section 5 risk response options; GV.RM-06, ID.RA-05, ID.RA-06) | NIST | https://doi.org/10.6028/NIST.CSWP.29 | 2026-10-04 | primary |
| 45 CFR 164.308(a)(1)(ii)(A) and (B), risk analysis and risk management | Office of the Federal Register, eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308 | 2026-10-04 | primary |
| 45 CFR 164.404, 164.406, 164.408 (notification thresholds used in the impact scale) | Office of the Federal Register, eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D | 2026-10-04 | primary |
| DeviceLogonEvents table in the advanced hunting schema (states that the table is populated by records from Microsoft Defender for Endpoint; R-05, DX-07) | Microsoft Learn | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table | 2026-10-04 | primary |
| DeviceProcessEvents table in the advanced hunting schema (states that the table is populated by records from Microsoft Defender for Endpoint; R-05, DX-07) | Microsoft Learn | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table | 2026-10-04 | primary |

Companion files: `threat-models/zero-trust-healthcare/attack-paths.md` (AP-1 to AP-7), `threat-models/zero-trust-healthcare/threat-model.md` (trust boundaries TB-1 and TB-8, for R-12), `architecture/zero-trust-healthcare/02-reference-architecture.md` (component glossary; residual risks RR-01 to RR-16), `architecture/zero-trust-healthcare/adr/ADR-009-recovery-requirements.md` (recovery requirements), `detections/zero-trust-healthcare/coverage-map.md` (rule-to-risk links), `crosswalk.yaml`, and `notification-clocks.md`.
