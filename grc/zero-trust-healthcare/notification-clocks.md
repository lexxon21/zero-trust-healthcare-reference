# Contoso Regional Health (fictional): breach and incident notification clocks

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

This matrix lists the notification clocks that apply to Contoso Regional Health (fictional) when an incident may involve protected health information (PHI) or payment card data.
- **What it supports.** The companion incident response playbooks for identity compromise and ransomware and the ransomware tabletop exercise kit (`ir-identity-compromise.md`, `ir-ransomware.md`, and `tabletop-ransomware.md` in `detections/zero-trust-healthcare/playbooks/`), and the crosswalk rows for 45 CFR 164.308(a)(6) and 164.314(a)(2)(i) in `crosswalk.md`.
- **Sources.** Every clock cites its primary source, and all sources were checked on 2026-10-04 or 2026-10-07. Regulatory text was read through the eCFR versioner API (point in time 2026-09-30).

## 1. How to use this matrix

- **Scope.** Contoso is a HIPAA covered entity and a merchant that accepts payment cards (`01-scenario-and-assumptions.md`). Two families of clocks apply:
  - the HIPAA Breach Notification Rule for PHI (sections 2 and 3);
  - card brand and acquirer rules for card data (section 4).

  Section 5 covers regimes that were reviewed but are proposed, not final, or not mapped.
- **Each regime starts its own clock.** The triggers differ:
  - HIPAA counts from discovery as 45 CFR 164.404(a)(2) defines it.
  - Visa counts from evidence that raises a reasonable suspicion of compromise.
  - American Express: see the policy cited in section 4. This matrix does not paraphrase it.
  - Discover's page says "within 48 hours of incident".

  Run every clock from one incident timeline.
- **Status labels.**
  - In force: a regulation that applies now.
  - Contract: a term of an agreement Contoso signs, such as the merchant agreement or a business associate agreement.
  - Card brand rule: a brand's own rule, which reaches Contoso through its merchant agreement.
  - Not in force: a proposed rule.
  - Not final: a rule still in rulemaking.
- **Counsel decides.** This matrix supports the playbooks. It does not decide whether an incident is reportable, and contracts can set shorter clocks than the ones listed.
- **Units.** Calendar days, business days, and hours are as each source states them.

**Clock summary**

| Event | Recipient | Limit | Status | Detail |
|---|---|---|---|---|
| Breach of unsecured PHI | Each affected individual | Without unreasonable delay, and no later than 60 calendar days after discovery | In force | 2.3 |
| Breach of unsecured PHI involving more than 500 residents of a State or jurisdiction | Prominent media outlets serving it | Same as individual notice | In force | 2.3 |
| Breach of unsecured PHI involving 500 or more individuals | HHS | At the same time as individual notice | In force | 2.3 |
| Breach of unsecured PHI involving fewer than 500 individuals | HHS | No later than 60 days after the end of the calendar year of discovery | In force | 2.3 |
| Breach of unsecured PHI at a business associate | Contoso | Without unreasonable delay, and no later than 60 calendar days after the business associate's discovery | In force | 3 |
| Security incident at a business associate | Contoso | As the business associate agreement sets | In force (the contract term is required; the clock is not) | 3 |
| Suspected or confirmed card data compromise | Acquirer | Per the merchant agreement; Visa also requires immediate notice | Contract | 4 |
| Suspected or confirmed card data compromise | Visa | 3 calendar days from discovery | Card brand rule | 4 |
| Card data compromise | American Express | Not paraphrased; see the policy cited in section 4 | Card brand rule | 4 |
| Card data security breach | Discover | 48 hours | Card brand rule (undated web page) | 4 |
| Card data compromise | Acquirer, for Mastercard | Under the merchant agreement and Mastercard's rules; this matrix gives no time limit | Contract; card brand rule (not read) | 4 |
| Contingency plan activation at a business associate | Contoso | 24 hours | Not in force (proposed rule) | 5.1 |
| Change in a workforce member's access to another regulated entity's ePHI | That covered entity or business associate | 24 hours | Not in force (proposed rule) | 5.1 |
| Covered cyber incident; ransom payment (CIRCIA) | CISA (Cybersecurity and Infrastructure Security Agency) | 72 hours; 24 hours | Not final, no duty yet | 5.2 |

## 2. HIPAA Breach Notification Rule (45 CFR 164.400 to 164.414)

### 2.1 Reportable or not

- **Breach.** 45 CFR 164.402 defines a breach as acquisition, access, use, or disclosure of PHI that the Privacy Rule (Subpart E) does not permit and that compromises the security or privacy of the PHI. Three narrow exclusions apply:
  - good-faith, unintentional access by a workforce member acting within the scope of authority;
  - inadvertent disclosure between people authorized to access PHI at the same entity or organized health care arrangement;
  - disclosure to a recipient who could not reasonably have retained the information.
- **Presumption.** An impermissible use or disclosure is presumed to be a breach unless the covered entity or business associate demonstrates a low probability that the PHI has been compromised. That demonstration needs a risk assessment of at least four factors (164.402):
  - the nature and extent of the PHI, including identifiers and the likelihood of re-identification;
  - the unauthorized person who used it or received it;
  - whether the PHI was actually acquired or viewed;
  - how far the risk has been mitigated.
- **Unsecured PHI only.** The notice duties apply to breaches of unsecured PHI. Unsecured PHI is PHI that is "not rendered unusable, unreadable, or indecipherable to unauthorized persons through the use of a technology or methodology specified by the Secretary" (164.402).
- **Burden of proof.** The covered entity or business associate must be able to show either that every required notice was made, or that the use or disclosure was not a breach (164.414(b)). Document the risk assessment either way.

### 2.2 What makes PHI secured

HHS guidance published with the interim final rule names encryption and destruction as the two methods (74 FR 42740, August 24, 2009; guidance at 74 FR 42742 to 42743). The key text, quoted from the Federal Register:

- **Data at rest:** "Valid encryption processes for data at rest are consistent with NIST Special Publication 800-111, Guide to Storage Encryption Technologies for End User Devices."
- **Data in motion:** "Valid encryption processes for data in motion are those which comply, as appropriate, with NIST Special Publications 800-52, Guidelines for the Selection and Use of Transport Layer Security (TLS) Implementations; 800-77, Guide to IPsec VPNs; or 800-113, Guide to SSL VPNs, or others which are Federal Information Processing Standards (FIPS) 140-2 validated."
- **Keys:**
  - Encryption counts only where "such confidential process or key that might enable decryption has not been breached".
  - The guidance adds that "these decryption tools should be stored on a device or at a location separate from the data they are used to encrypt or decrypt."
- **Destruction:**
  - Paper, film, or other hard copy is shredded or destroyed so the PHI cannot be read or reconstructed. Redaction is specifically excluded.
  - Electronic media is cleared, purged, or destroyed consistent with NIST SP 800-88, so the PHI cannot be retrieved.

**Currency note (this note's words, not HHS's).** NIST has revised several of the publications the guidance names:
- SP 800-52 is now Rev. 2 (August 29, 2019).
- SP 800-77 is Rev. 1 (June 30, 2020).
- SP 800-88 Rev. 2 (September 2025) supersedes Rev. 1.
- FIPS 140-2 is superseded by FIPS 140-3. NIST's FIPS 140-3 transition page (updated April 13, 2026) gives September 22, 2026 as the date all FIPS 140-2 certificates are placed on the Historical List, a date that had passed when this note was checked on 2026-10-04 (the CMVP list itself was not checked). The page also says that even on that list, CMVP supports the purchase and use of these modules for existing systems.

The guidance is cited from the Federal Register because hhs.gov blocks automated retrieval. Its current hhs.gov wording has not been re-read.

**Ransomware.** Ransomware that encrypts ePHI is judged under the same 164.402 definitions:
- A breach is presumed unless an exclusion applies or a documented risk assessment shows a low probability of compromise (section 2.1).
- Whether the PHI was secured is a separate question from the presumption: it decides whether notice is owed, because the notice duties apply only to breaches of unsecured PHI (section 2.1).
- In a May 2017 cyber threat update, HHS wrote: "As outlined in its guidance available on its website, OCR presumes a breach in the case of ransomware attack." (HHS Update #4 (Revised), May 16, 2017).
- The same update addresses ePHI that was already encrypted when the attack occurred, and puts the proof on the entity: "If the data is not encrypted by the entity to at least NIST specifications when the ransomware attack is deployed, then OCR presumes a breach occurred, due to the ransomware attack. As such, the entity would need to prove, through forensic or other evidence, that the ePHI was encrypted when the attack occurred, and the ransomware containerized (or encrypted again) already-encrypted ePHI."
- HHS's separate ransomware fact sheet is not quoted here, because its current text could not be retrieved.

**Design note for Contoso.** The reference architecture sets an at-rest encryption requirement for every class of store that holds ePHI (`02-reference-architecture.md` section 7, Data at rest by data-store class; `crosswalk.md` section 8). Three points connect it to this section:
- **A requirement is not a finding that ePHI was secured.** Whether lost, stolen, or exfiltrated ePHI was secured depends on the encryption process used and on the key not having been breached, as the guidance quoted above says, and it is decided case by case in the risk assessment (section 2.1).
  - The design's key custody rule keeps keys and recovery keys outside the system they protect, in line with the guidance's point that decryption tools be stored apart from the data.
  - Whether a given configuration, such as the TPM-only protection that 02 section 7 chooses for shared clinical workstations, is consistent with NIST SP 800-111 is part of that case-by-case assessment.
- **Encryption at rest does not protect data read through a running system.** It protects media that leave Contoso's control (02 section 7). An attacker who reads ePHI through a compromised identity or process on a running system, as in the ransomware path, takes it in readable form, so the at-rest encryption does not render that copy unreadable to the person who took it.
- **Some ePHI stays unsecured by design.** Medical devices that cannot encrypt the ePHI they store are owned, dated exceptions (residual risk RR-15).
  - ePHI on such a device that is lost or stolen is unsecured PHI. The loss is assessed as a possible breach under section 2.1, and notification follows unless an exclusion applies or a documented risk assessment shows a low probability of compromise.
  - The same holds for any copy left unencrypted under another documented exception, such as a legacy platform that cannot encrypt, or a copy taken through a storage platform whose encryption sits only at the storage layer.
  - Backup copies must be encrypted (ADR-009), but the recovery implementation is not designed, so this matrix assumes nothing about any copy that exists today.

### 2.3 Clocks and recipients

| Notice | Trigger | Clock | Method and content | Citation |
|---|---|---|---|---|
| Individuals | Discovery of a breach of unsecured PHI | Without unreasonable delay, and in no case later than 60 calendar days after discovery | Written notice by first-class mail, or by email if the individual agreed to electronic notice and has not withdrawn that agreement. Plain language. Content: what happened (breach date and discovery date, if known), the types of PHI involved, steps individuals should take, what Contoso is doing, and contact procedures that include a toll-free number, email address, website, or postal address | 45 CFR 164.404(a) to (d)(1) |
| Substitute notice | Contact information is insufficient or out of date | Same as individual notice | Fewer than 10 individuals: another written form, telephone, or other means. 10 or more: a conspicuous 90-day posting on the website home page, or conspicuous notice in major print or broadcast media where the individuals likely live, plus a toll-free number active for at least 90 days | 164.404(d)(2) |
| Urgent notice | Possible imminent misuse | When needed, in addition to written notice | Telephone or other means | 164.404(d)(3) |
| Media | Breach involving more than 500 residents of a State or jurisdiction | Without unreasonable delay, and in no case later than 60 calendar days after discovery | Notice to prominent media outlets serving that State or jurisdiction | 164.406 |
| HHS, 500 or more individuals | Breach involving 500 or more individuals | Contemporaneously with the individual notice | In the manner specified on the HHS website | 164.408(a), (b) |
| HHS, fewer than 500 individuals | Breach involving fewer than 500 individuals | Not later than 60 days after the end of each calendar year, for breaches discovered in the preceding calendar year | Keep a log or other documentation, then submit in the manner specified on the HHS website | 164.408(c) |
| Law enforcement delay | A law enforcement official says a notice would impede a criminal investigation or damage national security | Written statement: delay for the period it specifies. Oral statement: document it, including the official's identity, and delay no longer than 30 days from the oral statement unless a written statement arrives in that time | Applies to any notification, notice, or posting under the subpart | 164.412 |

### 2.4 When the clock starts

Under 164.404(a)(2), "a breach shall be treated as discovered by a covered entity as of the first day on which such breach is known to the covered entity, or, by exercising reasonable diligence would have been known to the covered entity." The same paragraph continues: "A covered entity shall be deemed to have knowledge of a breach if such breach is known, or by exercising reasonable diligence would have been known, to any person, other than the person committing the breach, who is a workforce member or agent of the covered entity (determined in accordance with the federal common law of agency)."

What follows for the playbook:
- **Day 0 is the earliest such knowledge.** It is not the day the privacy office hears about it. Because the test includes what reasonable diligence would have revealed, a triage backlog is a timing risk, not a pause.
- **60 days is the outer limit.** The primary test is without unreasonable delay.
- **An agent's knowledge counts as Contoso's** (section 3).

## 3. Business associate obligations

The component glossary in `02-reference-architecture.md` section 11 labels these Contoso suppliers as business associates:
- the EHR vendor (`EXT-VENDOR-EHR`);
- the revenue-cycle outsourcer (`EXT-RCM-BA`);
- the telehealth video service (`EXT-TELEHEALTH`);
- biomedical device vendors whose service can reach ePHI on a device, which includes every vendor with access through the vendor broker (`EXT-VENDOR-BIOMED`, assumption A-13).

| Obligation | Who notifies whom | Clock | Content | Citation |
|---|---|---|---|---|
| Breach of unsecured PHI | Business associate to Contoso | Without unreasonable delay, and in no case later than 60 calendar days after the business associate's discovery: the first day the breach is known to it, or would have been known with reasonable diligence | Each affected individual, identified to the extent possible. Any other information Contoso needs for its individual notices, at the time of notice or promptly as it becomes available | 45 CFR 164.410(a) to (c) |
| Security incident | Business associate to Contoso | No regulatory clock: the business associate agreement sets it | The contract must require the business associate to report any security incident it becomes aware of, including breaches of unsecured PHI as 164.410 requires | 164.314(a)(2)(i)(C) |
| Subcontractors | Subcontractor to business associate | By contract | The business associate must ensure that subcontractors handling ePHI for it agree by contract to comply with the applicable requirements | 164.314(a)(2)(i)(B) |
| Law enforcement delay | As in section 2.3 | As in section 2.3 | As in section 2.3 | 164.412 |

**Security incident.** 45 CFR 164.304 defines it as "the attempted or successful unauthorized access, use, disclosure, modification, or destruction of information or interference with system operations in an information system." This is broader than a breach, so the agreement should say what to report and how fast.

**Effect on Contoso's clock.** A business associate that acts as Contoso's agent under the federal common law of agency passes its knowledge to Contoso (164.404(a)(2)). Contoso's 60-day clock can then start before the business associate reports. Whether a given vendor is an agent depends on the facts of the relationship, and counsel decides.

**Contract terms (reference recommendation).** The regulation sets no clock for security incidents and allows up to 60 days for breach reports. Contoso's business associate agreements should therefore:
- set a specific, short reporting period for both;
- name the recipient;
- require the 164.410(c) information.

The scenario does not include Contoso's actual agreements.

**Proposed change (not in force).** The January 2025 HIPAA Security Rule NPRM would add a 24-hour business associate report of contingency plan activation if adopted as proposed (section 5.1).

## 4. PCI DSS and card brand obligations (CDE)

**Where the clocks come from.** PCI DSS v4.0.1 sets no notification clock of its own.
- **Requirement 12.10.1.** It requires an incident response plan that is ready to activate for suspected or confirmed security incidents. This paraphrase was checked against the requirement text in SAQ P2PE.
- **PCI SSC guidance on notification** (Responding to a Cardholder Data Breach, 2020):
  - be ready to alert the necessary parties immediately;
  - the plan covers the payment card brands, acquirers, and anyone else owed notice by contract or law;
  - acquirers and brands each set their own rules and thresholds for requiring a PCI Forensic Investigator (PFI);
  - PCI SSC FAQ 1142 lists brand contacts.
- **Age of that guidance.** It predates PCI DSS v4.0 and v4.0.1 and quotes the superseded v3.2.1 wording of Requirement 12.10.

**Contoso's card data exposure.** Card-present payments run through P2PE terminals (`RES-POI` in `Z-CDE`) that encrypt at the terminal. Online payments redirect to the payment service provider (`EXT-PSP`) (ADR-007). A card data incident is still possible through:
- terminal tampering or substitution (risk R-10);
- a malicious change to the payment redirect on the patient portal (`RES-PORTAL`; risk R-12);
- a compromise at the P2PE provider or the PSP (R-11).

The patient portal also holds PHI, so one portal incident can start HIPAA clocks and card brand clocks at the same time. The brand rules below apply whatever validation path the acquirer accepts (A-16).

| Recipient | Who notifies | Clock | Source (title, edition, section) | Verification |
|---|---|---|---|---|
| Acquirer | Contoso | Per Contoso's merchant agreement, which is not part of this reference set. Visa separately requires immediate notice to the acquirer (next row) | Merchant agreement | Not available in the scenario |
| Visa | Contoso must ensure Visa is notified | <ul><li>Report to Visa within 3 calendar days of discovering evidence enough to raise a reasonable suspicion of a compromise event, or to confirm one (A-1.1).</li><li>Notify the acquirer immediately (A-3.1).</li><li>Send an Incident Report within 3 calendar days of notifying Visa (A-2.1).</li><li>Send known or suspected compromised account numbers within 3 calendar days of discovery, Visa's request, or determination of the window of exposure (A-4.1).</li><li>If Visa requires a PFI: contract the PFI within 5 business days, then a preliminary report within 5 business days of retaining the PFI and a final report within 10 business days of completion (A-5).</li></ul> | What To Do If Compromised: Visa Supplemental Requirements, Version 10.0, effective 25 June 2026, Section A | Primary, read in full from Visa's Argentina domain (the US path returns HTTP 403). It supplements the Visa Core Rules and the Visa Product and Service Rules, which control if they conflict. Those rules were not checked |
| Acquirer, for Mastercard | Contoso | Notify the acquirer under the merchant agreement and Mastercard's rules. This matrix gives no time limit for Mastercard | Merchant agreement; Mastercard's Security Rules and Procedures, Merchant Edition (edition not confirmed) | Mastercard's rules were not read: the Mastercard hosts tried returned HTTP 403 to automated retrieval on 2026-10-04. Confirm the timing with the acquirer |
| American Express | Contoso | Not paraphrased: American Express marks the policy confidential and trade secret, so this matrix cites it by title, edition, and section only. Read the cited sections directly | Data Security Operating Policy (DSOP), United States, April 2026, Sections 3 and 8 | Primary. Applies where Contoso is bound by the DSOP; the scenario does not say how Contoso accepts American Express |
| Discover | Contoso, by telephone to Discover Global Network Security, using the number on the page | "Within 48 hours of incident" | Discover Global Network, Contact Us page, U.S. business owners | Primary but undated, and no versioned rules document was found. The page does not say whether the 48 hours run from the incident or from its discovery, so plan on the earlier reading and confirm with the acquirer |

**Working with a PFI (PCI SSC guidance, 2020).**
- A listed PFI must be able to start an investigation within five business days of signing an agreement.
- The PFI's preliminary and final reports go to the acquirer and the affected brands.
- A company that already provides other PCI services to Contoso, such as its assessor, cannot act as its PFI.
- Unless the PFI directs otherwise, isolate compromised systems from the network rather than turning them off, and preserve all evidence and logs.

## 5. Other regimes reviewed

### 5.1 HIPAA Security Rule NPRM (proposed, not in force)

The notice of proposed rulemaking published January 6, 2025 (90 FR 898, RIN 0945-AA22, Docket HHS-OCR-2024-0020) is a proposal. The 2026 Unified Agenda lists it under Long-Term Actions, with final action 07/00/2027 (checked 2026-10-07). If adopted as proposed, two provisions would add 24-hour clocks:

- **Contingency plan activation.** Proposed 45 CFR 164.314(a)(2)(i)(D) would make business associate contracts require a report to the covered entity when the business associate activates its contingency plan (proposed 164.308(a)(13)). In the proposed regulatory text, the report would be due "without unreasonable delay, and in no case later than 24 hours after activation of the contingency plan." The NPRM's preamble adds that the proposal, if finalized, would not change the business associate's breach reporting obligations under the Breach Notification Rule (section 3).
- **Workforce access changes.** Proposed 45 CFR 164.308(a)(9)(ii)(D) concerns changes to a workforce member's authorization to access another covered entity's or business associate's ePHI or systems. Proposed (D)(1) would require written procedures to notify that entity of the change, and proposed (D)(2) sets the deadline. In the proposed regulatory text of (D)(2): "Notification must occur as soon as possible but no later than 24 hours after a change in or termination of a workforce member's authorization to access electronic protected health information or relevant electronic information systems maintained by such other covered entity or business associate."

Neither proposed provision applies today, and this matrix schedules neither one. Re-check the rulemaking status before relying on this section.

### 5.2 CIRCIA (not final)

The Cyber Incident Reporting for Critical Infrastructure Act of 2022 reporting duties start only under a final rule from CISA (Cybersecurity and Infrastructure Security Agency).
- **No final rule as of 2026-10-04.** The final rule (RIN 1670-AA04) has been under OIRA review since 2026-10-01. The NPRM was published at 89 FR 23644 (April 4, 2024, Docket CISA-2022-0010).
- **The statute sets the clocks a CIRCIA covered entity would face:**
  - covered cyber incidents: "not later than 72 hours after the covered entity reasonably believes that the covered cyber incident has occurred" (6 U.S.C. 681b(a)(1));
  - ransom payments: "not later than 24 hours after the ransom payment has been made" (681b(a)(2)).
- **The duties are not yet in effect.** They take effect "on the dates prescribed in the final rule issued pursuant to subsection (b)" (681b(a)(7)).

Whether Contoso would be a CIRCIA covered entity cannot be determined until the final rule is published. For context only: the NPRM's criteria included owning or operating a hospital with 100 or more beds, or a critical access hospital. The scenario gives no bed counts. Check the Federal Register before relying on this section.

### 5.3 State breach notification laws

State breach notification laws vary, and some may apply alongside HIPAA. The scenario names no states, so this matrix lists none. For each incident, counsel maps the states involved and their clocks.

## 6. Decision points for the incident response playbook

| Step | Question | If yes | Detail |
|---|---|---|---|
| 1 | Is there a possible compromise of PHI or card data? | Start one incident timeline. Record the earliest time any workforce member or agent knew, or with reasonable diligence would have known. That is HIPAA discovery; each card brand applies its own trigger | 2.4, 4 |
| 2 | Could card data be involved (`Z-CDE`, `RES-POI`, the portal payment redirect, `EXT-PSP`, `EXT-P2PE`)? | Notify the acquirer immediately. Notify Visa within 3 calendar days and Discover within 48 hours. For Mastercard, notify the acquirer under the merchant agreement and Mastercard's rules (this matrix gives no Mastercard time limit). For American Express, follow the policy sections cited in section 4. Isolate rather than power off, unless a PFI directs otherwise | 4 |
| 3 | Could PHI be involved? | Run and document the 164.402 four-factor risk assessment, and decide whether the PHI was secured under the HHS guidance. For ransomware, start from the presumption of breach | 2.1, 2.2 |
| 4 | Is it a breach of unsecured PHI? | Notify individuals, and the media where required (more than 500 residents of one State or jurisdiction affected), without unreasonable delay and no later than 60 calendar days after discovery. Notify HHS at the same time as individuals if 500 or more individuals are affected, or through the annual log otherwise | 2.3 |
| 5 | Is a business associate involved? | Apply the agreement's reporting clock, request the 164.410(c) information, and ask counsel whether the business associate's knowledge is imputed to Contoso | 3 |
| 6 | Has law enforcement asked for a delay? | Get the request in writing, or document an oral request and limit the delay to 30 days unless a written statement follows | 2.3 |
| 7 | Always | Keep the timeline, the risk assessment, and copies of every notice. The burden of proof is Contoso's (164.414(b)) | 2.1 |

Companion files: `crosswalk.md` (sections 3 and 8), `risk-register.md` (impact scale), `02-reference-architecture.md` (component glossary; section 7, data at rest by data-store class; residual risk RR-15), and ADR-007 and ADR-009 in the architecture's `adr/` folder.

## Sources

| Title | Publisher | URL | Date checked | Quality |
|---|---|---|---|---|
| 45 CFR Part 164 Subpart D (164.400 to 164.414), read through the eCFR versioner API at point in time 2026-09-30 | Office of the Federal Register, eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D | 2026-10-04 | primary |
| 45 CFR 164.304 (security incident) and 164.314(a)(2)(i) (business associate contracts) | Office of the Federal Register, eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C | 2026-10-04 | primary |
| Breach Notification for Unsecured Protected Health Information, interim final rule, 74 FR 42740 (August 24, 2009); guidance at 74 FR 42742 to 42743 | Office of the Federal Register, via GPO govinfo | https://www.govinfo.gov/content/pkg/FR-2009-08-24/html/E9-20169.htm | 2026-10-04 | primary |
| HHS Update #4 (Revised), May 16, 2017 | HHS, hosted by ASPR TRACIE | https://files.asprtracie.hhs.gov/documents/hhs-update-4-international-cyber-threat-to-healthcare-orgs.pdf?cb=4339 | 2026-10-07 | primary |
| NIST SP 800-52 Rev. 2, Guidelines for the Selection, Configuration, and Use of Transport Layer Security (TLS) Implementations | NIST | https://csrc.nist.gov/pubs/sp/800/52/r2/final | 2026-10-04 | primary |
| NIST SP 800-77 Rev. 1, Guide to IPsec VPNs | NIST | https://csrc.nist.gov/pubs/sp/800/77/r1/final | 2026-10-04 | primary |
| NIST SP 800-88 Rev. 2, Guidelines for Media Sanitization | NIST | https://csrc.nist.gov/pubs/sp/800/88/r2/final | 2026-10-04 | primary |
| FIPS 140-3 Transition Effort (CMVP) | NIST | https://csrc.nist.gov/projects/fips-140-3-transition-effort | 2026-10-04 | primary |
| HIPAA Security Rule To Strengthen the Cybersecurity of Electronic Protected Health Information (proposed rule), 90 FR 898 | Federal Register | https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information | 2026-10-04 | primary |
| Unified Agenda 2026, RIN 0945-AA22 (Long-Term Actions; final action 07/00/2027) | reginfo.gov | https://www.reginfo.gov/public/do/eAgendaViewRule?pubId=202510&RIN=0945-AA22 | 2026-10-07 | primary |
| 6 U.S.C. 681b, Required reporting of certain cyber incidents (USCODE-2024 edition) | GPO govinfo | https://www.govinfo.gov/link/uscode/6/681b?link-type=html | 2026-10-04 | primary |
| Cyber Incident Reporting for Critical Infrastructure Act (CIRCIA) Reporting Requirements (proposed rule), 89 FR 23644 | Federal Register | https://www.federalregister.gov/documents/2024/04/04/2024-06526/cyber-incident-reporting-for-critical-infrastructure-act-circia-reporting-requirements | 2026-10-04 | primary |
| EO 12866 review record, RIN 1670-AA04 final rule (received 2026-10-01; still under review when checked) | reginfo.gov | https://www.reginfo.gov/public/do/eoDetails?rrid=1550967 | 2026-10-04 | primary |
| Unified Agenda 2026, RIN 1670-AA04 | reginfo.gov | https://www.reginfo.gov/public/do/eAgendaViewRule?pubId=202510&RIN=1670-AA04 | 2026-10-04 | primary |
| Guidance: Responding to a Cardholder Data Breach (2020) | PCI Security Standards Council | https://listings.pcisecuritystandards.org/documents/Responding_to_a_Cardholder_Data_Breach.pdf | 2026-10-04 | primary |
| Self-Assessment Questionnaire P2PE for PCI DSS v4.0 (April 2022), superseded by the v4.0.1 SAQs; used for the Requirement 12.10.1 text | PCI Security Standards Council | https://listings.pcisecuritystandards.org/documents/PCI-DSS-v4-0-SAQ-P2PE.pdf | 2026-10-04 | primary |
| PCI DSS v4.0.1 (document library; automated retrieval returned HTTP 403) | PCI Security Standards Council | https://www.pcisecuritystandards.org/document_library/ | 2026-10-04 | primary |
| What To Do If Compromised: Visa Supplemental Requirements, Version 10.0 (effective 25 June 2026) | Visa | https://www.visa.com.ar/dam/VCOM/download/merchants/cisp-what-to-do-if-compromised.pdf | 2026-10-04 | primary |
| Security Rules and Procedures, Merchant Edition (not retrieved: HTTP 403) | Mastercard | https://www.mastercard.com/content/dam/mccom/shared/business/support/rules-pdfs/SPME-Manual.pdf | 2026-10-04 | unverified |
| Data Security Operating Policy, United States (April 2026) | American Express | https://www.americanexpress.com/content/dam/amex/us/merchant/new-data-security/DSOP_United_States_EN.pdf | 2026-10-04 | primary |
| Contact Us, U.S. business owners (undated web page) | Discover Global Network | https://servicecenter.discoverglobalnetwork.com/onlineform/contact-us | 2026-10-04 | primary |
