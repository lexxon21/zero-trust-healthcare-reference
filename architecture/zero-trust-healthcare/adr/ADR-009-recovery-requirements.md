# ADR-009: Recovery requirements

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

| Field | Value |
|---|---|
| Status | Accepted (reference design). Requirements only: this record sets what recovery must achieve, not how. |
| Date | 2026-10-04 |
| Revised | 2026-10-07 |
| Decision owners (fictional roles) | CISO, VP Infrastructure, Chief Medical Information Officer, Emergency Management lead, Identity Engineering lead |
| Scope | The properties of every copy that Contoso Regional Health (fictional) would restore ePHI, clinical systems, or Tier 0 identity systems from (`SVC-BACKUP`). Products, topology, recovery time and point objectives, and restore order stay with Contoso (A-19). |
| Related | `02-reference-architecture.md` sections 7, 11, and 13 (RR-11); ADR-004; ADR-008; the companion threat model (`threat-model.md` section 9 item 1, TM-A1); the companion ransomware playbook (`ir-ransomware.md` sections 3.1 and 6.5) |

## Context

Ransomware against clinical operations is the top-ranked attack path in the companion threat model (AP-4), and the Tier 0 path (AP-5) is ranked fifth with the same Critical impact. Both include a step that destroys or blocks recovery (`attack-paths.md` AP-4 step 10, AP-5 step 9), and the threat model says both turn on whether recovery survives the attack. Its sourced context includes a documented intrusion that reached a synced administrator and then deleted cloud backups (`threat-model.md` section 7). Its section 9 item 1 asks for immutable and offline copies, isolation from Tier 0 administrative reach, and tested restores, with recovery assets treated as Tier 0 for monitoring. Until this record, the design set specified none of them: `SVC-BACKUP` was a placeholder (A-19), and RR-11 recorded recovery as undesigned.

Facts this record depends on (checked 2026-10-04):

- **HIPAA requires backups and restoration, and makes testing addressable.** Under 45 CFR 164.308(a)(7)(ii), the data backup plan ((A), procedures to create and maintain retrievable exact copies of ePHI) and the disaster recovery plan ((B), procedures to restore any loss of data) are required. Testing and revision procedures ((D)) and the applications and data criticality analysis ((E)) are addressable. The integrity standard (164.312(c)(1)) asks for protection of ePHI from improper alteration or destruction.
- **Encryption at rest makes key recovery part of data recovery.** Microsoft documents that backups of a SQL Server database protected by transparent data encryption are encrypted with the database encryption key, that restoring them requires the certificate that protects that key, and that data is lost if the certificate is no longer available. The at-rest requirements in `02-reference-architecture.md` section 7 therefore create keys that recovery depends on.
- **The maturity model stops short of recovery.** CISA's ZTMM v2.0 states that it does not address recovery. It places backups in the Data pillar and points to NIST SP 1800-11 for detailed data integrity and recovery guidance.
- **Tiering alone does not resolve where backups belong.** ADR-004 puts in Tier 0 anything that controls identity or can run code on every device (`03-identity-and-access.md` section 4). A system that holds copies of `IDS-AD` and can overwrite any server qualifies by impact. If production Tier 0 accounts also administer it, the Tier 0 compromise in AP-5 reaches the copies with the same credentials.

What is not known: which products Contoso runs today, where its copies sit, and whether any restore has been tested. A-19 assumes the capability exists. This record does not assume it meets the requirements below.

## Decision

`SVC-BACKUP` must meet four requirements. Each is a property that a reviewer can test against any proposed recovery design.

**Scope of the copies.**

- The Tier 0 identity systems that the clinical restores depend on: `IDS-AD` (directory and domain controller system state) and `PIP-PKI` (certification authority database and the material needed to rebuild the issuing CAs).
- The stores in ADR-008's local-first set (`RES-EHR` database tier, `RES-PACS` archive, `RES-LIS`, `RES-PHARM`, `RES-INTEGRATION`), plus `RES-LEGACY`, `RES-FILES`, and `RES-AZ-WORKLOADS`.
- The keys, certificates, and recovery keys that encrypted data depends on (`02-reference-architecture.md` section 7), kept apart from the data they unlock.
- `RES-M365`: whether Contoso keeps its own copies of Microsoft 365 data is a decision for its criticality analysis. Any copies it keeps must meet these requirements.

Contoso's criticality analysis may add data sets. It may not drop the identity systems, because the clinical applications cannot be restored to working order without them (sign-in on the local clinical plane runs through `IDS-AD`, and badge sign-in through `PIP-PKI`).

1. **Immutable and offline copies.**
   - For every in-scope data set, at least one copy is immutable for a retention period that Contoso sets. Until that period ends, no identity can alter or delete the copy or shorten its retention, including the recovery plane's own administrators.
   - At least one copy is offline: no standing network path or credential path reaches it from production. It comes back online only through a deliberate, recorded action taken outside production administration.
   - One copy may have both properties, or two copies may have one each. The design does not choose (see Consequences).
   - Retention reaches back past the likely start of an undetected intrusion, not only as far as storage cost allows. A copy taken after an intruder gained persistence restores the intruder too, so Contoso sets retention from its own detection evidence.
   - Copies are encrypted at rest. Their keys are held apart from the copies and can be recovered without production Tier 0 (`02-reference-architecture.md` section 7, backup copies row).

2. **Isolation from Tier 0 administrative reach.**
   - Recovery-plane administration is its own administrative domain. Its accounts are not issued, governed, or recoverable by `IDS-AD` or by production roles in `IDS-ENTRA`, and no production Tier 0 role can reset, enroll, or grant a recovery-plane credential.
   - A person who holds both a production role and a recovery-plane role uses separate accounts and separate authenticators for each.
   - Recovery-plane administration runs from devices that production device management (`PIP-DEVICE-MGMT`) does not manage. Tier 0 includes Intune administrators, who can run code on every device they manage (`03-identity-and-access.md` section 4), so a recovery console on a production-managed PAW would sit within Tier 0's reach.
   - Destructive operations need approval by a second recovery-plane administrator, and none can be started from production. They are: deleting a copy, shortening retention, changing immutability or encryption settings, and taking an offline copy out of custody.
   - The recovery plane's management interfaces accept no connections from production zones, including `Z-MGMT` and `Z-T0`. The only flows between production and the recovery plane carry copies, and no credential held in production can use them to change or delete a copy already taken.
   - `SVC-BACKUP` therefore sits outside the production zones in `02-reference-architecture.md` section 7. Its segment is not designed here.
   - These properties make the separation a trust boundary. Copies cross it into the recovery plane, restores cross it back as writes into production, and no management connection crosses it from production. The companion threat model records it as TB-9, and its threat analysis waits for a recovery design, because no control at the boundary is designed yet.

3. **Tested restores, with evidence.**
   - Restores are tested on a schedule that Contoso sets, and after any change to the recovery design, from the immutable or offline copy, not only from a convenient online copy.
   - A test restores into an isolated environment. It passes only when the system owner confirms that the application works there. A clinical application test includes sign-in, so the identity systems it depends on (`IDS-AD`, and `PIP-PKI` for badge sign-in) must be restored or available in the test environment.
   - Each test leaves evidence outside the recovery plane: the copy used and its age, the elapsed time for each stage, the integrity checks and their results, the owner's confirmation, and any failure with its remediation. The evidence is kept with Contoso's contingency plan documentation.
   - Measured restore times are inputs to Contoso's recovery time and point objectives. This record sets no objectives. It requires that whatever objectives Contoso sets are checked against measured times.
   - In an incident, restoration starts from a copy that predates the compromise and is verified before use. The companion identity compromise playbook already confirms that `SVC-BACKUP` is intact and unreachable from compromised identities before any restoration (Branch D step 5).
   - ADR-008's failure-mode drills test continuity of access and restore nothing, so they do not count as restore tests.

4. **Monitored as Tier 0.**
   - Recovery-plane events go to `PIP-SIEM` and are handled at the same priority as Tier 0 events (`03-identity-and-access.md` section 4): administrative sign-ins and role changes; deletion of copies and changes to their expiry; changes to retention, immutability, or encryption settings; failed or missed copy jobs; restores started outside a test or incident record; and any attempt to reach the management interfaces from a production zone.
   - Denied attempts count. A refused attempt to delete a copy or shorten its retention means someone holding credentials is preparing the recovery-inhibition step of AP-4 or AP-5.
   - The recovery plane also keeps its own audit trail, which production identities cannot change, so the record survives a compromise of the tenant that hosts `PIP-SIEM`.
   - Detection status: the companion detection pack watches recovery inhibition on Windows hosts, and deletion of Azure backup items and restore points where Azure-native backup is used (`coverage-map.md` section 3, item 1). Rules for the recovery plane's own logs depend on the product chosen and are not built.

**What this record does not set.**

- Products, topology, and where copies are kept.
- Recovery time and point objectives, and the restore order among clinical applications. Contoso owns them through its applications and data criticality analysis (164.308(a)(7)(ii)(E)), as ADR-008 already states.
- Retention periods and test frequency.
- Recovery of the cloud identity plane's own configuration (`PE-IDENTITY` policies, `PIP-DEVICE-MGMT` baselines) after a destructive Tier 0 compromise. It is a candidate for the recovery design.
- Ransomware response steps. They are in the companion ransomware playbook (`ir-ransomware.md`, with its tabletop kit `tabletop-ransomware.md`), which uses these requirements as its recovery inputs. A playbook is not a recovery capability: recovery stays unverified (RR-11; `coverage-map.md` section 7).

**Capability stays unverified.** These are requirements, not a capability. Until restore tests produce evidence against them, recovery capability is unverified (A-19, RR-11), and the threat model's impact bands for AP-4 and AP-5 stand (TM-A1).

## Alternatives considered

### A. Keep recovery out of scope (rejected)

The top-ranked attack path would keep its decisive control unstated, and the threat model's section 9 item 1 would stay open in every companion artifact. Stating requirements costs little and makes the gap testable.

### B. A full recovery design with products and objectives (deferred)

Objectives need Contoso's criticality analysis, which ADR-008 leaves to Contoso. A product design would also add claims that only a real environment can confirm. Revisit when the criticality analysis exists.

### C. Administer backups as part of Tier 0, from Tier 0 PAWs with Tier 0 accounts (rejected)

It fits ADR-004 neatly, because a system that holds copies of the directory is Tier 0 by impact. But whoever reaches production Tier 0 (AP-5) would then reach the copies with the same credentials, which is the move described in the threat model's sourced context. The recovery plane needs protection equal to Tier 0, not shared administration with it.

### D. Immutable copies only, with no offline copy (rejected)

Immutability holds only while the platform enforces it correctly. A flaw or misconfiguration in that enforcement, or a compromise of the account that controls it, leaves no fallback. An offline copy depends on no running system. The cost is slower restores and custody procedures.

### E. Snapshots on production storage or hypervisors as the recovery copy (rejected as the only copy)

Snapshots restore fast and stay useful for routine operational restores. But production administrators, and anyone holding their credentials, can delete them, so they fail requirement 2. They remain a convenience layer, not the copy these requirements apply to.

## Consequences

Positive:

- The threat model's decisive control is now a stated, testable requirement set instead of an open item in its section 9.
- Any proposed recovery design can be checked against four properties before it is bought.
- Restore evidence gives Contoso's contingency plan testing and its recovery objectives a measured basis.

Negative and residual:

- **Nothing is protected yet.** RR-11 stays open, and ransomware against clinical operations stays the highest-ranked path.
- **A second administrative domain to run.** Separate accounts, authenticators, workstations, and monitoring, with on-call cover. It is one more place for configuration to drift.
- **Offline copies restore slowly** and need custody procedures. The interval between offline copies bounds how much data a restore from them loses.
- **Microsoft 365 data is the hardest case for requirement 2.** The production tenant's own Tier 0 administers the service, so a copy that production Global Administrators can delete does not meet it, whatever product makes it.
- **Retention and storage costs grow** with the look-back period that detection delay demands.
- **Restore tests cost clinical and infrastructure time,** and each clinical test needs its identity dependencies in the test environment.

## Compliance drivers

| Framework | Identifier | Why it matters here |
|---|---|---|
| HIPAA | 45 CFR 164.308(a)(7)(ii)(A), data backup plan (required) | Requirements 1 and 2 keep exact copies retrievable after an attacker reaches production |
| HIPAA | 164.308(a)(7)(ii)(B), disaster recovery plan (required) | Restoration depends on copies that survive the attack |
| HIPAA | 164.308(a)(7)(ii)(D), testing and revision procedures (addressable) | Requirement 3: restore tests with evidence |
| HIPAA | 164.308(a)(7)(ii)(E), applications and data criticality analysis (addressable) | Contoso adds data sets and sets objectives and restore order there |
| HIPAA | 164.312(c)(1), integrity (standard) | Immutable copies protect ePHI from improper alteration or destruction |
| HIPAA | 164.312(b), audit controls (standard) | Requirement 4 records and examines recovery-plane activity |
| NIST CSF 2.0 | PR.DS-11, RC.RP-03, RC.RP-05, PR.AA-05, DE.CM-09, ID.IM-02 | Backups created, protected, maintained, and tested; restoration assets verified before use; restored assets verified; separation of duties; monitoring; improvements from tests |

## ZTMM mapping

Data: Data Availability, not rated in `05-ztmm-maturity-roadmap.md` until recovery is designed and restore-tested. Identity: Access Management (separate recovery-plane administration). Visibility and Analytics (cross-cutting): recovery-plane monitoring. CISA states that the model does not address recovery, so these requirements extend past its scope, as the medical device controls do.

## Revisit when

- Contoso completes its criticality analysis and sets recovery objectives. That is the trigger for a recovery design (alternative B).
- A restore test fails, or measured restore times miss Contoso's objectives.
- A final HIPAA Security Rule sets restoration times or backup and recovery standards. The January 2025 NPRM proposes both (companion research note, contingency planning and backup and recovery rows).
- The recovery plane's product or hosting changes, especially a move onto a platform that production Tier 0 administers.
- An incident or exercise shows a path from production identities to the copies.

## Sources

| Title | Publisher | URL | Date checked | Quality |
|---|---|---|---|---|
| 45 CFR 164.308 and 164.312 | eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C | 2026-10-04 | Primary |
| Zero Trust Maturity Model Version 2.0 | CISA | https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf | 2026-10-04 | Primary |
| NIST SP 1800-11, Data Integrity: Recovering from Ransomware and Other Destructive Events | NIST | https://csrc.nist.gov/pubs/sp/1800/11/final | 2026-10-04 | Primary |
| Transparent Data Encryption (TDE) | Microsoft Learn | https://learn.microsoft.com/en-us/sql/relational-databases/security/encryption/transparent-data-encryption | 2026-10-04 | Primary |
| The NIST Cybersecurity Framework (CSF) 2.0, NIST CSWP 29 | NIST | https://doi.org/10.6028/NIST.CSWP.29 | 2026-10-04 | Primary |
