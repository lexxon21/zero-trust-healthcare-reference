# Contoso Regional Health (fictional): prioritized attack paths

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

Seven attack paths through the Contoso Regional Health (fictional) Zero Trust architecture as designed. Each path is a chain of adversary behaviors described at the level MITRE ATT&CK itself uses: what the technique is, the preconditions and telemetry that matter, and the architecture component that breaks the path or the residual risk that remains. This is adversary modeling for defenders. It contains no exploit code, no tooling, and no operator procedures.

Companion files: `threat-model.md` (scope, assets, trust boundaries, STRIDE, threat actors, sources), `detection-priorities.md` (detection priorities in three tiers), `purple-team-plan.md` (validation design). Component, zone, policy, flow, and residual-risk IDs are from `02-reference-architecture.md`, `03-identity-and-access.md`, and `04-segmentation.md`.

Technique references use MITRE ATT&CK Enterprise v19.2. Every ID, name, and tactic mapping was verified against MITRE's official ATT&CK STIX data for v19.2. v19 split the former Defense Evasion tactic into Stealth (TA0005) and Defense Impairment (TA0112); log and tool tampering is therefore T1685 and its sub-techniques, the current (not revoked) IDs. The help-desk call in AP-2 step 2 is mapped to T1566.004 (Phishing: Spearphishing Voice) under Initial Access, the technique the HHS HC3 alert names for this campaign (`threat-model.md` section 10). The employee impersonation the same alert describes is T1684.001 (Social Engineering: Impersonation), which v19 places under Stealth (TA0005); it is noted here rather than given a step of its own, so each step keeps one tactic.

## How to read a path

Each step names its ATT&CK tactic (with tactic ID), its technique (with technique ID and name), the data source a defender needs to see the step, and the architecture control that stops or constrains it (or the residual risk if none does). "Data source" means the telemetry a security operations analyst would query, named for the scenario stack (Microsoft Sentinel tables, Microsoft Defender XDR advanced hunting tables, and the network and application logs that `PIP-SIEM` ingests under assumption A-17). A path is not a script: real intrusions skip, reorder, and repeat steps.

Likelihood bands reflect both how common the behavior is in current healthcare reporting (see `threat-model.md` section 7) and how much of the path the architecture already blocks. Impact bands reflect harm to patients, to ePHI, and to Contoso.

Every rule in the detection pack is an untested template as of 2026-10-04 (`coverage-map.md` section 1).

## Priority summary

AP numbers are identifiers that other files cite, not ranks; the Rank column gives the order.

| Rank | ID | Path | Likelihood | Impact | Residual risks exercised |
|---|---|---|---|---|---|
| 1 | AP-4 | Ransomware against clinical operations from a phished managed workstation | High | Critical | RR-02, RR-11 |
| 2 | AP-1 | Adversary-in-the-middle phishing steals a live session to ePHI | High | High | RR-03 |
| 3 | AP-2 | Help-desk social engineering enrolls attacker MFA, then diverts payments | High | High | RR-01, identity-proofing process |
| 4 | AP-3 | Compromised partner tenant reaches the EHR or an imaging modality through the vendor broker | Medium to High | Very High | RR-06, RR-12 |
| 5 | AP-5 | Hybrid identity Tier 0 compromise via the Entra Connect sync boundary | Medium | Critical | RR-07, RR-09, RR-11, RR-16 |
| 6 | AP-6 | Illicit OAuth consent or workload-identity abuse reaches ePHI in Microsoft 365 | Medium | High | Workload-identity coverage gap |
| 7 | AP-7 | Medical device compromise with constrained lateral reach and availability impact | Medium | High | RR-04, RR-05, RR-14 |

---

## AP-4: Ransomware against clinical operations

**One line.** A phished managed workstation becomes the foothold for lateral movement across the clinical network, defense impairment, and encryption that takes clinical systems offline.

**Why it ranks first.** Healthcare and Public Health is the most-reported ransomware sector in current federal data (FBI IC3 2025, primary), and peer-reviewed studies tie a ransomware attack on a health system to measurable disruption and worse cardiac arrest outcomes at neighboring hospitals that were not attacked (JAMA Network Open 2023; Critical Care Explorations 2024; `threat-model.md` section 7). Impact is a patient-safety event, not only a data event.

**Boundary and residual risks.** TB-4 (local clinical plane, RR-02) and the recovery assumption (RR-11, TM-A1). The local plane evaluates fewer signals than the cloud plane by design, and recovery requirements are set (ADR-009) but the implementation is not designed, so recovery capability is unverified.

**Preconditions.** A workforce member opens a malicious attachment on a managed endpoint. Report-only or phased controls (TM-A2) raise likelihood during rollout.

| Step | Tactic | Technique | Data source a defender needs | Breaks the path / residual |
|---|---|---|---|---|
| 1 | Initial Access (TA0001) | T1566.001 (Phishing: Spearphishing Attachment) | EmailEvents, Defender for Office 365 detonation verdicts | `SVC-EMAIL` filtering; user reporting |
| 2 | Execution (TA0002) | T1204.002 (User Execution: Malicious File) | DeviceProcessEvents | `PEP-HOST` application control; Defender for Endpoint |
| 3 | Execution (TA0002) | T1059 (Command and Scripting Interpreter) | DeviceProcessEvents | EDR behavioral blocking |
| 4 | Discovery (TA0007) | T1018 (Remote System Discovery) | DeviceNetworkEvents, DeviceProcessEvents | Micro-segmented `Z-CLIN-APP`; limited reach from `Z-CLIN-USER` |
| 5 | Discovery (TA0007) | T1135 (Network Share Discovery) | DeviceNetworkEvents, SecurityEvent | Host east-west blocking (`PEP-HOST`) |
| 6 | Credential Access (TA0006) | T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting) | IdentityDirectoryEvents, Defender for Identity alerts, SecurityEvent | Protected Users, AES types, tiering; RR-02 on the local plane |
| 7 | Lateral Movement (TA0008) | T1021.002 (Remote Services: SMB/Windows Admin Shares) | DeviceNetworkEvents, DeviceLogonEvents | `PEP-HOST` blocks peer-to-peer SMB and RDP between workstations |
| 8 | Lateral Movement (TA0008) | T1570 (Lateral Tool Transfer) | DeviceFileEvents, DeviceNetworkEvents | Host firewall, application control, egress proxy |
| 9 | Defense Impairment (TA0112) | T1685 (Disable or Modify Tools) | DeviceEvents, AlertInfo (tamper-protection alerts) | Defender for Endpoint tamper protection; attack disruption |
| 10 | Impact (TA0040) | T1490 (Inhibit System Recovery) | DeviceProcessEvents, DeviceEvents | RR-11: requirements set (ADR-009 decisions 1 and 2), implementation not designed; capability unverified |
| 11 | Impact (TA0040) | T1486 (Data Encrypted for Impact) | DeviceFileEvents, AlertInfo | EDR and attack disruption; segmentation limits blast radius |
| 12 | Impact (TA0040) | T1489 (Service Stop) | DeviceProcessEvents, SecurityEvent | Service recovery; clinical downtime procedures (ADR-008) |

**Key breaker.** Host east-west blocking (`PEP-HOST`, `04-segmentation.md` section 6) is the cheapest, highest-value control: it denies the peer-to-peer SMB and RDP that ransomware uses to spread between workstations. The decisive control for impact, however, is recovery (RR-11). The sourced context includes an actor that deleted cloud backups (Storm-0501). ADR-009 requires copies that no production credential can delete or alter, but until restores are tested against it the impact band stands (TM-A1). Once implemented, it takes the decisiveness out of step 10 for the in-scope copies and leaves steps 11 and 12, and the data theft below, untouched (`threat-model.md` section 9, item 1).

**Data theft before encryption.** Both sourced cases took data before the destructive phase. The Change Healthcare intruder moved laterally and exfiltrated data, and ransomware followed nine days after entry (Change Healthcare testimony); Storm-0501 began its mass deletion only after its exfiltration phase was complete. This path gives exfiltration no step of its own. AP-1 step 9 and AP-3 step 6 model the same tactic with T1567.002 (Exfiltration Over Web Service: Exfiltration to Cloud Storage) and T1048 (Exfiltration Over Alternative Protocol), and the detection pack lists both as not built (`coverage-map.md` section 4). Recovery does nothing for it: the ePHI breach stands whether or not restores succeed.

**Likelihood High, Impact Critical.**

---

## AP-1: Adversary-in-the-middle phishing steals a live session to ePHI

**One line.** A reverse-proxy phishing page captures a valid, fully authenticated session (including the MFA result) and replays the stolen session material to read and exfiltrate ePHI, most cleanly against the EHR browser path on an unmanaged device.

**Why it ranks second.** The RaccoonO365 phishing-as-a-service kits were used against at least 20 US healthcare organizations (Microsoft Digital Crimes Unit, 2025, primary), and Cloudflare, which took part in disrupting the service, describes the kit as an adversary-in-the-middle proxy that captures the session cookie and so bypasses MFA (Cloudflare, 2025, primary for its own analysis). Token theft is also called out as a way attackers bypass MFA (Microsoft Digital Defense Report 2025, primary). It directly exercises RR-03, the design's acknowledged gap.

**Boundary and residual risks.** TB-1 (RR-03). The EHR browser interface and guest or unmanaged sessions are not enforced by continuous access evaluation, so a stolen session stays usable until it expires.

**Preconditions.** An affiliated physician on an unmanaged personal device uses the EHR browser interface under CA-10 (session-controlled browser access). Phishing-resistant MFA (CA-07) resists the credential phish, but the session token captured after authentication is the target.

| Step | Tactic | Technique | Data source a defender needs | Breaks the path / residual |
|---|---|---|---|---|
| 1 | Reconnaissance (TA0043) | T1589 (Gather Victim Identity Information) | External (brand and physician-directory monitoring) | Awareness training; limited visibility |
| 2 | Initial Access (TA0001) | T1566.002 (Phishing: Spearphishing Link) | EmailEvents, UrlClickEvents, SigninLogs | `SVC-EMAIL`; phishing-resistant MFA raises the bar on credential capture |
| 3 | Execution (TA0002) | T1204.001 (User Execution: Malicious Link) | SigninLogs (unusual proxy source), CloudAppEvents | Risk-based policies CA-17, CA-18 |
| 4 | Credential Access (TA0006) | T1557 (Adversary-in-the-Middle) | SigninLogs, EntraIdSignInEvents (anomalous session properties), AADUserRiskEvents (user risk detections) | ID Protection risk detections: Attacker in the Middle, an offline user risk detection that raises the user to High risk, the level CA-18 acts on; and Anomalous token, a sign-in and user risk detection |
| 5 | Credential Access (TA0006) | T1539 (Steal Web Session Cookie) | CloudAppEvents, EntraIdSignInEvents | RR-03: EHR browser path and guest or unmanaged sessions not CAE-enforced |
| 6 | Lateral Movement (TA0008) | T1550.004 (Use Alternate Authentication Material: Web Session Cookie) | AADNonInteractiveUserSignInLogs, CloudAppEvents | Token protection CA-21 (Windows native apps only); CA-10 session controls |
| 7 | Collection (TA0009) | T1114.002 (Email Collection: Remote Email Collection), T1114.003 (Email Collection: Email Forwarding Rule) | CloudAppEvents, OfficeActivity | CA-10 in-session restrictions; Purview DLP (phase 3) |
| 8 | Collection (TA0009) | T1213.002 (Data from Information Repositories: Sharepoint) | OfficeActivity, CloudAppEvents | In-session download, print, copy blocking (CA-10) |
| 9 | Exfiltration (TA0010) | T1567.002 (Exfiltration Over Web Service: Exfiltration to Cloud Storage) | CloudAppEvents, DeviceNetworkEvents | DLP; session controls limit volume |

**Key breaker.** `PEP-SESSION-PROXY` under CA-10 keeps unmanaged-device access in the browser and blocks download, print, and copy of sensitive content, which caps what a hijacked session yields. Prevention of the token theft itself is the open gap (RR-03); detection (session anomalies, impossible travel, noninteractive sign-ins from new infrastructure) is the compensation. The architectural recommendation to pursue EHR-vendor CAE or token binding is in `threat-model.md` section 9.

**Likelihood High, Impact High.**

---

## AP-2: Help-desk social engineering, then revenue-cycle payment diversion

**One line.** An attacker convinces the IT help desk to enroll an attacker-controlled MFA method using stolen identifiers, then uses the mailbox to divert payer or direct-deposit payments.

**Why it ranks third.** This exact pattern, callers impersonating revenue-cycle or administrative staff to a health-sector IT help desk, is documented (HHS HC3 Sector Alert 202404031000, primary; no public attribution), and it ends in diverted ACH payments. Business email compromise losses exceed 3 billion US dollars in the latest IC3 report (primary). It needs no malware and defeats phishable MFA at the enrollment step rather than the sign-in step.

**Boundary and residual risks.** TB-1, plus the identity-proofing process that sits outside Zero Trust enforcement, and RR-01 (misuse of legitimate access).

**Preconditions.** The attacker holds enough identity data (for example the last four digits of the employee's Social Security number and the corporate ID number, as HC3 describes) to pass help-desk verification during the phishing-resistant rollout, while interim methods are still accepted (ADR-003).

| Step | Tactic | Technique | Data source a defender needs | Breaks the path / residual |
|---|---|---|---|---|
| 1 | Reconnaissance (TA0043) | T1589 (Gather Victim Identity Information) | External; HR data-exposure monitoring | Limited visibility; proofing controls at the help desk |
| 2 | Initial Access (TA0001) | T1566.004 (Phishing: Spearphishing Voice) | Help-desk ticketing records, call logs | In-person or sponsor-verified identity proofing (CA-19, section 2) |
| 3 | Persistence (TA0003) | T1098.005 (Account Manipulation: Device Registration) | AuditLogs (registered security info, device registration) | Phishing-resistant method requirement; proofing before registration |
| 4 | Credential Access (TA0006) | T1556.006 (Modify Authentication Process: Multi-Factor Authentication) | AuditLogs, SigninLogs (method changes, new-device sign-in) | No phone-only reset exception; short interim-method window |
| 5 | Collection (TA0009) | T1114.002 (Email Collection: Remote Email Collection), T1114.003 (Email Collection: Email Forwarding Rule) | OfficeActivity, CloudAppEvents | CA policies; mailbox-audit review |
| 6 | Stealth (TA0005) | T1564.008 (Hide Artifacts: Email Hiding Rules) | OfficeActivity (New-InboxRule), CloudAppEvents | Inbox-rule monitoring; `PIP-SIEM` correlation |
| 7 | Impact (TA0040) | T1657 (Financial Theft) | OfficeActivity, payer-portal and ERP or banking logs | Process controls: callback verification and dual approval for bank changes |

**Key breaker.** The architecture's phishing-resistant MFA and identity-proofing design (ADR-003, CA-19) is the preventive control, but the help desk is the human weak point. The highest-value compensations are process (verified proofing for any method change, no phone-only exception) and a correlation detection that chains an MFA or contact-method change to a new inbox rule and a banking-change request. Recovery of diverted funds depends on speed, so this correlation must be near-real-time.

**Likelihood High, Impact High.**

---

## AP-3: Compromised partner tenant reaches the EHR or an imaging modality through the vendor broker

**One line.** An attacker who controls a trusted vendor or outsourcer tenant signs in under inbound MFA trust and uses an approved just-in-time broker session to reach EHR servers or, through a biomedical vendor, an imaging modality that holds ePHI.

**Why it ranks fourth.** Third-party and business-associate compromise is a leading healthcare breach driver: the Change Healthcare clearinghouse breach reached a very large population, and about a third of healthcare ransomware filings involved a business associate (peer-reviewed). Likelihood is Medium to High because the broker, approval, and recording controls are strong; impact is Very High because the target is EHR servers.

**Boundary and residual risks.** TB-2 and TB-6 (RR-06, RR-12). Inbound MFA trust means Contoso accepts the partner's authentication claim, and Contoso cannot enforce controls inside a supplier. The biomedical variant also puts the attacker on a medical device behind TB-5 (RR-04), with RR-14 applying where the device sits at a clinic.

**Preconditions.** A partner account in `IDS-PARTNER` is compromised (the partner's own phishing or token theft). The attacker must still obtain PIM-for-Groups activation approved by a Contoso owner, within a bounded window (F-06, F-07). Biomedical vendors without an Entra tenant use Contoso-managed member accounts with Contoso-issued security keys, disabled between engagements (`03-identity-and-access.md` section 7). Against them the attacker needs the key and an account enabled for an engagement, or a proofing failure at key registration (the AP-2 pattern), instead of a compromised tenant.

| Step | Tactic | Technique | Data source a defender needs | Breaks the path / residual |
|---|---|---|---|---|
| 1 | Initial Access (TA0001) | T1199 (Trusted Relationship) | SigninLogs (guest sign-ins), cross-tenant access logs | Due diligence (A-12); CA-13 limits guests to approved apps |
| 2 | Initial Access (TA0001) | T1078.004 (Valid Accounts: Cloud Accounts) | SigninLogs, AADNonInteractiveUserSignInLogs | CA-14 short sign-in frequency, CA-16 location; RR-06 inbound trust |
| 3 | Privilege Escalation (TA0004) | T1098.003 (Account Manipulation: Additional Cloud Roles) | AuditLogs (PIM activation, role and group changes) | PIM-for-Groups activation approved by a named Contoso owner |
| 4 | Lateral Movement (TA0008) | T1021 (Remote Services) | `PEP-VENDOR-BROKER` session logs and recordings | Brokered, recorded session to a narrow target host and ports (F-06) |
| 5 | Collection (TA0009) | T1213 (Data from Information Repositories) | EHR application audit logs | Minimum-necessary EHR roles; billing-only for the outsourcer |
| 6 | Exfiltration (TA0010) | T1048 (Exfiltration Over Alternative Protocol) | DeviceNetworkEvents, firewall (`PEP-NET-ZONE`) logs, broker logs | Egress limited to approved targets; no network-level vendor access |

**Biomedical vendor variant (F-07).** The same chain applies to biomedical vendors (`EXT-VENDOR-BIOMED`), which are business associates when their broker access reaches ePHI on a device (A-13). What changes:

- **Step 3.** The activation is of that vendor's own session group, `grp-vendor-biomed-<vendor>-session`, and clinical engineering approves it (`03-identity-and-access.md` section 7).
- **Step 4.** The session reaches only that vendor's devices in `Z-IOMT-IMAGING`, while the device is out of clinical use or with clinical approval (F-07).
- **Step 5.** The data is what the modality holds, such as patient images (A-13), so the technique is T1005 (Data from Local System) and the evidence is the broker's session recording rather than EHR audit logs. The attacker also inherits the modality's allowed flows to PACS and the worklist, the same residual as AP-7 step 3 (RR-04).
- **Step 6.** Devices that need manufacturer cloud services reach them through the egress proxy on a per-manufacturer allow-list (`04-segmentation.md` section 3). If the compromise reaches the manufacturer's own service (an upstream supplier compromise, RR-12), that allow-listed destination gives data a way out that bypasses the broker. Egress-proxy logs are the source.
- **Visibility.** The passive sensor sees the device side of the session at the three hospitals only. Where the modality sits at a clinic, no sensor sees it (RR-14), and the broker recording, `PEP-NET-ZONE` flow logs, and egress-proxy logs are the only evidence.

The variant reaches less data per session than the EHR path, so the path's rating does not change. It lands on a medical device, though, which makes it one way into AP-7.

**Key breaker.** Just-in-time PIM-for-Groups activation with a named Contoso approver (the system owner for the EHR vendor, clinical engineering for biomedical vendors), a bounded window, recorded broker sessions, and a narrow target set (F-06, F-07) constrain this path tightly: the attacker needs an approved activation, not just a stolen credential. The residual is the approver being socially engineered and the inbound-trust assumption itself (RR-06). Detections: vendor or guest sign-in anomalies, PIM activation outside the expected pattern for any vendor session group (`grp-vendor-*-session`), and broker sessions to unusual hosts.

**Likelihood Medium to High, Impact Very High.**

---

## AP-5: Hybrid identity Tier 0 compromise via the Entra Connect sync boundary

**One line.** From a datacenter foothold, an attacker harvests Active Directory credentials, abuses the hybrid sync boundary to influence cloud authentication, and reaches Tier 0 control of both planes.

**Why it ranks fifth.** A documented intrusion set pivoted from on-premises to the cloud through an Entra Connect Sync server (Microsoft on Storm-0501, 2025, primary; `threat-model.md` section 7 gives the case in full). Likelihood is Medium because it needs a prior foothold and Tier 0 reach, and because the architecture specifically counters the documented variant; impact is Critical because Tier 0 compromise is a full compromise by definition (RR-07).

**Boundary, residual risks, and preconditions.** TB-7 and TB-3 (RR-07, RR-09, RR-11, RR-16). The remote Kerberos SSO path publishes domain controllers to connected clients, and the sync boundary couples on-premises and cloud; steps 8a and 8b are where RR-16 applies. The path needs a foothold in the datacenter or management reach (for example chained from AP-4 or AP-3) and, with privileged accounts not synchronized (ADR-004), assumes the attacker must work harder than in the documented case.

| Step | Tactic | Technique | Data source a defender needs | Breaks the path / residual |
|---|---|---|---|---|
| 1 | Discovery (TA0007) | T1482 (Domain Trust Discovery) | IdentityQueryEvents, Defender for Identity alerts | Tiering; Defender for Identity on domain controllers |
| 2 | Discovery (TA0007) | T1087.002 (Account Discovery: Domain Account) | IdentityQueryEvents, IdentityDirectoryEvents | Monitoring of directory enumeration |
| 3 | Credential Access (TA0006) | T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting) | Defender for Identity alerts, SecurityEvent | Protected Users, AES types, group managed service accounts |
| 4 | Credential Access (TA0006) | T1003.006 (OS Credential Dumping: DCSync) | Defender for Identity alerts, IdentityDirectoryEvents | Tier 0 isolation; replication from non-DC flagged |
| 5 | Credential Access (TA0006) | T1649 (Steal or Forge Authentication Certificates) | Defender for Identity (AD CS) alerts, certification authority audit logs | `PIP-PKI` is Tier 0 with sensors on the certification authority |
| 6 | Persistence (TA0003) | T1556.007 (Modify Authentication Process: Hybrid Identity) | Entra Connect server logs, AuditLogs, Defender for Identity alerts; DeviceProcessEvents only with Defender for Endpoint (`threat-model.md` TM-A4) | Defender for Identity sensors on the Entra Connect servers; Defender for Endpoint there is an open design question (key breaker) |
| 7 | Privilege Escalation (TA0004) | T1484.002 (Domain or Tenant Policy Modification: Trust Modification) | AuditLogs (domain and tenant policy changes) | Alerting on federation and trust changes; approval-gated PIM (one of two named Tier 0 approvers) |
| 8 | Persistence (TA0003) | T1098.003 (Account Manipulation: Additional Cloud Roles) | AuditLogs (directory role assignments) | PIM eligible-only, with Tier 0 activation approved by one of two named approvers; emergency-account alerting |
| 8a | Persistence (TA0003) | T1556.006 (Modify Authentication Process: Multi-Factor Authentication) | AuditLogs (member, owner, and property changes to `grp-ca-emergency-access`) | Role-assignable group with no owners, so a change needs Tier 0 access; every change alerts at Tier 0 priority (ADR-004 decision 9; SN-07); the standing paths need no approval (RR-16) (appendix) |
| 8b | Persistence (TA0003) | T1098 (Account Manipulation) | AuditLogs, then SigninLogs and AADNonInteractiveUserSignInLogs (appendix) | Privileged Authentication Administrator and pass-issuing applications (none by default) are Tier 0 (ADR-004 decision 1); alerts from SN-02, SN-07, and SN-06; two paths need no approval (RR-16) (appendix) |
| 9 | Impact (TA0040) | T1490 (Inhibit System Recovery) | AuditLogs, Azure activity logs, DeviceEvents | RR-11: ADR-009 decision 2 requires isolation from Tier 0 (not implemented); capability unverified |

**Steps 8a and 8b: persistence without a role change.** They are alternatives to step 8 at the same point in the path, not further steps: 8a joins the exclusion group or removes an account from an admin group, and 8b resets an emergency account. Neither changes a role, so a watch on role assignments misses both; 8a edits no Conditional Access policy, so a watch on policy changes misses it too; and both need Tier 0 access first (appendix: AP-5 steps 8a and 8b).

**Key breaker.** The architecture answers the documented variant in three ways. Privileged accounts are cloud-only and not synchronized (ADR-004), which removes the synced-administrator step the documented case used. Defender for Identity sensors run on the Entra Connect servers as well as the domain controllers and AD CS (`03-identity-and-access.md` section 4), which adds identity telemetry at the sync boundary. Emergency and recovery credentials are sealed and monitored. None of the three is the control Microsoft names as missing in the documented case, a sync server onboarded to Defender for Endpoint, and the design does not yet state Defender for Endpoint on Tier 0 servers (`threat-model.md` TM-A4 and section 9 item 8), so that gap is not shown closed. The residual: Tier 0 compromise is a full compromise (RR-07) and remote Kerberos needs a network path to Tier 0 (RR-09), both structural, and ADR-009 decision 2, which at step 9 keeps recovery-plane administration outside Tier 0's reach, is a requirement, not yet a capability (RR-11); what it would and would not close is in `threat-model.md` section 9, item 1.

**Rating.** The Medium likelihood rests on the attacker needing Tier 0 access first. Each route closed in the appendix (AP-5 steps 8a and 8b) would otherwise break that premise, also where AP-2 or AP-4 chains in, so closing them confirms Medium rather than lowering it. Moves 8a and 8b are persistence once Tier 0 is held, not new reach; the Critical band rests on RR-07.

**Likelihood Medium, Impact Critical.**

---

## AP-6: Illicit OAuth consent or workload-identity abuse reaches ePHI in Microsoft 365

**One line.** An attacker obtains an application access token through illicit consent or a compromised app registration and reads ePHI from mailboxes and files without a user session, bypassing MFA.

**Why it ranks sixth.** OAuth and consent abuse is documented and current across sectors (Microsoft Digital Defense Report 2025; FBI FLASH-20250912-001 on connected-app abuse, both primary), and the FBI notes it bypasses many traditional defenses including MFA. Healthcare-specific primary reporting was not found, so likelihood here is inferred from other sectors and set to Medium; impact is High because app tokens give durable, user-independent access to ePHI.

**Boundary and residual risks.** TB-1 and TB-2, plus the workload-identity coverage gap: CA-22 does not cover managed identities or multitenant apps (`03-identity-and-access.md` section 6).

**Preconditions.** A user is induced to consent to a malicious application, or an app registration or service principal is compromised. User consent is restricted by design, so the attacker aims at a user who can still consent, or at admin-consent workflow abuse, or at adding credentials to an existing app.

| Step | Tactic | Technique | Data source a defender needs | Breaks the path / residual |
|---|---|---|---|---|
| 1 | Initial Access (TA0001) | T1566.002 (Phishing: Spearphishing Link) | EmailEvents, UrlClickEvents | `SVC-EMAIL`; user-consent restrictions |
| 2 | Credential Access (TA0006) | T1528 (Steal Application Access Token) | AuditLogs (consent grants), CloudAppEvents | Admin consent workflow; user consent restricted |
| 3 | Persistence (TA0003) | T1098.001 (Account Manipulation: Additional Cloud Credentials) | AuditLogs (service principal credential add) | App credential hygiene; quarterly (example) permission review |
| 4 | Lateral Movement (TA0008) | T1550.001 (Use Alternate Authentication Material: Application Access Token) | AADNonInteractiveUserSignInLogs (delegated tokens), service principal sign-in logs (app-only tokens), CloudAppEvents | CA-22 workload-identity controls (not for managed identities) |
| 5 | Collection (TA0009) | T1114.002 (Email Collection: Remote Email Collection) | OfficeActivity, CloudAppEvents | Mailbox-audit review; app-access anomaly detection |
| 6 | Collection (TA0009) | T1530 (Data from Cloud Storage) | OfficeActivity, CloudAppEvents | Purview labeling and DLP (phase 3) |
| 7 | Exfiltration (TA0010) | T1567.002 (Exfiltration Over Web Service: Exfiltration to Cloud Storage) | CloudAppEvents, DeviceNetworkEvents | DLP; egress monitoring |

**Key breaker.** The preventive layer is consent governance (admin consent workflow, restricted user consent, app credential hygiene). CA-22 adds workload-identity egress and risk controls where licensed, but it does not cover managed identities, so their sign-ins need monitoring, which the detection pack lists as a gap: managed identity sign-in monitoring is not built (`coverage-map.md` section 3, item 11). The residual is that a granted app token is hard to distinguish from legitimate integration use. The detection pack covers new consents and new service-principal credentials; hunting for app-only mailbox and file access is not yet built (`coverage-map.md` section 4).

**Likelihood Medium, Impact High.**

---

## AP-7: Medical device compromise with constrained lateral reach and availability impact

**One line.** A rogue or compromised device on a MAC-authenticated port reaches its device-class server over the one flow the segment allows, and threatens data integrity and availability rather than acting as a broad pivot.

**Why it ranks seventh.** Read together, the sources point mostly to legacy devices that cannot be patched, rather than to attacks on device function; that weighting is this model's synthesis, not a claim any one source makes (`threat-model.md` section 7). The FBI describes outdated, unpatched devices and default configurations, and recommends isolating a device from the network or auditing its network activity where replacing it is not feasible (FBI PIN 20220912-001, primary). Specific firmware exposures add to this, such as the Contec patient-monitor advisories (CISA and FDA, primary). No 2024 to 2026 primary report of ransomware deliberately manipulating device function was found; documented clinical harm came through IT and EHR outages. Impact is therefore weighted toward availability, data exposure, and lateral staging, not device-function manipulation (which is plausible but less evidenced).

**Boundary and residual risks.** TB-5 (RR-04, RR-05, RR-14). A compromised device can still reach its own allowed servers, and MAC Authentication Bypass identifies a device by an attribute an attacker can copy. The 22 clinics have no passive sensor (RR-14), so the `PIP-IOMT-SENSOR` data sources in the steps below apply at the three hospitals only. At a clinic, NAC profiling at admission, `PEP-NET-ZONE` flow logs, and egress-proxy logs are the only visibility.

**Preconditions.** A device segment admits the attacker's device through MAC Authentication Bypass (RR-05), or a legitimate agentless device is compromised through its exposed service, its manufacturer connectivity, or a compromised biomedical vendor session (AP-3, F-07). Validation of this path must be bench or lab only, never against a device in patient use (see `purple-team-plan.md`).

| Step | Tactic | Technique | Data source a defender needs | Breaks the path / residual |
|---|---|---|---|---|
| 1 | Initial Access (TA0001) | T1200 (Hardware Additions) | NAC (`PE-NETWORK`) events, `PIP-IOMT-SENSOR` new-device alerts | RR-05: MAB identifies by a copyable attribute; profiling limits it |
| 2 | Discovery (TA0007) | T1046 (Network Service Discovery) | `PIP-IOMT-SENSOR` anomaly alerts, DeviceNetworkEvents | Passive sensor baselines; no lateral traffic between segments. At a clinic, scanning that stays inside one segment reaches no sensor and no zone firewall (RR-14) |
| 3 | Lateral Movement (TA0008) | T1210 (Exploitation of Remote Services) | `PIP-IOMT-SENSOR`, firewall (`PEP-NET-ZONE`) logs | RR-04: the one allowed flow (device to its server) remains |
| 4 | Collection (TA0009) | T1005 (Data from Local System) | `PIP-IOMT-SENSOR` (unusual egress), egress-proxy logs | Segment allow-lists; no general internet; egress proxy |
| 5 | Impact (TA0040) | T1565.001 (Data Manipulation: Stored Data Manipulation) | `PIP-IOMT-SENSOR`, device-class server logs | Integrity monitoring; clinical validation of device data |
| 6 | Impact (TA0040) | T1489 (Service Stop) | `PIP-IOMT-SENSOR`, server and application logs | Clinical safety gate: a device in use is never auto-disconnected |

**Key breaker.** Device-class micro-segmentation with narrow allow-lists and no lateral traffic between segments (ADR-006) means a compromised device reaches only its own server, and at the three hospitals passive sensor anomaly detection (`PIP-IOMT-SENSOR`) is the primary visibility where no endpoint agent can run. At the clinics there is no sensor (RR-14), so a device foothold there shows only through NAC profiling at admission or a flow that breaks the allow-list at `PEP-NET-ZONE` or the egress proxy; an attacker who wants to stage quietly would pick a clinic device. RR-14 does not change the rating, because a clinic device reaches the same device-class servers through the same allow-lists: it changes how likely the path is to be seen, not how far it reaches. The clinical safety gate (`04-segmentation.md` section 3) deliberately keeps containment of medical devices a human decision, and ADR-008 excludes their segments from automatic attack disruption's IP containment, so the time from detection to a clinical decision, not automation, bounds how long a device foothold lasts. That is a safety choice, not a detection gap. The residuals (RR-04, RR-05, RR-14) are inherent to agentless devices and to where the sensors sit.

**Likelihood Medium, Impact High.**

---

## Cross-path notes

- **Chaining.** AP-1, AP-2, AP-3, and AP-7 are footholds that commonly precede AP-4 (ransomware) and AP-5 (Tier 0), and AP-3's biomedical variant can also open AP-7. The ranking reflects each path's own likelihood and impact; a mature program treats the early-stage paths as the places to break the chain cheaply.
- **The decisive controls appear more than once.** Host east-west blocking (`PEP-HOST`), consent governance, and tested recovery each break multiple paths, and Defender for Identity coverage of the full Tier 0 set, including the Entra Connect servers, detects steps on multiple paths. These are the highest-leverage investments.
- **The open residuals cluster.** RR-02 (local plane signals), RR-03 (token theft against non-CAE apps), and RR-11 (recovery) carry the most residual exposure across the ranked paths. The architectural handback in `threat-model.md` section 9 prioritizes them.

## Sources

Technique data: MITRE ATT&CK Enterprise v19.2, verified against MITRE's official ATT&CK STIX data. Threat-context sources, with publishers, URLs, dates checked, and quality labels, are consolidated in `threat-model.md` section 10. The inline citations in this file refer to those entries.

## Appendix: AP-5 steps 8a and 8b

- **8a, joining the exclusion group.** An account added to `grp-ca-emergency-access` escapes every enforced policy that blocks or restricts sign-in, including baseline MFA (CA-02), legacy authentication blocking (CA-01), the PAW-only rules (CA-04, CA-05), and the risk policies (CA-17, CA-18) (`03-identity-and-access.md` section 5). An owner added to the group is the durable form of the move: owners of a role-assignable group can manage its membership (03 section 5), so after one Tier 0 change an owner can add accounts with no further activation. Unlike a member, an owner gains a permission (management of the group), so that move maps to T1098.003 (Account Manipulation: Additional Cloud Roles). The design has no owners, and an owner change alerts like any other change to the group. The admin groups, `grp-admins-t0` and `grp-admins-t1`, invite the same move in the other direction: removing an admin account from one takes it out of the phishing-resistant and PAW-only policies (CA-03, CA-04, CA-05), so they are role-assignable Tier 0 groups too (ADR-004 decision 6), and `detection-priorities.md` item 20 carries their alert. Deleting an admin group makes that move for every member at once. An owner added to an admin group is the durable form of that removal, able to make it later with no Tier 0 activation, so it maps to T1098.003 for the same reason as an owner of the exclusion group. A role assigned to any of the three groups reaches every member, which is step 8's move (T1098.003) made through the group; the design assigns none of them a role.
- **8b, resetting an emergency account.** A reset of an emergency account's password or authentication methods hands over a permanent Global Administrator that no enforced Conditional Access policy restricts, usable from any device. The same reset on another Tier 0 account yields less, because that account still needs an approved activation from a Tier 0 PAW (CA-04, CA-06).
- **Why these techniques.** 8a is T1556.006 (Modify Authentication Process: Multi-Factor Authentication): ATT&CK's description of it names "excluding users from Azure AD Conditional Access Policies" as a way to disable MFA defenses, and joining the exclusion group does exactly that. T1556.009 (Modify Authentication Process: Conditional Access Policies) describes changing a policy, and no policy changes; no role or permission is added, so T1098.003 (Account Manipulation: Additional Cloud Roles) does not fit; and T1098.007 (Account Manipulation: Additional Local or Domain Groups) covers local or domain groups on Windows, Linux, and macOS, not Entra ID groups. 8b is T1098: the behavior is one account changing another account's credentials to gain its access, which the T1098 description names ("modifying credentials", and modifications that "grant access to additional roles, permissions, or higher-privileged Valid Accounts"). Its sub-techniques each cover a narrower move.
- **What keeps both moves behind Tier 0.** Privileged Authentication Administrator is Tier 0, and the exclusion group is role-assignable with no owners (decisions 1 and 9). Held outside Tier 0, that role would let its holder make move 8b, a route into every Tier 0 account that skips Tier 0's gates. An application that can issue a pass, which the design reads as able to issue one to any user, would open a second route of the same kind, so it is a Tier 0 workload identity, and no application holds such a permission by default (decision 1 and alternative G). Three more routes are closed the same way. Security Administrator, which can change Conditional Access, is Tier 0. So are Application Administrator and Cloud Application Administrator at tenant scope, which can add a credential to any application, Tier 0 applications included. And the admin groups that decide who the PAW-only policies cover are role-assignable (decisions 1, 4, and 6; alternatives H and I). Partner Tier2 Support is never assigned because it too can reset a Global Administrator's password, and SN-02 alerts on any assignment. Other routes are closed because the design never assigns these roles: Partner Tier1 Support, whose definition can update any application's credentials and owners; Windows 365 Administrator, whose definition includes the permission to write the device tag the PAW-only policies read; and External Identity Provider Administrator, whose definition can update the federation property of domains. Domain Name Administrator, which can configure a domain for federation and so make step 7's move, is Tier 0. And every role is checked against the whole Tier 0 scope before its first assignment, whichever system grants it (decisions 1 and 6; alternatives J and K; Consequences; `03-identity-and-access.md` section 4). Both moves therefore need Tier 0 access first, which this path already assumes. On standing paths that access needs no activation or approval: the emergency accounts themselves, Tier 0 workload identities, and anyone holding a credential already added to a Tier 0 application (RR-16).
- **Rows 8a and 8b of the steps table.** For 8a, the Tier 0 access a change needs is, for an administrator, an approved activation; an emergency account or a Tier 0 workload identity granted RoleManagement.ReadWrite.Directory needs no approval, so on those paths the alert is the only control (RR-16). For 8b, the data sources are AuditLogs (password resets and authentication method changes that target an emergency account, a Temporary Access Pass included), then SigninLogs and AADNonInteractiveUserSignInLogs for the sign-in it enables. Resetting a Tier 0 account needs Tier 0 access, for an administrator an approved activation, which alerts (SN-02); the change alerts whoever makes it (SN-07), and so does every emergency-account sign-in (SN-06). Two paths need no approval, and on them the alert is the only control (RR-16): one emergency account resetting the other, and a Tier 0 workload identity holding a pass-issuing permission issuing a pass to an emergency account.
- **Alerting and validation.** Alerting for steps 8, 8a, and 8b: `detection-priorities.md` items 10, 19, and 20 (SN-02, SN-06, SN-07); validation: `purple-team-plan.md` PX-17, PX-19, and PX-20.
- **The clinical Kerberos path.** The phase-3 recommendation to keep the clinical Kerberos path off the cloud is in `threat-model.md` section 9.
