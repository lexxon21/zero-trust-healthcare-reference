# Contoso Regional Health (fictional): detection pack index

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

The detection pack responds to the 20 behaviors in `threat-models/zero-trust-healthcare/detection-priorities.md` for Contoso Regional Health (fictional). Coverage is partial for some of them and one is a gap, as `coverage-map.md` section 3 records. Item 19 is the emergency access monitoring that `architecture/zero-trust-healthcare/03-identity-and-access.md` section 5 requires (SN-06 and SN-07), and item 20 the admin-group monitoring that 03 sections 3 and 4 require (SN-07). The pack has 22 rules in three parts, two incident response playbooks, and a tabletop exercise kit:

- 9 Microsoft Defender XDR advanced hunting queries, the primary target.
- 7 Microsoft Sentinel analytics queries, used where only Sentinel holds the source (Entra audit and sign-in logs, Office activity, Azure activity).
- 6 Sigma rules for behaviors that Sigma expresses well.
- Two incident response playbooks, one for identity compromise and one for ransomware.
- A tabletop exercise kit for the ransomware playbook.

`coverage-map.md` shows technique-level coverage and the gaps. Technique references use MITRE ATT&CK Enterprise v19.2.

## Status

Every rule is an **untested template**. Each was written against Microsoft's published table schemas, the Sigma specification v2.1.0 (2025-08-02), and MITRE's v19.2 data, and none has been run against any tenant, workspace, or lab. Static checks last ran on 2026-10-05: all 16 KQL queries parse and pass semantic analysis with no errors or warnings (Microsoft's Kusto.Language library 12.4.1, against table schemas built from Microsoft Learn's Defender XDR and Azure Monitor table references), and all six Sigma rules pass `sigma check` (sigma-cli 3.1.0, pySigma 1.5.1). Severity values are suggestions for the reference design, and none of the rules carries tuning derived from real telemetry. `purple-team-plan.md` describes how a rule would move to lab-tested.

## Layout

| Path | Contents |
|---|---|
| `kql/defender-xdr/` | Defender XDR advanced hunting queries. Each except DX-07 is written to work as a custom detection candidate (DX-05 at the every-12-hours or every-24-hours frequency); DX-07 is a daily hunting query only. Their headers explain why |
| `kql/sentinel/` | Sentinel analytics queries: scheduled rules, plus SN-06, written to run as a near-real-time rule or a scheduled one |
| `sigma/` | Sigma rules (status experimental) |
| `playbooks/` | Incident response playbooks for identity compromise and ransomware, aligned to NIST SP 800-61 Rev. 3, and a ransomware tabletop exercise kit |
| `coverage-map.md` | Technique, data source, rule file, status, and attack path, plus the gaps |

Every KQL file starts with the reference label and then the title, status, ATT&CK mapping, data sources, and licensing assumptions. After those come the purpose, logic, known false positives, tuning knobs, response notes (including the clinical safety gate), validation notes, and references.

Every Sigma file opens with comments that carry the reference label, the fictional scenario note, the rule ID and status, the ATT&CK version, the priority item and attack path, a conversion note, tuning, and validation notes. SG-01 to SG-04 also name their companion KQL rule or companion controls; SG-05 and SG-06 state their required telemetry and name their Defender XDR equivalents in the conversion note. The standard Sigma fields carry the description, references, ATT&CK tags, false positives, and level. The Sigma files have no purpose, logic, licensing, or response notes; where a KQL companion exists, its header carries them.

## Rules

| ID | File | Platform | Purpose | Priority item | Attack path | Suggested severity | Status |
|---|---|---|---|---|---|---|---|
| DX-01 | `kql/defender-xdr/dx01-recovery-inhibition-shadow-copy-backup-deletion.kql` | Defender XDR | Built-in utilities deleting shadow copies or the backup catalog, or turning off boot recovery or the Windows Recovery Environment | 1 | AP-4, AP-5 | High | untested template |
| DX-02 | `kql/defender-xdr/dx02-mass-file-rename-encryption-burst.kql` | Defender XDR | One process renaming many files to a new extension across many folders, joined to Defender encryption alerts | 2 | AP-4 | High | untested template |
| DX-03 | `kql/defender-xdr/dx03-entra-session-reuse-new-country-or-client.kql` | Defender XDR | One Entra sign-in session seen from several countries, or from a new network and client, in a short window | 5 | AP-1 | High or Medium | untested template |
| DX-04 | `kql/defender-xdr/dx04-exchange-inbox-rule-hide-or-forward.kql` | Defender XDR | Inbox rules and mailbox settings that forward, delete, or hide mail, scored up for payment keywords | 4 | AP-2, AP-1 | High or Medium | untested template |
| DX-05 | `kql/defender-xdr/dx05-mdi-tier0-credential-access-alert-chain.kql` | Defender XDR | Defender for Identity reconnaissance, Kerberoasting, certificate abuse, and replication alerts chained per source entity | 6, 7, 8, 18 | AP-4, AP-5 | Critical for a chain reaching replication | untested template |
| DX-06 | `kql/defender-xdr/dx06-dcsync-replication-from-non-dc.kql` | Defender XDR | Directory replication from a host that is not a domain controller, or by the wrong account from a sync server | 7 | AP-5 | High | untested template |
| DX-07 | `kql/defender-xdr/dx07-entra-connect-sync-server-anomalies.kql` | Defender XDR | Unexpected logons, never-seen processes, and ADSync scripting on Entra Connect servers, plus sync-identity alerts. The logon and process signals need Defender for Endpoint on those servers, which the design does not yet state | 9 | AP-5 | High | untested template |
| DX-08 | `kql/defender-xdr/dx08-workstation-peer-smb-and-tool-transfer.kql` | Defender XDR | SMB between workstations and executables written over SMB from another workstation (assurance for `PEP-HOST`) | 12 | AP-4 | High | untested template |
| DX-09 | `kql/defender-xdr/dx09-endpoint-protection-tampering.kql` | Defender XDR | Tamper protection events, tamper alerts, and command-line attempts to weaken Defender Antivirus | 13 | AP-4 | High | untested template |
| SN-01 | `kql/sentinel/sn01-mfa-method-change-then-new-country-or-inbox-rule.kql` | Sentinel | MFA method change followed within 24 hours by a new-country sign-in or a mail-hiding or forwarding rule | 3, 4 | AP-2 | High or Medium | untested template |
| SN-02 | `kql/sentinel/sn02-entra-control-plane-and-vendor-activation-changes.kql` | Sentinel | Assignments and activations of the Tier 0 roles in 03 section 4, scoped assignments included, any assignment of a role the design never assigns, Conditional Access, federation, sync, and cross-tenant changes, and off-hours vendor PIM-for-Groups activations | 9, 10, 15 | AP-5, AP-3 | High or Medium | untested template |
| SN-03 | `kql/sentinel/sn03-oauth-consent-and-service-principal-credential-add.kql` | Sentinel | Consent grants with Tier 0 permissions (the table in 03 section 6), mail, or file permissions, and new service principal credentials, including any credential added to a Tier 0 workload identity | 11 | AP-6 | High or Medium | untested template |
| SN-04 | `kql/sentinel/sn04-device-code-and-authentication-transfer-signins.kql` | Sentinel | Device code flow and authentication transfer sign-ins, successful or blocked, outside the CA-20 exception | 16 | AP-1 | High or Medium | untested template |
| SN-05 | `kql/sentinel/sn05-azure-backup-and-restore-point-deletion.kql` | Sentinel | Deletion of Azure backup items, vaults, restore points, or snapshots, and vault security setting changes | 1 | AP-5, AP-4 | High | untested template |
| SN-06 | `kql/sentinel/sn06-emergency-access-account-signin.kql` | Sentinel | Every sign-in by either tenant emergency access account, interactive or non-interactive, successful or failed | 19 | AP-5 (the alerting control at step 8, and the sign-in a step 8b reset enables) | High | untested template |
| SN-07 | `kql/sentinel/sn07-emergency-access-group-and-account-audit-activity.kql` | Sentinel | Every change to `grp-ca-emergency-access`, `grp-admins-t0`, and `grp-admins-t1`, and all audit activity by or on either emergency access account, matched by object ID | 19, 20 | AP-5 (steps 8a and 8b, and step 8a's admin-group form) | High | untested template |
| SG-01 | `sigma/proc_creation_win_recovery_inhibition_utilities.yml` | Sigma, Windows process creation | Portable form of DX-01 | 1 | AP-4 | high | untested template |
| SG-02 | `sigma/proc_creation_win_defender_preference_tampering.yml` | Sigma, Windows process creation | Defender Antivirus protections turned off or exclusions added from PowerShell | 13 | AP-4 | high | untested template |
| SG-03 | `sigma/proc_creation_win_office_spawns_script_interpreter.yml` | Sigma, Windows process creation | Office applications starting script interpreters or proxy binaries after a malicious file is opened | 14 | AP-4 | medium | untested template |
| SG-04 | `sigma/proc_creation_win_domain_trust_and_group_discovery.yml` | Sigma, Windows process creation | Domain trust, domain group, and domain user enumeration with built-in tools | 18 | AP-5, AP-4 | medium | untested template |
| SG-05 | `sigma/win_security_kerberos_rc4_service_ticket_user_spn.yml` | Sigma, Windows Security log | RC4 Kerberos service tickets for user-based service accounts (event 4769) | 6 | AP-4, AP-5 | medium | untested template |
| SG-06 | `sigma/win_security_replication_rights_non_computer_account.yml` | Sigma, Windows Security log | Replication control access rights used by an account that is not a computer account (event 4662) | 7 | AP-5 | high | untested template |

## Playbooks

| File | Purpose | Status |
|---|---|---|
| `playbooks/ir-identity-compromise.md` | Decision points D1 to D12, escalation criteria, branch procedures, and notification steps for identity compromise, with the clinical safety gate, the HIPAA breach assessment, and the card data path. Regulatory clocks come from `grc/zero-trust-healthcare/notification-clocks.md` | Reference playbook, not exercised |
| `playbooks/ir-ransomware.md` | Decision points RD1 to RD17 for ransomware against clinical operations (AP-4): containment under the clinical safety gate, clinical downtime (ADR-008), restoration against the four recovery requirements (ADR-009), the breach analysis that starts from the presumption of breach, card data, law enforcement reporting, and the executive decision on a ransom demand, with no recommendation on payment. Recovery capability stays unverified until restores are tested (RR-11). Regulatory clocks come from `notification-clocks.md` | Reference playbook, not exercised |
| `playbooks/tabletop-ransomware.md` | Facilitator-ready discussion exercise on the AP-4 scenario: objectives tied to 45 CFR 164.308(a)(7)(ii)(D) and to RD1 to RD17, fictional participant roles, ground rules, six timed injects with expected decisions and discussion questions, evaluation criteria, and an after-action report template. Strategy level only: no attack procedures, commands, tools, or payloads | Reference exercise kit, not run |

## Design choices worth noting

- **Detections compensate where prevention has a gap.** DX-03, DX-04, SN-01, and SN-03 cover the behaviors that `detection-priorities.md` says the architecture cannot fully prevent: token theft against apps without continuous access evaluation, help-desk proofing, and OAuth consent.
- **Assurance detections are expected to be quiet.** DX-08 and DX-09 confirm that host east-west blocking and tamper protection are working. A result there is a control gap as much as an intrusion.
- **Emergency access and Tier 0 group alerts have no exclusions.** SN-06 and SN-07 implement items 19 and 20 with no exclusion for scheduled tests or planned work, because a drill should confirm that the alert fires (the rules' notes cite Microsoft's emergency access guidance); tests, approved changes, and administrator joiners and leavers are closed against their records. SN-07 matches by object ID rather than by activity name, so an activity that Microsoft adds or renames cannot open a gap. The requirements are in `03-identity-and-access.md` sections 3 to 5.
- **Raw telemetry backs up product alerts on Tier 0.** DX-05 uses Defender for Identity alerts. DX-06 and SG-06 watch the same behavior in raw events, and DX-06 keeps the Entra Connect connector account visible: it holds replication rights by design, and it is the documented hybrid pivot.
- **Response is bounded by clinical safety.** Every KQL rule's response notes apply the clinical safety gate from ADR-008, directly or through playbook decision point D5, which applies it. The Sigma files carry no response notes. Medical devices are never disconnected automatically, and identity actions against clinical staff include a clinical notification step.
- **No ActionType string is guessed.** Where Microsoft defers ActionType values to the in-portal schema reference, the queries rely on documented columns (DX-02, DX-08) or a term match with a stated caveat (DX-06). The exception is ActionType values that Microsoft documents directly, such as TamperingAttempt and the Exchange rule operations.
