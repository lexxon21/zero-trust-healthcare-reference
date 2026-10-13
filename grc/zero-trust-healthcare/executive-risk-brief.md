# Contoso Regional Health (fictional): executive risk brief

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

**From:** the CISO (fictional role). **To:** the governing board and executive leadership. **Date:** 2026-10-13.

## 1. Bottom line

Ransomware that stops clinical systems ([R-03](risk-register.md#3-register)) is Contoso's top risk, and the only one still rated Critical with every designed control in place, because recovery is specified but neither designed nor tested. The largest available reduction is recovery built to [ADR-009](../../architecture/zero-trust-healthcare/adr/ADR-009-recovery-requirements.md) and proven by restore tests; until then, no estimate of how long clinical systems would stay down rests on evidence. Next comes blocking traffic between workstations, which the threat model calls the cheapest, highest-value control against ransomware spreading between them. Section 4 asks for seven decisions.

## 2. Top risks

Ordered by the [risk register](risk-register.md)'s residual score (likelihood x impact, 1 to 5 each, assuming the 36-month target state works as designed), ties by the threat model's rank. For context, the FBI's Internet Crime Complaint Center logged 460 ransomware complaints related to the Healthcare and Public Health sector in 2025 (filed complaints, not all incidents; [2025 Internet Crime Report](https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf), p. 16).

| Risk | Inherent to residual | What it means for Contoso | Owner |
|---|---|---|---|
| [R-03](risk-register.md#4-risk-detail) Ransomware that stops clinical systems ([AP-4](../../threat-models/zero-trust-healthcare/attack-paths.md#ap-4-ransomware-against-clinical-operations), ranked first) | 25 Critical to 20 Critical | Encryption can take the EHR, PACS, laboratory, and pharmacy systems down at every site at once, for weeks rather than hours, leaving care on downtime procedures ([playbook 3.1](../../detections/zero-trust-healthcare/playbooks/ir-ransomware.md#31-preparation-checks-standing-work-before-any-incident)). Data taken before encryption stays taken; neither a restore nor a payment changes the breach analysis ([playbook 6.6](../../detections/zero-trust-healthcare/playbooks/ir-ransomware.md#66-executive-decision-the-ransom-demand-rd15)). | CISO |
| [R-01](risk-register.md#4-risk-detail) Session theft against cloud and EHR browser access ([AP-1](../../threat-models/zero-trust-healthcare/attack-paths.md#ap-1-adversary-in-the-middle-phishing-steals-a-live-session-to-ephi), ranked second) | 20 Critical to 16 High | A phishing proxy captures a live session to patient records. Phishing-resistant sign-in makes that harder, but a session stolen after sign-in to the EHR browser path lasts until the EHR's own timeout, and nothing in the design prevents that theft ([RR-03](../../architecture/zero-trust-healthcare/02-reference-architecture.md#13-what-this-architecture-does-not-solve)). | Identity Engineering lead |
| [R-04](risk-register.md#4-risk-detail) Compromised partner tenant reaches the EHR or an imaging modality ([AP-3](../../threat-models/zero-trust-healthcare/attack-paths.md#ap-3-compromised-partner-tenant-reaches-the-ehr-or-an-imaging-modality-through-the-vendor-broker), ranked fourth) | 20 Critical to 15 High | Contoso accepts a partner's sign-in claim (RR-06), so a stolen vendor or outsourcer account passes Contoso's MFA requirement; a Contoso approver of each time-limited, recorded session then stands between it and ePHI, and a deceived approver is the remaining gap. | Director of Clinical Applications |
| [R-05](risk-register.md#4-risk-detail) Tier 0 compromise through the hybrid identity boundary ([AP-5](../../threat-models/zero-trust-healthcare/attack-paths.md#ap-5-hybrid-identity-tier-0-compromise-via-the-entra-connect-sync-boundary), ranked fifth) | 20 Critical to 15 High | Control of the directories is control of every account (RR-07), so every store of ePHI is exposed whether or not restores succeed. | CISO |
| [R-02](risk-register.md#4-risk-detail) Help-desk MFA enrollment fraud followed by payment diversion ([AP-2](../../threat-models/zero-trust-healthcare/attack-paths.md#ap-2-help-desk-social-engineering-then-revenue-cycle-payment-diversion), ranked third) | 16 High to 12 High | A caller talks the help desk into registering an attacker's sign-in method, then uses the mailbox to divert payer or payroll payments. The residual assumes a finished phishing-resistant rollout and help-desk identity checks that hold; until the rollout finishes and a tabletop exercise shows the checks holding, the threat model rates this path High likelihood. | Service Desk Manager |

## 3. Recommended investments, in priority order

Ranked by risk reduction, not schedule. The repository states no budget figures, work-package durations, or staffing levels, so none appear here.

1. **Recovery that survives the attack ([ADR-009](../../architecture/zero-trust-healthcare/adr/ADR-009-recovery-requirements.md#decision); R-03, R-05).** Complete the applications and data criticality analysis, which triggers the recovery design; design to ADR-009's four requirements (immutable and offline copies, isolation from production Tier 0 so that no production credential can delete or alter a copy, restore tests with evidence, and Tier 0 monitoring); then test restores. Recovery is the [register](risk-register.md#3-register)'s biggest lever on R-03's impact, yet AP-4's impact falls one band at most, and only for data sets whose copies are shown to meet ADR-009, including a passing restore test ([TM-A1](../../threat-models/zero-trust-healthcare/threat-model.md#6-assumptions-this-model-depends-on)). ADR-009's stated [costs](../../architecture/zero-trust-healthcare/adr/ADR-009-recovery-requirements.md#consequences): a second administrative domain, growing storage, slow restores from offline copies, and clinical and infrastructure time for restore tests.
2. **Block traffic between workstations ([WP-2.1](../../architecture/zero-trust-healthcare/05-ztmm-maturity-roadmap.md#phase-2-segmentation-and-enclaves-months-9-to-24); R-03).** Host firewall policy refuses inbound SMB, RDP, WinRM, and RPC from peer workstations ([04 section 6](../../architecture/zero-trust-healthcare/04-segmentation.md#6-east-west-controls)), the control [AP-4](../../threat-models/zero-trust-healthcare/attack-paths.md#ap-4-ransomware-against-clinical-operations) calls the cheapest and highest-value. It waits only on the logging baseline (WP-0.5), so it can start when phase 2 opens at month 9, alongside the end of phase 1.
3. **Finish phase 1 identity work ([WP-1.1, WP-1.2, and WP-1.4](../../architecture/zero-trust-healthcare/05-ztmm-maturity-roadmap.md#phase-1-identity-and-privileged-access-months-3-to-12); R-05, R-01, R-04, R-02).** That means cloud-only administrator accounts with eligible-only PIM on privileged access workstations, phishing-resistant MFA for administrators, remote staff, and vendors, and every remote vendor session through the recorded broker.
4. **Fund the smart card badge work as designed ([WP-2.7 and WP-3.1](../../architecture/zero-trust-healthcare/05-ztmm-maturity-roadmap.md#5-critical-path-and-dependencies); [RR-02](../../architecture/zero-trust-healthcare/02-reference-architecture.md#13-what-this-architecture-does-not-solve)).** It is the roadmap's most expensive item and the most likely to be cut. Its fallback, FIDO2 keys, is also phishing-resistant but puts a cloud dependency at the point of care and would revise [ADR-003](../../architecture/zero-trust-healthcare/adr/ADR-003-phishing-resistant-mfa-and-clinical-badges.md) and ADR-008.

## 4. Decisions requested

Residual risk reasoning is from [02 section 13](../../architecture/zero-trust-healthcare/02-reference-architecture.md#13-what-this-architecture-does-not-solve).

| Decision | Recommendation | Why | Decides |
|---|---|---|---|
| Fund recommendation 1 (or accept RR-11, recovery unverified) and recommendation 4 | Reject RR-11; fund both | A requirement is not a capability, so R-03 stays Critical until restore tests produce evidence; badges keep shared-workstation sign-in working without internet | Proposed: Chief Executive Officer and CFO, with board oversight, advised by the decision owners of ADR-009, ADR-003, and ADR-008 |
| Start WP-2.1 when phase 2 opens | Approve | Cheapest, highest-value control on the top-ranked path | Proposed: CISO and VP Infrastructure, through the Zero Trust steering group (WP-0.1) |
| Accept RR-02: the on-site clinical plane evaluates fewer signals | Accept for the target state with its partial mitigations, badges included; revisit if badges are descoped | Failing closed on site would stop clinical systems in an internet or identity outage ([ADR-008](../../architecture/zero-trust-healthcare/adr/ADR-008-clinical-continuity-failure-modes.md#alternatives-considered), alternative B) | ADR-008's decision owners: CISO, Chief Medical Information Officer, Chief Nursing Officer, VP Infrastructure, Emergency Management lead |
| Accept RR-16: emergency access accounts and Tier 0 workload identities hold standing Tier 0 access that no approval gates | Accept if note 4's partial mitigations operate, including the alerts on both and the emergency accounts' 90-day checks | Emergency access must work when normal gates fail, and an application permission is a standing grant outside PIM; the alert is the control | ADR-004's decision owners: CISO, VP Infrastructure, Identity Engineering lead |
| RR-01: insider misuse of EHR access ([R-09](risk-register.md#3-register), 12 High, unchanged) | Do not count it as addressed; sponsor EHR privacy monitoring outside this program | Zero Trust decides whether a session may exist, not whether each record lookup is appropriate | Privacy Officer |
| Accept RR-12: supplier compromise ([R-11](risk-register.md#3-register), 12 High) | Accept once contracts, third-party monitoring, and narrow integrations are in place | Contoso cannot enforce controls inside a supplier | Compliance Officer |
| Name the ransom decision group now ([RD15](../../detections/zero-trust-healthcare/playbooks/ir-ransomware.md#66-executive-decision-the-ransom-demand-rd15)) | Agree its members, advisers, and how it records its decision | The playbook frames the payment decision with no recommendation; neither does this brief | Chief Executive Officer or delegate, advised by counsel, with the governing board as Contoso's governance documents set |

Board review of these decisions relates to NIST CSF 2.0 GV.OV-01 (strategy outcomes reviewed to adjust strategy and direction), and the accept or reject calls to GV.RM-02 (risk appetite and risk tolerance statements).

## 5. What this brief is not

- **Not a deployment.** A reference design for a fictional organization: nothing is deployed or tested, and every detection rule is an untested template.
- **Not a risk analysis.** It is not a HIPAA Security Risk Analysis under 45 CFR 164.308(a)(1)(ii)(A) of any real entity.
- **Not measured data.** Its ratings are the register's illustrative judgments ([register section 1](risk-register.md#1-purpose-and-limits)); residual scores describe intent, not evidence.

## Sources

| Title | Publisher | URL | Date checked | Quality |
|---|---|---|---|---|
| The NIST Cybersecurity Framework (CSF) 2.0, NIST CSWP 29 (Appendix A: GV.OV-01, GV.RM-02) | NIST | https://doi.org/10.6028/NIST.CSWP.29 | 2026-10-13 | primary |
| 45 CFR 164.308(a)(1)(ii)(A), risk analysis, read through the eCFR versioner API at point in time 2026-09-30 | Office of the Federal Register, eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308 | 2026-10-13 | primary |
| Internet Crime Report 2025 (2025 IC3 Annual Report), p. 16, chart "Cyber Threats to Critical Infrastructure" (the 460 figure is the chart's ransomware value for the Healthcare and Public Health sector) | Federal Bureau of Investigation, Internet Crime Complaint Center | https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf | 2026-10-13 | primary |

Every other statement comes from the companion documents linked in the text.
