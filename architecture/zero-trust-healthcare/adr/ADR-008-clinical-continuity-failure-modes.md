# ADR-008: Clinical continuity: failure modes for each decision plane

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

| Field | Value |
|---|---|
| Status | Accepted (reference design) |
| Date | 2026-10-03 |
| Revised | 2026-10-04 |
| Decision owners (fictional roles) | CISO, Chief Medical Information Officer, Chief Nursing Officer, VP Infrastructure, Emergency Management lead |
| Scope | What every access path does when a component it depends on fails |
| Related | `02-reference-architecture.md` section 10, ADR-001, ADR-002, ADR-003, ADR-006, ADR-009 |

## Context

Zero Trust concentrates decisions in policy engines, and in Contoso Regional Health's (fictional) scenario stack the primary engine is a cloud service. A hospital cannot pause medication administration because an internet circuit or an identity service is down. Verified facts (checked 2026-10-03):

- **The backup authentication service covers existing sessions only.** During a Microsoft Entra ID outage it:
  - Issues tokens for existing sessions.
  - Does not support new sessions or authentication by guest users.
  - Does not evaluate the methods that authentication strengths require.
- **Resilience defaults are a tenant-wide tradeoff.** They are on by default for each Conditional Access policy, and let the backup service rely on data captured at the start of a session. Turning them off blocks access whenever a condition cannot be evaluated. On a policy that targets a group or role, Microsoft notes this reduces resilience for all users in the tenant.
- **Backup-issued sign-ins are identifiable.** Sign-ins served by the backup service show as issued by Microsoft Entra Backup Auth in sign-in logs.
- **HIPAA requires contingency planning:**
  - An emergency mode operation plan (45 CFR 164.308(a)(7)(ii)(C), required).
  - An applications and data criticality analysis (164.308(a)(7)(ii)(E), addressable).
  - An emergency access procedure (164.312(a)(2)(ii), required).

## Decision

Each path has a defined failure behavior:

| Path | Depends on | On failure |
|---|---|---|
| On-site clinical access from `Z-CLIN-USER` to the local-first set (local plane) | Hospital domain controllers (`IDS-AD`), `PE-NETWORK`, `PEP-NET-ZONE`, on-site PKI revocation data, the WAN path to the datacenter | Continues without internet or Entra ID. If the local domain controllers fail, clients fall back to other sites over the WAN. If no domain controller is reachable, or the site loses its WAN path to the datacenter, clinical downtime procedures apply. |
| Cloud apps (Microsoft 365, SaaS) | Entra ID, internet circuit | Existing sessions continue through the backup authentication service; new sessions fail. Resilience defaults stay on. Sign-ins the backup service issued are reviewed afterward. |
| Remote workforce access (application proxy, ZTNA), and on-site `Z-CORP` laptop access to the CA-11 apps (ZTNA) | Entra ID, Microsoft cloud edge, connectors | Fails closed. Remote staff follow downtime procedures, and on-site staff move to `Z-CLIN-USER` workstations. There is no automatic fallback to VPN. |
| Vendor access | Entra ID, `PEP-VENDOR-BROKER` | Fails closed. Urgent vendor work happens on site, or through a Contoso engineer following vendor guidance. |
| Administrative access | Entra ID, PAWs | Fails closed, with three exceptions below |
| Medical device admission | `PE-NETWORK` | Admitted ports keep their last authorized segment. Unknown devices go to `Z-IOMT-ONBOARD`. Never fails open to an unrestricted segment. The chosen NAC platform must be confirmed to support this behavior. |
| Detection and response | `PIP-SIEM`, `PIP-XDR` | Detection gap only. Enforcement does not change. |

**The local-first set.** These paths run on the local plane:

- On-site clinical access from `Z-CLIN-USER` to `RES-EHR`, `RES-PACS`, `RES-LIS`, and `RES-PHARM`.
- The `RES-INTEGRATION` flows that carry orders and results among them. Flows to partners are not in the set.
- The device-to-server flows that feed them (F-08), such as modality to PACS, analyzer to LIS middleware, and dispensing cabinet to the pharmacy system.

The four applications and the integration engine run in the datacenter (A-09) and are reached over the WAN, and device admission depends only on `PE-NETWORK` (table above). None of these paths therefore depends on a hospital's internet circuit or on Entra ID. That holds only while on-site sign-in to these applications authenticates against `IDS-AD`. An application that could sign users in only through Entra ID would put the cloud back in its on-site path.

The set records which paths the architecture keeps local. It is not a criticality ranking. Ranking these applications against one another, and setting their recovery objectives and restore order, belong to Contoso's criticality analysis under 164.308(a)(7)(ii)(E) and to recovery design. This design set states the requirements recovery must meet (ADR-009) but does not design it (A-19, RR-11).

**On-site `Z-CORP` laptops are not in the set.** Their ZTNA client carries the CA-11 apps through the cloud on site as well as remotely, because Intelligent Local Access is not used (alternative G). Microsoft documents that, without it, Private Access sends application and authentication traffic through the service regardless of the user's location. The zone rules give `Z-CORP` no direct path to the EHR full client or PACS viewer ports, and `Z-LEGACY` accepts no `Z-CORP` source (`04-segmentation.md` section 2), so those apps are reached from `Z-CORP` only through CA-11. During an internet or Entra ID outage at a hospital they fail closed on the laptops, and staff who need them move to `Z-CLIN-USER` workstations under downtime procedures. The design does not depend on how the laptops' tunneled traffic, including Kerberos to the published domain controller segment, behaves during the outage.

The three administrative exceptions:

1. **Tenant emergency access accounts** (`03-identity-and-access.md` section 5). They are for when Entra ID is up but normal admin access is broken.
2. **Sealed on-premises AD recovery credentials.** For recovering Active Directory under incident command.
3. **A dormant emergency administrative path.** A VPN service that is disabled by default.
   - Enabling it requires two Tier 0 approvers under incident command.
   - Connections are accepted only from Tier 0 PAWs.
   - Authentication uses certificates validated on premises, because Entra ID may be the component that failed.
   - Every use is logged and reviewed, and credentials are rotated afterward.

Automation boundaries:

- **Identity actions.** Automated identity responses (revoking sessions, disabling an account) are allowed for high-confidence incidents. Each one includes a clinical notification step, so unit leadership can move affected staff onto downtime procedures. Accounts whose automatic suspension would stop clinical work, such as service accounts that clinical interfaces depend on, are excluded from automatic disable in attack disruption. Each such exclusion has an owner and an expiry (P-5), and the identity responder decides containment for those accounts instead.
- **Device actions.** Automated device containment is allowed only for devices that are not medical devices. Medical devices follow the clinical safety gate (`04-segmentation.md` section 3). Automatic attack disruption has to be configured for this boundary to hold. Microsoft documents that it can contain the IP address of a device that is not onboarded to Defender for Endpoint, and medical devices are not onboarded. The address ranges of the medical device segments are therefore configured as attack disruption IP exclusions. Each exclusion has an owner and an expiry (P-5), and a medical device involved in an attack goes to the clinical safety gate for a human decision.

Failure-mode drills with clinical participation run twice a year (example cadence). Results feed the HIPAA contingency plan.

## Alternatives considered

### A. Fail open when the identity service is unreachable (rejected)

Disabling enforcement during an outage hands an attacker the easiest possible window, and outages can be induced.

### B. Fail closed everywhere, including on-site clinical access (rejected)

An internet or identity outage would stop clinical systems. That is a patient-safety failure, and it would also produce the shadow workarounds that undermine every other control.

### C. Rely on the cloud provider's resilience alone (rejected)

It does not cover two cases:
- The backup service creates no new sessions and does not evaluate authentication strengths.
- Nothing in the cloud helps when a hospital's own internet circuit is down.

### D. Turn off resilience defaults so evaluation stays strict during outages (rejected for workforce policies)

On group- or role-targeted policies, this reduces resilience for every user in the tenant. The design keeps the defaults on, and reviews backup-issued sign-ins afterward instead.

### E. A standing VPN as a general fallback for remote clinicians (rejected)

It would recreate the network-level access that ADR-002 removes, along with a permanently exposed listener.

### F. Keep only the EHR and pharmacy local-first (rejected)

Orders placed in the EHR reach PACS and the LIS through the integration engine, and results come back the same way. An EHR that stays up while imaging and laboratory results are unreachable does not keep care running. The set therefore covers all four applications and the flows among them.

### G. Intelligent Local Access, so that on-site `Z-CORP` laptops reach the CA-11 apps directly (rejected for now)

Intelligent Local Access lets the ZTNA client detect the corporate network with DNS probes and send selected Private Access apps directly instead of through the cloud. It was rejected for two reasons:

- **It needs a direct network path** from `Z-CORP` to the CA-11 app ports. With that path open, the network no longer forces those sessions through CA-11: a laptop whose client is disabled or bypassed reaches the app ports with Kerberos alone. Without it, the zone rules keep the connector path as the only way in.
- **It does not make the laptops local-first.** Microsoft states that Conditional Access policies for Private Access apps still apply under it, and describes it as a path optimization, not a separate access model. Access decisions therefore still depend on Entra ID, so it shortens the data path but not the cloud dependency.

The cost of rejecting it is latency for on-site laptop users (see Consequences).

## Consequences

Positive:

- Care continues through cloud and internet outages.
- Every path has an explicit, testable failure behavior instead of an accidental one.

Negative and residual:

- **The local plane is weaker in signals** (RR-02).
- **The dormant emergency path is attack surface,** even while disabled (RR-10).
- **Downtime procedures create unmanaged copies of ePHI** (RR-13).
- **Drills cost clinical time.**
- **During an outage, existing cloud sessions continue without re-evaluating authentication strength.** Review afterward is a detective control, not a preventive one.
- **On-site `Z-CORP` laptops lose the CA-11 apps during an outage, and their on-site traffic to those apps takes the longer path through the cloud edge.** Microsoft describes that backhaul as added latency, the problem Intelligent Local Access exists to solve. Image-heavy PACS work on site belongs on `Z-CLIN-USER` workstations.
- **No automatic attack disruption for medical devices or the excluded accounts.** Defender will not contain them on its own, so containment waits for a human decision. Microsoft cautions that exclusions reduce attack disruption's effectiveness. The design accepts that for patient safety and limits exclusions to the medical device segments and named clinical accounts, each owned and dated.

## Compliance drivers

| Framework | Identifier | Why it matters here |
|---|---|---|
| HIPAA | 45 CFR 164.308(a)(7)(ii)(C), emergency mode operation plan (required) | Defines how clinical access continues while ePHI stays protected |
| HIPAA | 164.308(a)(7)(ii)(E), applications and data criticality analysis (addressable) | The local-first set names the applications the architecture keeps local. Their relative criticality and recovery objectives come from Contoso's own analysis. |
| HIPAA | 164.308(a)(7)(ii)(B), disaster recovery plan (required) | Recovery credentials and the dormant administrative path support restoration. ADR-009 sets the requirements for the copies that restoration depends on. |
| HIPAA | 164.312(a)(2)(ii), emergency access procedure (required) | Emergency administrative access, and the EHR's clinical break-the-glass |
| NIST CSF 2.0 | PR.IR-03, GV.OC-04, RS.MI-01 | Resilience mechanisms, services that patients depend on, containment boundaries |

## ZTMM mapping

Networks: Network Resilience. Data: Data Availability (not rated; recovery requirements are in ADR-009, see `05-ztmm-maturity-roadmap.md`). Automation and Orchestration and Governance (cross-cutting).

## Revisit when

- Microsoft extends backup authentication to new sessions or to authentication strength evaluation.
- Hospitals gain redundant internet circuits and the clinical leadership risk appetite changes.
- The EHR moves to a vendor-hosted service, which would change every assumption in this record.
- Another application in the local-first set moves to a vendor-hosted service, or to sign-in through Entra ID only.
- On-site latency for `Z-CORP` laptop users becomes a clinical or operational problem, or Microsoft documents how Intelligent Local Access behaves when Entra ID or the internet circuit is unavailable (alternative G).

## Sources

| Title | Publisher | URL | Date checked | Quality |
|---|---|---|---|---|
| Resilience defaults for Microsoft Entra Conditional Access | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/conditional-access/resilience-defaults | 2026-10-03 | Primary |
| Manage emergency access admin accounts | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access | 2026-10-03 | Primary |
| Enable Intelligent Local Network | Microsoft Learn | https://learn.microsoft.com/en-us/entra/global-secure-access/enable-intelligent-local-access | 2026-10-04 | Primary |
| Tutorial: Configure Intelligent Local Access | Microsoft Learn | https://learn.microsoft.com/en-us/entra/global-secure-access/tutorial-private-access-intelligent-local-access | 2026-10-04 | Primary |
| Automatic attack disruption in Microsoft Defender | Microsoft Learn | https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption | 2026-10-04 | Primary |
| Exclude assets from automated response in attack disruption | Microsoft Learn | https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption-exclusions | 2026-10-04 | Primary |
| 45 CFR 164.308 and 164.312 | eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C | 2026-10-03 | Primary |
| The NIST Cybersecurity Framework (CSF) 2.0, NIST CSWP 29 | NIST | https://doi.org/10.6028/NIST.CSWP.29 | 2026-10-03 | Primary |
