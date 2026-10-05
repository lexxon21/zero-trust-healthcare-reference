# ADR-001: Two decision planes and the SP 800-207 approaches used

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

| Field | Value |
|---|---|
| Status | Accepted (reference design) |
| Date | 2026-10-03 |
| Decision owners (fictional roles) | CISO, Chief Medical Information Officer, VP Infrastructure, Director of Clinical Engineering |
| Scope | Contoso Regional Health (fictional): all subjects and resources |
| Related | `02-reference-architecture.md` sections 2 to 5, ADR-002, ADR-006, ADR-008 |

## Context

NIST SP 800-207 describes a logical policy engine and policy administrator that decide access requests, with policy enforcement points in the data path. Contoso's subjects do not fit one model:

- **Identity-capable subjects.** Workforce, affiliated physicians, partners, administrators, and workloads can carry an identity and use modern authentication.
- **Medical devices.** About 6,000 devices cannot run an agent or present a user identity.
- **Legacy apps.** Some clinical applications need Kerberos or NTLM and cannot federate.
- **Care continuity.** On-site clinical work has to continue when a hospital's internet circuit or the cloud identity service is unavailable.

Microsoft documents the limits of cloud identity resilience. During a Microsoft Entra ID outage, the backup authentication service:
- Issues tokens for existing sessions only.
- Does not serve new sessions or guest users.
- Does not evaluate the methods that authentication strengths require.

A shift change during an outage is all new sessions.

## Decision

1. **Enhanced identity governance (SP 800-207 Section 3.1.1)** is the primary approach for every subject that can carry an identity. `PE-IDENTITY` is the policy engine for cloud, federated, remote, external, privileged, and workload access; Microsoft Entra Conditional Access implements it in the scenario stack.
2. **Micro-segmentation (Section 3.1.2)** applies where identity cannot carry the decision: medical devices, the legacy enclave, the CDE, and per-application datacenter segments. `PE-NETWORK` decides network admission and segment placement.
3. **Network infrastructure and software defined perimeters (Section 3.1.3)** take the form of per-app ZTNA for remote access to non-web private apps (ADR-002).
4. **On-site clinical access from clinical workstations in `Z-CLIN-USER` runs on a local clinical plane:**
   - `IDS-AD` authenticates with Kerberos.
   - `PE-NETWORK` admits the device.
   - `PEP-NET-ZONE` enforces the network path.
   - The EHR applies its own roles.

   This plane keeps working without internet access or Entra ID. Its failure behavior is defined in ADR-008. On-site `Z-CORP` laptops stay on the cloud identity plane (ADR-008).
5. **One policy intent for both planes.** Both are authored from one access matrix and one asset classification (`PIP-ASSET-INV`), and are reviewed together every quarter.

## Alternatives considered

### A. One cloud policy engine in the path of every request (rejected)

All on-site clinical access would be federated through Entra ID or routed through ZTNA. This puts the internet circuit and the cloud identity service in the critical path of medication administration. The backup authentication service does not create new sessions, so the first sign-ins of a shift would fail during an outage. Patient safety outranks the gain in signal richness.

### B. Network-centric Zero Trust only (rejected)

Micro-segmentation would be the primary model, with VPN plus NAC kept for remote access. It does nothing about identity attacks on cloud and remote paths, such as phishing, token theft, and consent abuse. It also gives no per-request evaluation of device health or risk for applications.

### C. Identity-centric only (rejected)

This leaves about 6,000 medical devices outside the architecture. The CISA ZTMM v2.0 itself states that it does not address challenges specific to operational technologies or certain classes of internet of things devices.

### D. A separate policy orchestration platform spanning identity and network (deferred)

It would add a Tier 0 system and licensing cost. The coordination problem it solves is handled for now by one access matrix and one asset classification. Revisit if the planes drift apart in practice.

## Consequences

Positive:

- Clinical care continues through a cloud or internet loss at a hospital.
- The design relies on capabilities the scenario already licenses for its primary decisions.
- Each subject type is governed by an enforcement point that can actually see it.

Negative and residual:

- There are two planes to keep consistent. Drift is a real risk; it is controlled through the shared access matrix and the quarterly joint review.
- The local plane evaluates fewer signals, with no Conditional Access risk evaluation for on-site EHR sign-ins (RR-02 in `02-reference-architecture.md`).
- On-premises Active Directory stays Tier 0 and sits in the critical path of clinical care (RR-07).

## Compliance drivers

| Framework | Identifier | Why it matters here |
|---|---|---|
| HIPAA | 45 CFR 164.308(a)(7)(ii)(C), emergency mode operation plan (required) | Critical processes must continue while protecting ePHI in emergency mode |
| HIPAA | 164.308(a)(7)(ii)(E), applications and data criticality analysis (addressable) | Identifies which clinical applications must survive outages |
| HIPAA | 164.312(a)(1), access control (standard); 164.312(d), person or entity authentication (standard, required) | Both planes must authenticate and authorize |
| NIST CSF 2.0 | PR.AA-05, PR.IR-01, PR.IR-03, GV.OC-04 | Access policy, network protection, resilience, critical services others depend on |

## ZTMM mapping

Identity: Authentication, Access Management. Networks: Network Segmentation, Network Resilience. Governance (cross-cutting).

## Revisit when

- The EHR platform supports continuous access evaluation or token binding.
- Microsoft documents a user's first FIDO2 sign-in, without internet connectivity, on a shared Windows device (ADR-003).
- Cloud identity resilience extends to new sessions and to authentication strength evaluation.
- Two consecutive quarterly reviews find drift between the planes.

## Sources

| Title | Publisher | URL | Date checked | Quality |
|---|---|---|---|---|
| NIST SP 800-207, Zero Trust Architecture | NIST | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf | 2026-10-03 | Primary |
| Zero Trust Maturity Model Version 2.0 | CISA | https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf | 2026-10-03 | Primary |
| Resilience defaults for Microsoft Entra Conditional Access | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/conditional-access/resilience-defaults | 2026-10-03 | Primary |
| 45 CFR 164.308 and 164.312 | eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C | 2026-10-03 | Primary |
| The NIST Cybersecurity Framework (CSF) 2.0, NIST CSWP 29 | NIST | https://doi.org/10.6028/NIST.CSWP.29 | 2026-10-03 | Primary |
