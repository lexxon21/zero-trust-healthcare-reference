# ADR-005: Legacy Kerberos and NTLM applications in a gateway-enforced enclave

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

| Field | Value |
|---|---|
| Status | Accepted (reference design) |
| Date | 2026-10-03 |
| Decision owners (fictional roles) | CISO, Director of Clinical Applications, VP Infrastructure |
| Scope | Clinical applications that require Kerberos or NTLM and cannot federate (`RES-LEGACY`) |
| Related | `04-segmentation.md` section 4, ADR-001, ADR-002, ADR-008 |

## Context

Some of Contoso Regional Health's (fictional) clinical applications authenticate only with Kerberos or NTLM. They cannot take part in Conditional Access directly, and some cannot be replaced quickly because the vendor controls the upgrade path. Verified facts (checked 2026-10-03):

- **NTLM is deprecated.** Microsoft deprecated all NTLM versions (LANMAN, NTLMv1, and NTLMv2) in June 2024. NTLMv1 is removed starting with Windows 11 version 24H2 and Windows Server 2025.
- **NTLMv1 enforcement is changing now.** Per KB5066470, the BlockNTLMv1SSO default changes from audit to enforce in October 2026.
- **SP 800-207 has a model for this.** It describes the enclave-based deployment (Section 3.2.2) as suiting enterprises with legacy applications or on-premises data centers that cannot place a gateway in front of each resource.
- **Remote Kerberos needs the domain controllers published.** Microsoft Entra Private Access can provide Kerberos SSO to on-premises resources, but only if domain controllers are published to clients as a private resource.
- **Kerberos gating on domain controllers exists, with limits.** Microsoft Entra Private Access for Active Directory Domain Controllers (generally available January 2026) uses a sensor on each domain controller. The sensor can apply Conditional Access to Kerberos requests for configured service principal names. It accepts Kerberos requests only from connector addresses, installs in audit mode, and offers a break glass mode. Microsoft's documentation describes Kerberos interception. It does not describe gating NTLM.

## Decision

1. **The enclave.** Legacy applications move into `Z-LEGACY` behind `PEP-ENCLAVE-GW`, a dedicated firewall context that is the only way in. Allowed sources: clinical workstations in `Z-CLIN-USER` on application ports, the paired connector group, and `Z-MGMT` for administration. Enclave egress is limited to authentication in `Z-T0` and listed interfaces in `Z-CLIN-APP`.
2. **Remote web apps** that use Integrated Windows Authentication are published through `PEP-APP-PROXY` with Kerberos constrained delegation.
3. **Remote non-web apps** are reached through ZTNA with Kerberos SSO. The domain controller segment that requires is limited to the groups that use enclave apps and to the domain controllers in the connectors' AD site, and is monitored by Defender for Identity.
4. **NTLM is audited per application, then restricted.** Exceptions have an owner and an expiry date. Service accounts use AES Kerberos encryption types, and group managed service accounts where the application supports them.
5. **Every legacy application has a retirement plan:** an owner, a replacement or upgrade path, and a target date. Leaving the enclave is the goal.

## Alternatives considered

### A. Leave legacy applications on the general clinical network (rejected)

Any compromised workstation could reach them directly, with no gateway and no single place to log access. Weak protocols would stay exposed to the whole clinical network.

### B. Replace or upgrade every legacy application before starting Zero Trust work (rejected)

Vendors set the timelines, so this could take years. Containment now does not prevent replacement later.

### C. Gate Kerberos for these applications with Private Access for Active Directory Domain Controllers (rejected for clinical SPNs; considered for administrative SPNs)

The sensor accepts Kerberos requests only from connector addresses. On-site clinical workstations would therefore have to route through Private Access to get tickets, which puts the cloud in the path of care (ADR-008). The documentation does not describe NTLM gating. The sensor also adds code to every domain controller and carries a lockout risk that Microsoft addresses with audit mode and a break glass mode. It is listed for phase 3 evaluation on administrative service principal names only (WP-3.7).

### D. A virtual desktop or published application in front of each legacy app (allowed case by case)

Useful where an application cannot be fronted any other way. It is not the default, because it adds a platform to operate and secure.

## Consequences

Positive:

- The blast radius is contained to one enclave with one entry point and one log source.
- Remote users are authenticated and checked for device compliance before they reach the enclave.
- A dated path off NTLM exists ahead of Microsoft's own default changes.

Negative and residual:

- **On-site access to the enclave from `Z-CLIN-USER` still relies on Active Directory authentication** without Conditional Access (RR-02).
- **NTLM restriction can break applications.** Dated exceptions and testing manage this, but each exception is open risk until it expires.
- **Remote Kerberos SSO gives connected clients a network path to domain controllers** (RR-09).

## Compliance drivers

| Framework | Identifier | Why it matters here |
|---|---|---|
| HIPAA | 45 CFR 164.312(d), person or entity authentication (standard, required) | Authentication strength for legacy apps comes from the gateway path and Kerberos |
| HIPAA | 164.312(a)(1), access control (standard) | One controlled entry to the enclave |
| HIPAA | 164.308(a)(1)(ii)(B), risk management (required) | Containment and retirement reduce risk to a reasonable level |
| NIST CSF 2.0 | PR.PS-01 (NTLM restriction as configuration), PR.PS-02 (retirement), PR.IR-01, ID.AM-02, PR.AA-03 | Configuration, software lifecycle, network protection, inventory, authentication |

## ZTMM mapping

Applications and Workloads: Application Access. Networks: Network Segmentation. Identity: Authentication.

## Revisit when

- A vendor ships a release that supports modern authentication.
- Microsoft changes further NTLM defaults.
- Private Access for domain controllers can coexist with a local-first clinical path.

## Sources

| Title | Publisher | URL | Date checked | Quality |
|---|---|---|---|---|
| NIST SP 800-207, Zero Trust Architecture | NIST | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf | 2026-10-03 | Primary |
| Deprecated features in the Windows client | Microsoft Learn | https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features | 2026-10-03 | Primary |
| KB5066470, Upcoming changes to NTLMv1 in Windows 11, version 24H2 and Windows Server 2025 | Microsoft Support | https://support.microsoft.com/en-us/topic/upcoming-changes-to-ntlmv1-in-windows-11-version-24h2-and-windows-server-2025-c0554217-cdbc-420f-b47c-e02b2db49b2e | 2026-10-03 | Primary |
| Use Kerberos for single sign-on (SSO) with Microsoft Entra Private Access | Microsoft Learn | https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-configure-kerberos-sso | 2026-10-03 | Primary |
| Configure Microsoft Entra Private Access for Active Directory Domain Controllers | Microsoft Learn | https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-configure-domain-controllers | 2026-10-03 | Primary |
| Kerberos Constrained Delegation for single sign-on to your apps with application proxy | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/app-proxy/how-to-configure-sso-with-kcd | 2026-10-03 | Primary |
| 45 CFR 164.308 and 164.312 | eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C | 2026-10-03 | Primary |
