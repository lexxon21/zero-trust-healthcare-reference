# ADR-002: Per-app access through an application proxy and ZTNA replaces user VPN

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

| Field | Value |
|---|---|
| Status | Accepted (reference design) |
| Date | 2026-10-03 |
| Decision owners (fictional roles) | CISO, VP Infrastructure, Director of Clinical Applications |
| Scope | Remote access by the workforce, affiliated physicians, vendors, and the revenue-cycle outsourcer |
| Related | `04-segmentation.md` section 5, ADR-001, ADR-004, ADR-005, ADR-008 |

## Context

Remote users at Contoso Regional Health (fictional) connect today through VPN with MFA, which grants network-level reach after one authentication. The populations differ:

- Remote workforce on managed laptops.
- Affiliated physicians on personal devices.
- EHR and biomedical vendors needing privileged sessions.
- An outsourcer working in EHR billing queues.

Verified product facts (checked 2026-10-03) shape the options:

- **Licensing.** Microsoft Entra application proxy is included with Entra ID P1 and P2. It publishes on-premises web apps with pre-authentication, Conditional Access, and Kerberos constrained delegation SSO to Integrated Windows Authentication apps. Microsoft Entra Private Access is not included in Microsoft 365 E5 or Entra ID P2; it is sold standalone or in the Microsoft Entra Suite, and Microsoft 365 E7 includes it (checked 2026-10-04).
- **Client required.** Private Access traffic can only be captured by the Global Secure Access client. Remote networks cannot use the Private Access profile, so agentless devices cannot use it.
- **Client limits.**
  - The iOS and Android clients ship inside Defender for Endpoint, which does not support shared iOS or Android devices.
  - The Windows client does not support concurrent sessions, so it cannot run on multi-session hosts.
  - The client tunnels IPv4 only.
- **Guest access is preview.** Microsoft's Known Limitations page titles its section on Global Secure Access for B2B guest users "B2B guest access (preview) limitations" (checked 2026-10-04).
- **Kerberos SSO publishes the domain controllers.** Kerberos SSO through Private Access requires publishing domain controllers as a private resource (ports 88, 123, 135, 389, 445, 464, 636, 3268, 3269, and 49152 to 65535).

## Decision

1. **Web apps** go through `PEP-APP-PROXY`, with pre-authentication and Conditional Access (CA-07, CA-08). That includes the EHR browser interface and legacy web apps that use Integrated Windows Authentication, which reach their servers through Kerberos constrained delegation.
2. **Non-web private apps** go through per-app ZTNA (`PEP-ZTNA-CLIENT`, `PEP-ZTNA-BROKER`, `PEP-ZTNA-CONNECTOR`), from compliant managed devices only (CA-11). This covers the EHR full client, the PACS viewer, and legacy thick clients. Microsoft Entra Private Access is the example implementation and a licensed add-on; a third-party ZTNA service satisfies the same logical role.
3. **Unmanaged devices** get browser sessions through `PEP-APP-PROXY` with `PEP-SESSION-PROXY` in-session controls (CA-10), and no network-level access of any kind.
4. **Vendors** use `PEP-VENDOR-BROKER` with just-in-time activation (ADR-004), not ZTNA, until B2B ZTNA is generally available and evaluated.
5. **App segments** are defined per application by host and port. Broad subnet segments are allowed only during migration, with an expiry date, because a subnet-wide segment is a VPN by another name.
6. **The domain controller segment** needed for Kerberos SSO is assigned only to the groups that use those apps, limited to the domain controllers in the connectors' AD site, and watched by Defender for Identity.
7. **User VPN is retired** once coverage is complete. Site-to-site tunnels for the WAN stay. The only remaining user-style VPN is the dormant emergency administrative path in ADR-008.

## Alternatives considered

### A. Keep VPN, strengthened with phishing-resistant MFA and host checks (rejected)

Better authentication does not change what happens after authentication: the user gets network reach, and lateral movement follows. An internet-facing concentrator is also a listening service that has to be patched on the attacker's schedule, while connectors only make outbound connections. Per-app Conditional Access with device compliance cannot be expressed in a network tunnel.

### B. ZTNA for everyone, including unmanaged devices and vendors (rejected)

The ZTNA client requires a device Contoso can manage and check, so unmanaged devices are excluded by policy. Guest access through Global Secure Access is in preview, and vendor sessions need approval and recording, which the broker provides.

### C. A third-party ZTNA service instead of Microsoft's (viable, deferred)

The logical design is identical. The choice is a cost, integration, and contract decision, made at the licensing gate in phase 1 (WP-1.5 in `05-ztmm-maturity-roadmap.md`).

### D. Virtual desktops for all remote access (rejected as the default)

They are costly at Contoso's scale and still need their own access path. The Global Secure Access Windows client cannot run on multi-session hosts. Virtual desktops stay available for specific roles that need a full desktop.

## Consequences

Positive:

- No remote user receives network-level reach.
- Every remote request is evaluated per application against identity, device compliance, and risk.
- Connectors expose no inbound listener.
- On the Windows client, Universal CAE can force reauthentication or drop the tunnel after a critical event.

Negative and residual:

- Private Access is an incremental license (A-04).
- Connector hosts become footholds behind the zone boundary (RR-08). They are hardened and Tier 1 administered, with one connector group per zone.
- Kerberos SSO gives connected clients a network path to Tier 0 services (RR-09).
- Shared mobile devices cannot use the Global Secure Access client; they use the on-site path only.
- The client tunnels IPv4 only.
- An application inventory and per-app segment definitions are required before cutover.
- When the cloud broker is unavailable, remote non-web access fails closed (ADR-008).

## Compliance drivers

| Framework | Identifier | Why it matters here |
|---|---|---|
| HIPAA | 45 CFR 164.312(a)(1), access control (standard) | Per-application authorization replaces network-level access |
| HIPAA | 164.312(d), person or entity authentication (standard, required) | Phishing-resistant authentication before any remote session |
| HIPAA | 164.312(e)(1), transmission security (standard); 164.312(e)(2)(ii), encryption (addressable) | Encrypted per-app tunnels and TLS |
| PCI DSS v4.0.1 | Requirement 8.4.3 (design rule) | No remote path into the CDE exists. Any future path would need MFA. |
| NIST CSF 2.0 | PR.IR-01, PR.AA-05, PR.DS-02 | Network protection, least privilege, data in transit |

## ZTMM mapping

Networks: Network Segmentation, Network Traffic Management. Applications and Workloads: Application Access, Accessible Applications. Identity: Access Management.

## Revisit when

- Global Secure Access for B2B guests becomes generally available.
- Private Access licensing or packaging changes.
- The EHR vendor's support contract comes up for renewal.
- The EHR moves to a vendor-hosted service.

## Sources

| Title | Publisher | URL | Date checked | Quality |
|---|---|---|---|---|
| What is Global Secure Access? | Microsoft Learn | https://learn.microsoft.com/en-us/entra/global-secure-access/overview-what-is-global-secure-access | 2026-10-03 | Primary |
| Microsoft Entra licensing | Microsoft Learn | https://learn.microsoft.com/en-us/entra/fundamentals/licensing | 2026-10-04 | Primary |
| Publish on-premises apps with Microsoft Entra application proxy | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/app-proxy/overview-what-is-app-proxy | 2026-10-03 | Primary |
| Kerberos Constrained Delegation for single sign-on to your apps with application proxy | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/app-proxy/how-to-configure-sso-with-kcd | 2026-10-03 | Primary |
| Use Kerberos for single sign-on (SSO) with Microsoft Entra Private Access | Microsoft Learn | https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-configure-kerberos-sso | 2026-10-03 | Primary |
| Learn about the Global Secure Access clients for Microsoft Entra Private Access and Microsoft Entra Internet Access | Microsoft Learn | https://learn.microsoft.com/en-us/entra/global-secure-access/concept-clients | 2026-10-04 | Primary |
| Install the Global Secure Access Client for iOS | Microsoft Learn | https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-install-ios-client | 2026-10-04 | Primary |
| Install the Global Secure Access Client for Android | Microsoft Learn | https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-install-android-client | 2026-10-04 | Primary |
| Known Limitations for Global Secure Access | Microsoft Learn | https://learn.microsoft.com/en-us/entra/global-secure-access/reference-current-known-limitations | 2026-10-04 | Primary |
| Learn about Global Secure Access external user access | Microsoft Learn | https://learn.microsoft.com/en-us/entra/global-secure-access/concept-external-user-access | 2026-10-03 | Primary |
| Learn about Universal Continuous Evaluation | Microsoft Learn | https://learn.microsoft.com/en-us/entra/global-secure-access/concept-universal-continuous-access-evaluation | 2026-10-03 | Primary |
| Conditional Access app control | Microsoft Learn | https://learn.microsoft.com/en-us/defender-cloud-apps/proxy-intro-aad | 2026-10-03 | Primary |
| 45 CFR 164.312 | eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312 | 2026-10-03 | Primary |
