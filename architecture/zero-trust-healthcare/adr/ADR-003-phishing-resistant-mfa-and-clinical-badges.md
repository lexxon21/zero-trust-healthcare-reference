# ADR-003: Phishing-resistant MFA by risk tier, with certificate badges for shared clinical workstations

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

| Field | Value |
|---|---|
| Status | Accepted (reference design) |
| Date | 2026-10-03 |
| Revised | 2026-10-05 |
| Decision owners (fictional roles) | CISO, Chief Nursing Information Officer, Chief Medical Information Officer, Identity Engineering lead |
| Scope | Authentication methods for every workforce, partner, and administrator persona |
| Related | `03-identity-and-access.md` section 2, ADR-001, ADR-004, ADR-008 |

## Context

The current MFA at Contoso Regional Health (fictional) uses phishable methods. Clinicians share workstations across shifts, and fast user switching is a patient-care requirement (A-06). Verified facts (checked 2026-10-03; the FIDO2 and passkey on Windows items re-checked 2026-10-04):

- **What counts as phishing-resistant.** Microsoft's built-in "Phishing-resistant MFA" authentication strength accepts three methods:
  - Windows Hello for Business or platform credential.
  - FIDO2 security keys, now called Passkey (FIDO2).
  - Certificate-based authentication (multifactor).
- **FIDO2 needs the cloud for on-premises SSO.** FIDO2 sign-in to Windows and SSO to on-premises resources depend on a cloud step: Microsoft Entra issues a partial Kerberos ticket along with the Primary Refresh Token, and the client exchanges it with an on-premises domain controller. Microsoft's FAQ for hybrid FIDO2 security key deployment, which covers Entra joined and hybrid joined devices, makes internet connectivity a prerequisite. It says a user's first FIDO2 sign-in needs internet connectivity, and that for later sign-ins "cached sign-in should work" without it. It recommends that devices keep internet access and line of sight to domain controllers for a consistent experience.
- **Certificate-based authentication works with the local domain.** Entra certificate-based authentication supports Windows smart card sign-in on Entra joined and hybrid joined devices. On hybrid joined devices the sign-in must first succeed against Active Directory. It requires managed (not federated) authentication, which A-01 provides.
- **Microsoft's guidance for shared devices.**
  - Intune guidance calls FIDO2 keys ideal for shared devices.
  - Entra persona guidance describes synced passkeys as a good option for frontline workers, with security keys and smart cards as the other phishing-resistant options.
  - The same guidance marks Windows Hello for Business as optional for frontline workers.
  - Microsoft's Intune guidance describes "Microsoft Entra passkey on Windows" as well suited to shared devices. Microsoft announced it as a public preview in March 2026. On 2026-10-04 its feature page carried no preview label, and What's new showed no general availability entry, so its status is unconfirmed. Whatever the status, the feature page says it "doesn't support device sign-in", and that each device needs a separate passkey registration for each account. It therefore cannot sign clinicians in to shared Windows workstations. Its passkey profile also can't enforce attestation, so adopting it for any other use would need a separate passkey profile outside the attestation rule in `03-identity-and-access.md` section 2.
- **Password-replay SSO is not phishing-resistant.** Some clinical single sign-on products authenticate a proximity badge and then replay stored application passwords. That is fast, but it is not phishing-resistant authentication in Entra's terms, and the credential store becomes a target.

## Decision

1. **Phishing-resistant MFA is required for every persona,** in phases (`05-ztmm-maturity-roadmap.md`):
   - Phase 1: administrators, the remote workforce, and vendors.
   - Phase 2: corporate staff and mobile users.
   - Phase 3: shared clinical workstations (badge issuance readiness in phase 2, WP-2.7).
2. **Shared clinical workstations use smart card badges with a PIN-protected certificate issued by `PIP-PKI`.**
   - The badge signs in to Windows against the local domain, so it works without internet.
   - The badge signs in to Entra ID through certificate-based authentication (multifactor), which meets the phishing-resistant strength.
   - Removing the badge locks the session.
3. **Corporate staff on assigned devices** use Windows Hello for Business, with cloud Kerberos trust for on-premises SSO.
4. **Administrators** use device-bound FIDO2 security keys on PAWs. A passkey profile restricts accepted keys by AAGUID and enforces attestation.
5. **Clinicians and affiliated physicians on phones** use a passkey in Microsoft Authenticator. Synced passkeys are not accepted for workforce accounts until phase 3 review.
6. **Onboarding and recovery** use a Temporary Access Pass issued after in-person or sponsor-verified identity proofing, with no phone-only path, and only to register a phishing-resistant method (CA-19).
7. **SMS and voice are disabled** for workforce accounts, except a migration exception group with an owner and an expiry date.

## Alternatives considered

### A. FIDO2 security keys on shared clinical workstations (rejected for hospitals; accepted for administrators)

This is Microsoft's general recommendation for shared devices, and it is a strong method. It is rejected here because:
- On-premises SSO from a FIDO2 sign-in depends on a cloud step.
- Microsoft's FAQ says a user's first FIDO2 sign-in needs internet connectivity, and that later sign-ins rely on a cached sign-in. This design reads that cache as held on each workstation. With staff rotating across shared workstations, many sign-ins have no earlier sign-in on that device to rely on.
- For later sign-ins, the FAQ says only that cached sign-in "should work" offline, and it recommends keeping devices online with line of sight to domain controllers. It does not describe a shared workstation that rotating staff sign in to while the hospital is offline.

Together these put the cloud in the path of care (ADR-008).

### B. Proximity badge and PIN with a password-replaying clinical SSO product (rejected as the end state)

This is not phishing-resistant, and it concentrates application passwords in one store. It is allowed only as a transitional convenience layer, on managed shared workstations in `Z-CLIN-USER`, during the badge rollout.

### C. Windows Hello for Business on shared workstations (rejected)

Windows Hello for Business enrolls per user, per device, which does not fit staff who rotate across workstations. Microsoft's frontline guidance marks it optional.

### D. Number-matching push as the end state (rejected)

Push approval can be relayed by adversary-in-the-middle phishing proxies, so it is not phishing-resistant. It is accepted only as an interim method for non-privileged users.

### E. Synced passkeys for the workforce (deferred)

They are phishing-resistant and convenient. However, the credential lives in a consumer cloud account outside Contoso's control. Revisit in phase 3.

## Consequences

Positive:

- Phishing-resistant authentication on shared clinical workstations that keeps working when a hospital loses internet.
- One badge credential serves both the local domain and Entra ID.

Negative and residual:

- **Clinical workflow impact (A-06).** Removing a badge locks the session (Windows smart card removal policy: Lock Workstation) and leaves that clinician's work open, so a clinician who returns to the same workstation unlocks their session where they left it. The next clinician opens their own session through Switch User (Windows Fast User Switching) with their badge and its PIN, which Windows asks for at smart card sign-in, and the EHR full client signs them in with that session's Kerberos credentials (A-07). A phase 3 pilot on selected units measures the time from badge insert to a usable EHR screen at nursing stations and workstations on wheels, against a baseline taken on the current sign-in method. The pilot also confirms three assumptions on the shared-workstation build: unlock asks for the PIN too, earlier sessions stay intact while others sign in, and the EHR full client runs in more than one session per workstation. A locked session, including one left behind by Switch User, is signed out after an idle period Contoso sets, and the pilot also measures concurrent sessions and memory headroom per workstation model to inform that period. Rollout goes past the pilot units only after the Chief Nursing Information Officer and Chief Medical Information Officer (fictional roles, decision owners above) accept the measured time.
- **PKI becomes clinically critical.** Certificate revocation data has to stay reachable on-site, or smart card logon can fail closed. `PIP-PKI` is Tier 0 and watched by Defender for Identity sensors on the certification authority servers.
- **Program cost:** cards, readers, issuance, and a lost-badge revocation process.
- **Two credential types to support** (badge and phone passkey), plus a help desk recovery path that cannot become the weak link.
- **Badge-only sign-ins** have no Conditional Access risk evaluation on the local plane (RR-02).

## Compliance drivers

| Framework | Identifier | Why it matters here |
|---|---|---|
| HIPAA | 45 CFR 164.312(d), person or entity authentication (standard, required) | Verifies the person seeking ePHI access |
| HIPAA | 164.312(a)(2)(i), unique user identification (required) | Individual badges on shared workstations, no shared logins |
| HIPAA | 164.312(a)(2)(iii), automatic logoff (addressable) | The session locks on badge removal, and the EHR inactivity timeout ends the EHR session (`02-reference-architecture.md` section 9) |
| NIST CSF 2.0 | PR.AA-03, PR.AA-02, PR.AA-01 | Authentication, proofing before credential issuance, credential management |

## ZTMM mapping

Identity: Authentication (Advanced target). Identity: Identity Stores.

## Revisit when

- Microsoft documents a user's first FIDO2 sign-in, without internet connectivity, on a shared Windows device.
- "Microsoft Entra passkey on Windows" supports device sign-in.
- The badge program's cost or schedule changes materially. The fallback is FIDO2 keys, which requires revising ADR-008 as well.

## Sources

| Title | Publisher | URL | Date checked | Quality |
|---|---|---|---|---|
| Overview of Conditional Access Authentication Strengths | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths | 2026-10-03 | Primary |
| FIDO2 Security Key Sign-in to Windows | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key-windows | 2026-10-03 | Primary |
| Passwordless security key sign-in to on-premises resources | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key-on-premises | 2026-10-03 | Primary |
| FAQs for hybrid FIDO2 security key deployment (internet connectivity and cached sign-in) | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-faqs | 2026-10-04 | Primary |
| Enable Microsoft Entra passkey on Windows (device sign-in, per-device registration, attestation) | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-entra-passkeys-on-windows | 2026-10-04 | Primary |
| Microsoft Entra releases and announcements ("Public Preview - Microsoft Entra passkeys on Windows", March 2026) | Microsoft Learn | https://learn.microsoft.com/en-us/entra/fundamentals/whats-new | 2026-10-04 | Primary |
| Windows smart card sign-in using Microsoft Entra certificate-based authentication | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/authentication/concept-certificate-based-authentication-smartcard | 2026-10-03 | Primary |
| Smart Card Group Policy and Registry Settings ("Interactive logon: Smart card removal behavior", Lock Workstation option) | Microsoft Learn | https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-group-policy-and-registry-settings | 2026-10-04 | Primary |
| Certificate Requirements and Enumeration (smart card sign-in flow: Windows displays a PIN dialog) | Microsoft Learn | https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration | 2026-10-04 | Primary |
| WindowsLogon Policy CSP (HideFastUserSwitching: the Switch User interface in the sign-in UI) | Microsoft Learn | https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowslogon | 2026-10-04 | Primary |
| Considerations for specific personas in a phishing-resistant passwordless authentication deployment | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-plan-persona-phishing-resistant-passwordless-authentication | 2026-10-03 | Primary |
| Passwordless authentication with Microsoft Intune | Microsoft Learn | https://learn.microsoft.com/en-us/intune/solutions/passwordless | 2026-10-04 | Primary |
| Control security information registration with Conditional Access | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration | 2026-10-03 | Primary |
| 45 CFR 164.312 | eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312 | 2026-10-03 | Primary |
