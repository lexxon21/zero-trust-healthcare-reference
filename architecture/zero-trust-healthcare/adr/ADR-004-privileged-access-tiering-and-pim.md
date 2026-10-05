# ADR-004: Privileged access through tiering, cloud-only admin accounts, and PIM from PAWs

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

| Field | Value |
|---|---|
| Status | Accepted (reference design) |
| Date | 2026-10-03 |
| Revised | 2026-10-04 |
| Decision owners (fictional roles) | CISO, VP Infrastructure, Identity Engineering lead |
| Scope | Administrative access to cloud and on-premises systems, plus just-in-time vendor sessions |
| Related | `03-identity-and-access.md` sections 3 to 6, ADR-002, ADR-003; residual risk RR-16 in `02-reference-architecture.md` |

## Context

Contoso Regional Health (fictional) is hybrid: `IDS-AD` is the source of authority and synchronizes to `IDS-ENTRA`. Several systems can take over the whole environment:
- Entra ID and Active Directory.
- The directory synchronization servers.
- PKI.
- Device management and security tooling that can run code on every endpoint.

Verified facts (checked 2026-10-03):

- **Licensing.** PIM, PIM for Groups, and PIM Conditional Access controls are included in Entra ID P2.
- **Activation controls.** Activation can require a Conditional Access authentication context. Microsoft documents reauthentication on every PIM activation by setting sign-in frequency to "Every time" on that context's policy (generally available April 2026). The same page documents a limit (re-checked 2026-10-04): after a user reauthenticates for one activation, activating another eligible role within a 10-minute window does not prompt again, across Microsoft Entra roles, Azure resource roles, and PIM for Groups.
- **Approvals.** Microsoft requires at least one approver and recommends two. It warns of tenant lockout if every Privileged Role Administrator and Global Administrator assignment is eligible, approval is required, and no approver is set.
- **Whoever can manage Conditional Access is privileged** (re-checked 2026-10-04). Microsoft's PIM documentation says that principals with permissions to manage Conditional Access policies, "such as Conditional Access Administrators or Security Administrators", can change requirements, remove them, or block eligible users from activating, and that they "should be considered highly privileged and protected accordingly".
- **Synchronization guidance.** Microsoft's guidance is not to synchronize privileged users from on-premises Active Directory.

Verified facts (checked 2026-10-04):

- **Who can reset an administrator.** Microsoft documents that Privileged Authentication Administrator can manage the authentication methods of all users and can reset a Global Administrator's password. Helpdesk, Password, Authentication, and User Administrators cannot reset a Global Administrator's password. The deprecated Partner Tier2 Support role can. Microsoft says Partner Tier1 Support and Partner Tier2 Support are both deprecated and should not be used, and both role definitions include `microsoft.directory/applications/credentials/update` and `microsoft.directory/applications/owners/update`, which reach every application's credentials and owners (re-checked 2026-10-04).
- **Emergency access exclusions.** Microsoft recommends a dedicated security group for the emergency accounts, excluded from the Conditional Access policies that block or restrict sign-in, and alerts on all sign-in and audit log activity for the accounts. Its emergency access page does not say how to protect that group.
- **Role-assignable groups.** The property can be set only when a group is created. Membership must be assigned, not dynamic, and Privileged Role Administrators manage it unless owners are added. Microsoft Graph requires RoleManagement.ReadWrite.Directory to change it (Group.ReadWrite.All does not work), and no group can be nested inside one.
- **Restricted management administrative units.** Tenant-scoped administrators, Global Administrators included, cannot modify the objects in one unless they hold a role scoped to the unit. Microsoft documents one exception: the membership of a role-assignable group placed in one can be modified only by Global Administrators and Privileged Role Administrators. Objects in one cannot be managed with Microsoft Entra ID Governance features such as Privileged Identity Management and access reviews.
- **Applications and the Temporary Access Pass.** Microsoft's Graph reference for creating a Temporary Access Pass lists UserAuthMethod-TAP.ReadWrite.All and UserAuthenticationMethod.ReadWrite.All as application permissions, and states a role requirement only for delegated calls. The same table, in v1.0 and beta, also lists two read permissions as application permissions for the call: UserAuthMethod-TAP.Read.All, marked least privileged, and UserAuthenticationMethod.Read.All. For delegated calls, Privileged Authentication Administrators can issue a pass to administrators and members, and Authentication Administrators to members only. Microsoft's permissions overview says an application permission gives access to any data it is associated with, and that only Privileged Role Administrators and Global Administrators can consent to application permissions. PIM manages Microsoft Entra roles, Azure resource roles, and groups; Microsoft Graph application permissions are not among them. Microsoft does not state the Global Administrator case explicitly; the conclusion in decision 1 follows from these statements, and a community write-up (secondary) states it directly.
- **Security Administrator.** Microsoft lists it alongside Conditional Access Administrator for creating Conditional Access policies and managing named locations. Microsoft's Defender for Endpoint documentation grants full access to users with the role, through the Defender for Endpoint Global Administrator role, which has unrestricted access to all devices. That page describes Defender for Endpoint's own role model, and notes that customers new to Defender for Endpoint from February 16, 2025 have only unified role-based access control.
- **Application credentials.** Application Administrators can add credentials to an application and use them to impersonate it, doing whatever the application's identity is allowed to do. Cloud Application Administrator has the same permissions except managing application proxy. An application's owners have the same permissions as an Application Administrator, scoped to that application. Custom roles, and some built-in roles (Microsoft's example is Application Administrator), can be assigned at the scope of a single application. Microsoft's privileged roles guidance says to treat applications that hold highly privileged roles as control plane (Tier 0) intermediaries and to administer them only from equally trusted systems.
- **Application permissions that reach Tier 0.** Microsoft's Graph references list, as application permissions:
  - Application.ReadWrite.All and Directory.ReadWrite.All for adding a password to an application.
  - AppRoleAssignment.ReadWrite.All and Application.ReadWrite.All for granting an app role assignment, with a role requirement stated only for delegated calls.
  - Policy.ReadWrite.ConditionalAccess for updating a Conditional Access policy.
  - Device.ReadWrite.All and Directory.ReadWrite.All for updating a device, including its extension attributes, which Microsoft documents are mastered in the cloud. For delegated calls, the same reference names Intune Administrator as the least privileged role, and says a user with Windows 365 Administrator "can only update basic device properties".
- **Device tag writers.** The Graph note conflicts with Microsoft's role definitions. Windows 365 Administrator's definition, like Intune Administrator's, includes `microsoft.directory/devices/extensionAttributeSet1/update` ("Update the extensionAttribute1 to extensionAttribute5 properties on devices"), and Global Administrator's includes `microsoft.directory/devices/allProperties/allTasks`. Windows 365 Administrator's definition carries no privileged label, and Microsoft describes the privileged label as a preview. Microsoft's list of device permissions for custom roles includes no extension attribute permission. Microsoft's default user permissions page lists only reading BitLocker recovery keys and disabling the device among the actions a device's registered owner can take, but its summary table says members can "manage all properties of owned devices".
- **Managed identities.** A managed identity's security boundary is the resource it is attached to, and any code running there can request its tokens. Using a system-assigned identity needs write access to that resource, and a system-assigned identity cannot be shared with another resource. Azure role assignments are inherited from higher scopes.
- **Members of role-assignable groups.** Changing the credentials, resetting MFA, or modifying sensitive attributes of a role-assignable group's members and owners needs at least Privileged Authentication Administrator. Microsoft warns that assignments that can be activated without approval are exposed to less-privileged administrators who might reset a user's credentials and activate on their behalf. Its PIM guidance says the policy on an activation's authentication context should include all users or the role's eligible users, and describes a second policy that targets directory roles for sign-in with a role active. A tenant can create at most 500 role-assignable groups.
- **Domain federation roles.** Domain Name Administrator's definition includes `microsoft.directory/domains/allProperties/allTasks`, and Microsoft documents that its holders can configure domain names for federation and manage Microsoft Entra Connect. External Identity Provider Administrator's definition includes `microsoft.directory/domains/federation/update` and `microsoft.directory/identityProviders/allProperties/allTasks`, and Hybrid Identity Administrator's also includes `microsoft.directory/domains/federation/update`. Microsoft labels Domain Name Administrator and External Identity Provider Administrator privileged, and names Domain Name Administrator the least privileged role for managing domains.

## Decision

1. **Three tiers,** as defined in `03-identity-and-access.md` section 4, and roles that are never assigned:
   - Tier 0, the control plane. It includes:
     - Intune administrators, and security tooling roles that can run code on every device.
     - Both roles that can manage Conditional Access, Conditional Access Administrator and Security Administrator, with Tier 0 PIM settings. Under Defender for Endpoint's own role model, Security Administrator also gets full access across all devices.
     - Privileged Authentication Administrator, which can reset the authentication methods of any user, Global Administrators included.
     - Domain Name Administrator, which Microsoft documents can configure a domain for federation and manage Microsoft Entra Connect. Under managed authentication (A-01), federating a domain would let another identity provider authenticate its users. Microsoft names the role least privileged for managing domains, which Contoso still does, so it is Tier 0 rather than never assigned.
     - Application Administrator and Cloud Application Administrator when assigned at tenant scope, because they can add a credential to any application, Tier 0 applications included. Assigned at the scope of a single application that is not Tier 0, Application Administrator is Tier 1.
     - Workload identities that can change Tier 0 objects or the controls Tier 0 depends on: any application or managed identity holding a permission in `03-identity-and-access.md` section 6. Examples are RoleManagement.ReadWrite.Directory (decision 9) and the permissions that can issue a Temporary Access Pass to any user, Global Administrators included. The two read permissions in the Temporary Access Pass table count as Tier 0 until a lab test shows they cannot create a pass. Administrators issue passes through delegated access, and no application holds any of those permissions by default.
     - Whoever can change a Tier 0 workload identity. Tier 0 applications therefore have no owners in the directory, Tier 0 managed identities are system-assigned, and every Azure role that can write to the resources hosting those identities is Tier 0.
   - Tier 1, the management plane, which includes EHR security administrators and safety-critical clinical engineering consoles.
   - Tier 2, user support.
   - Never assigned: Partner Tier1 Support, Partner Tier2 Support, Windows 365 Administrator, and External Identity Provider Administrator (`03-identity-and-access.md` section 4). Each has a definition that reaches Tier 0, and each is deprecated or exists for a function Contoso does not use. Any assignment of one raises an alert.
2. **Dedicated, cloud-only admin accounts** for cloud administration, never synchronized from Active Directory. Separate per-tier admin accounts in AD.
3. **Eligible-only assignments through PIM.** The two emergency access accounts are the only permanent active Global Administrators (`03-identity-and-access.md` section 5).
4. **Activation requires authentication context `c1`** (CA-06). CA-06 requires a phishing-resistant method and a compliant device, with sign-in frequency set to every time, for any account. It targets all users, one of the two scopes Microsoft's PIM guidance gives, so those requirements do not depend on membership in the admin groups. The PAW requirement does: it comes from CA-04 and CA-05 through `grp-admins-t0` and `grp-admins-t1`, whose membership changes only through Tier 0 (decision 6). Reauthentication is not strictly per activation: Microsoft documents a 10-minute window in which a further activation does not prompt again, across Microsoft Entra roles, Azure resource roles, and PIM for Groups. Every Tier 0 activation still needs its own approval (decision 5).
5. **Tier 0 activation needs approval from one of two named approvers.** Safety-critical device consoles need two-person control: PIM approval by clinical engineering plus the clinical change process.
6. **Admin accounts work only from PAWs** (`PEP-PAW`), enforced by device filters (CA-04, CA-05) and by `Z-MGMT` firewall rules. Both inputs to those filters change only through Tier 0, subject to one lab test:
   - The groups they target, `grp-admins-t0` and `grp-admins-t1`, are role-assignable with no owners, like the exclusion group in decision 9. Among administrator roles, only Privileged Role Administrators and Global Administrators can change their membership, and only Privileged Authentication Administrators and Global Administrators can change their members' credentials. The only other identities that can do either are Tier 0 workload identities (RR-16). Every change to the groups raises an alert at Tier 0 priority.
   - The device tag the filters read, `extensionAttribute1`, can be written by applications holding Device.ReadWrite.All or Directory.ReadWrite.All, which are Tier 0 workload identities, and by any role whose definition includes `microsoft.directory/devices/extensionAttributeSet1/update`. Completeness rests on that permission, not on a list of role names. Of the built-in definitions checked, Intune Administrator's and Windows 365 Administrator's include it, and Global Administrator's covers every device property. Global Administrator and Intune Administrator are Tier 0. Windows 365 Administrator is never assigned, because Windows 365 is not in Contoso's stack, so writing the tag through it would first need a role assignment, which is Tier 0 work and raises an alert. Every other role is checked for the permission before its first assignment (Consequences).
   - The lab test in `03-identity-and-access.md` section 3 settles the two cases where Microsoft's pages disagree: whether Windows 365 Administrator can write the tag, and whether a device's registered owner can. If Contoso adopts Windows 365, the role is Tier 0 unless the test shows it cannot write the tag. If the owner's call is accepted, the tag alone cannot mark a PAW (Revisit when).
7. **On-premises Tier 0 protection:**
   - Logon restrictions across tiers.
   - The Protected Users group, and authentication policies and silos.
   - Windows LAPS.
   - Defender for Identity sensors on domain controllers, certification authority servers, and the active and staging Entra Connect servers. The last two qualifiers follow Microsoft's sensor v2.x prerequisites.
8. **Vendor elevation reuses the same machinery.** Vendor engineers hold eligible membership in session groups through PIM for Groups, activated with Contoso approval (ADR-002).
9. **The emergency access exclusion group is a Tier 0 object** (`03-identity-and-access.md` section 5). `grp-ca-emergency-access` is a role-assignable group with no owners and no role assigned, so an administrator can change it only through an approved Tier 0 activation. Every change to it, and all audit activity by or on the two emergency accounts, raises an alert at Tier 0 priority. The emergency accounts and Tier 0 workload identities can make such changes with no approval, and on those paths the alert is the only control (RR-16).

## Alternatives considered

### A. Synchronized admin accounts, one identity for on-premises and cloud administration (rejected)

A compromise of on-premises Active Directory would become a compromise of cloud administration. This contradicts Microsoft's guidance.

### B. Standing admin roles protected by strong MFA (rejected)

Standing privilege keeps the window of exposure open all the time. PIM is already licensed.

### C. A third-party privileged access management vault with session recording for all admin work (deferred)

It would add another Tier 0 system and its cost. PIM covers cloud roles, and the broker records vendor sessions. Revisit for vaulting on-premises Tier 0 credentials.

### D. Phishing-resistant MFA without PAWs (rejected)

A phishing-resistant sign-in from a compromised workstation still hands the attacker a live admin session. The device matters as much as the method.

### E. A restricted management administrative unit for the exclusion group (rejected)

It would stop tenant-scoped administrators, Global Administrators included, from changing the group unless they first take a role scoped to the unit. For a role-assignable group it adds little. Microsoft documents an exception for such groups: inside a restricted unit, only Global Administrators and Privileged Role Administrators can modify their membership. Those are the same Tier 0 roles that decision 9 already requires once the group has no owners. Used with an ordinary group instead, it would hand the group to whoever holds a role scoped to the unit: a second set of assignments to govern and monitor alongside Tier 0. Microsoft also documents that objects in such a unit cannot be managed with Privileged Identity Management or access reviews.

### F. Monitoring alone, with an ordinary security group (rejected)

Microsoft documents that a tenant-level Groups Administrator can add users to security groups, and that the Microsoft Graph application permission Group.ReadWrite.All can update group memberships across the tenant (role-assignable groups excepted). Neither is on the Tier 0 list. An account added through either path would escape baseline MFA and the PAW rules as soon as it joined, and an alert would report it only after the fact.

### G. Tier applications by purpose rather than by reach (rejected)

An onboarding tool that issues Temporary Access Passes looks like Tier 2 work, because it serves the service desk. Its permission is not limited that way. The role split that keeps an Authentication Administrator to non-administrators applies only to delegated calls, so the same application permission reaches every Global Administrator and both emergency accounts. Tiering by purpose would leave a route into Tier 0 outside Tier 0's controls, the same gap decision 1 closed for Privileged Authentication Administrator.

Alternatives H to K, narrower Entra role and group cases, are in the appendix at the end of this record.

## Consequences

Positive:

- No standing privilege for administrator accounts. The standing exceptions are named in RR-16.
- Every elevation is time-bound and logged, and every Tier 0 elevation is approved.
- Admin sessions start only from hardened devices. The admin groups that enforce this change only through Tier 0, and so does the device tag as Microsoft documents its writers; the lab test in decision 6 settles the two cases where Microsoft's pages disagree.
- Outside the standing paths in RR-16, each of these needs an approved Tier 0 activation:
  - resetting an administrator's credentials;
  - changing a Conditional Access policy or named location;
  - changing the membership of `grp-ca-emergency-access`, `grp-admins-t0`, or `grp-admins-t1`;
  - adding a credential to a Tier 0 application.

  This holds for the roles and permissions named in `03-identity-and-access.md` sections 4 and 6, as Microsoft documented them on 2026-10-04. Those lists come from a targeted review, not from a review of every role and permission Microsoft offers. The design therefore checks every role, built-in or custom, against the Tier 0 scope before its first assignment, and every application permission before it is granted, whether or not Microsoft labels it privileged (03 sections 4 and 6). The scope is control of identity or of code on every device, including domain federation and the secrets that unlock a PAW or a Tier 0 server, and the role check covers Microsoft Entra ID, Intune, Defender, Azure, and Active Directory. A role or permission that reaches Tier 0 and is assigned or granted without that check is not covered.

Negative and residual:

- **Friction for on-call work.** Night approvals need an approver rota.
- **PAW fleet cost and maintenance.**
- **Lockout risk** from misconfigured approval settings. Two named approvers and tested emergency accounts mitigate it.
- **The three Tier 0 groups must be created role-assignable.** The property cannot be added to an existing group. A tenant that already uses ordinary groups creates new ones and switches each policy to them before deleting the old groups. For the exclusion group, the new group joins every policy's exclusions before the old one leaves, so the emergency accounts are never left subject to those policies. Microsoft caps a tenant at 500 role-assignable groups.
- **Administrator joiners and leavers become Tier 0 work.** Adding an account to an admin group needs a Privileged Role Administrator or Global Administrator activation. Disabling or resetting a member needs Privileged Authentication Administrator or Global Administrator. Lifecycle automation therefore does not handle admin accounts.
- **Credential help for administrators becomes Tier 0 work,** with Tier 0 approvals and Tier 0 PAWs.
- **Conditional Access and Security Administrator work becomes Tier 0 work.** Policy changes, and any security operations task that needs Security Administrator, run from Tier 0 PAWs with Tier 0 approvals. Analysts whose work needs neither use narrower roles.
- **Tenant-scoped application administration becomes Tier 0 work.** Routine work moves to app-scoped assignments, which means one assignment per application to grant, review, and remove.
- **Every new role costs a review.** A role's first assignment, in Microsoft Entra ID, Intune, Defender, Azure, or Active Directory, waits for a check of its definition against the Tier 0 scope, and Microsoft's privileged label cannot stand in for that check (alternative K).
- **Automated pass issuance costs Tier 0 governance.** Issuing Temporary Access Passes through an application permission would make that application Tier 0 (decision 1). Automation that issues passes therefore either uses delegated access, where Microsoft limits an Authentication Administrator to non-administrators, or is governed as Tier 0.
- **Standing Tier 0 access has no gate (RR-16).**
  - The emergency accounts are permanent Global Administrators.
  - A Microsoft Graph application permission is a standing grant outside the roles and groups that PIM manages. Anyone holding a credential for the application can use the grant, including a credential added after it was made. A credential added to a Tier 0 application stays valid after the approved activation or automation run that added it has ended, and an application holding Application.ReadWrite.All or Directory.ReadWrite.All can add one to any application.
  - Each of these can change the exclusion group or an emergency account's credentials without approval. On those paths the control is the alert, not a gate, so response time decides the outcome. For credentials added to a Tier 0 application, the alert is SN-03, which scores every such addition High, whoever makes it.
- **Tier 0 compromise is still a full compromise** (RR-07). This design narrows the paths to Tier 0; it does not remove them.

## Compliance drivers

| Framework | Identifier | Why it matters here |
|---|---|---|
| HIPAA | 45 CFR 164.308(a)(4)(ii)(B), access authorization (addressable); 164.308(a)(4)(ii)(C), access establishment and modification (addressable) | Privileged access is granted, time-bound, and reviewed |
| HIPAA | 164.312(a)(2)(ii), emergency access procedure (required) | Emergency access accounts and sealed AD recovery credentials |
| HIPAA | 164.312(b), audit controls (standard, required) | Activations, role changes, changes to the three Tier 0 groups, credentials added to Tier 0 applications, and the emergency accounts' audit activity are recorded and examined |
| PCI DSS v4.0.1 | Requirement 7.2.1 (design rule) | No administrative access into the CDE exists by design. Any future access follows the defined access model. |
| NIST CSF 2.0 | PR.AA-05, PR.AA-01, DE.CM-03 | Least privilege, credential management, monitoring of privileged activity |

## ZTMM mapping

Identity: Access Management, Governance Capability, Visibility and Analytics Capability (alerts on the three Tier 0 groups, the emergency accounts, and credentials added to Tier 0 applications). Devices: Resource Access. Applications and Workloads: Application Access (workload identities with Tier 0 permissions).

## Revisit when

- Microsoft changes PIM capabilities or licensing.
- On-premises Tier 0 credential vaulting is funded.
- An incident or exercise shows a gap in PAW coverage.
- Microsoft's emergency access guidance names a way to protect the exclusion group (decision 9).
- Microsoft documents a limit on which users an application permission for authentication methods can reach (decision 1).
- Microsoft adds or changes a role or application permission that can manage Conditional Access, role-assignable groups, application credentials, authentication methods, domain federation, or device extension attributes, run code on every device, or read a BitLocker recovery key or a local administrator password (decision 1).
- A lab test shows whether the two read permissions in the Temporary Access Pass table can create a pass (decision 1).
- The device tag lab test reports (decision 6). If a device's registered owner can write its own device's tag, the tag alone cannot mark a PAW, and CA-04 and CA-05 need a second device signal that only Tier 0 can set.
- Contoso adopts Windows 365. Windows 365 Administrator is then Tier 0 unless the device tag lab test shows it cannot write the tag (decision 6).

## Sources

| Title | Publisher | URL | Date checked | Quality |
|---|---|---|---|---|
| What is Privileged Identity Management? | Microsoft Learn | https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure | 2026-10-04 | Primary |
| Configure Microsoft Entra role settings in PIM (reauthentication on activation; 10-minute window) | Microsoft Learn | https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings | 2026-10-04 | Primary |
| Microsoft Entra releases and announcements (April 2026: "General Availability - Enforce Conditional Access policies like MFA on every PIM activation") | Microsoft Learn | https://learn.microsoft.com/en-us/entra/fundamentals/whats-new | 2026-10-04 | Primary |
| Least privileged roles by task in Microsoft Entra ID (Conditional Access tasks; managing domains) | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/delegate-by-task | 2026-10-04 | Primary |
| Microsoft Entra built-in roles (Application Administrator, Cloud Application Administrator, Domain Name Administrator, External Identity Provider Administrator, Global Administrator, Hybrid Identity Administrator, Intune Administrator, Windows 365 Administrator, Partner Tier1 Support, Partner Tier2 Support) | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference | 2026-10-04 | Primary |
| Role definition source files behind the built-in roles reference (domain-name-administrator.md, external-identity-provider-administrator.md, global-administrator.md, hybrid-identity-administrator.md, intune-administrator.md, windows-365-administrator.md, partner-tier1-support.md, partner-tier2-support.md) | Microsoft (MicrosoftDocs/entra-docs on GitHub) | https://github.com/MicrosoftDocs/entra-docs/tree/main/docs/identity/role-based-access-control/includes | 2026-10-04 | Primary (source of the Microsoft Learn page) |
| Device management permissions for Microsoft Entra custom roles | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/custom-device-permissions | 2026-10-04 | Primary |
| device resource type, Microsoft Graph v1.0 (extensionAttributes mastered in the cloud) | Microsoft Learn | https://learn.microsoft.com/en-us/graph/api/resources/device?view=graph-rest-1.0 | 2026-10-04 | Primary |
| Default user permissions (actions on owned devices) | Microsoft Learn | https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions | 2026-10-04 | Primary |
| Assign Microsoft Entra roles (app registration scope) | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/manage-roles-portal | 2026-10-04 | Primary |
| Overview of Microsoft Entra role-based access control (RBAC) (resource scopes) | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/custom-overview | 2026-10-04 | Primary |
| Overview of Enterprise Application Ownership | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/overview-assign-app-owners | 2026-10-04 | Primary |
| Use role-based access control to grant fine-grained access to Microsoft Defender portal (Security Administrator access; unified RBAC note for new customers) | Microsoft Learn | https://learn.microsoft.com/en-us/defender-endpoint/rbac | 2026-10-04 | Primary |
| Managed identities for Azure resources (system-assigned and user-assigned) | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview | 2026-10-04 | Primary |
| Managed identities for Azure resources frequently asked questions (security boundary, permissions to use) | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/managed-identities-faq | 2026-10-04 | Primary |
| Understand scope for Azure RBAC | Microsoft Learn | https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview | 2026-10-04 | Primary |
| Microsoft Entra licensing | Microsoft Learn | https://learn.microsoft.com/en-us/entra/fundamentals/licensing | 2026-10-03 | Primary |
| Manage emergency access admin accounts | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access | 2026-10-04 | Primary |
| Privileged roles and permissions in Microsoft Entra ID (preview) (Partner Tier1 and Tier2 Support deprecation; privileged label in preview) | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions | 2026-10-04 | Primary |
| Use Microsoft Entra groups to manage role assignments | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept | 2026-10-04 | Primary |
| Restricted management administrative units in Microsoft Entra ID | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management | 2026-10-04 | Primary |
| Microsoft Graph permissions reference | Microsoft Learn | https://learn.microsoft.com/en-us/graph/permissions-reference | 2026-10-04 | Primary |
| Overview of Microsoft Graph permissions | Microsoft Learn | https://learn.microsoft.com/en-us/graph/permissions-overview | 2026-10-04 | Primary |
| Create temporaryAccessPassMethod, Microsoft Graph v1.0 (permissions section) | Microsoft Learn | https://learn.microsoft.com/en-us/graph/api/authentication-post-temporaryaccesspassmethods?view=graph-rest-1.0 | 2026-10-04 | Primary |
| Create temporaryAccessPassMethod, Microsoft Graph beta (permissions section) | Microsoft Learn | https://learn.microsoft.com/en-us/graph/api/authentication-post-temporaryaccesspassmethods?view=graph-rest-beta | 2026-10-04 | Primary |
| application: addPassword, Microsoft Graph v1.0 (permissions section) | Microsoft Learn | https://learn.microsoft.com/en-us/graph/api/application-addpassword?view=graph-rest-1.0 | 2026-10-04 | Primary |
| Grant an appRoleAssignment for a service principal, Microsoft Graph v1.0 (permissions section) | Microsoft Learn | https://learn.microsoft.com/en-us/graph/api/serviceprincipal-post-approleassignedto?view=graph-rest-1.0 | 2026-10-04 | Primary |
| Update conditionalAccessPolicy, Microsoft Graph v1.0 (permissions section) | Microsoft Learn | https://learn.microsoft.com/en-us/graph/api/conditionalaccesspolicy-update?view=graph-rest-1.0 | 2026-10-04 | Primary |
| Update device, Microsoft Graph v1.0 (permissions section; role notes on Intune Administrator and Windows 365 Administrator) | Microsoft Learn | https://learn.microsoft.com/en-us/graph/api/device-update?view=graph-rest-1.0 | 2026-10-04 | Primary |
| Configure a Temporary Access Pass in Microsoft Entra ID to register passwordless authentication methods | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass | 2026-10-04 | Primary |
| Least privilege for Temporary Access Pass creation (Jan Bakker, 2026-01-25) | JanBakker.tech | https://janbakker.tech/least-privilege-for-temporary-access-pass-creation/ | 2026-10-04 | Secondary (community write-up; states that the application permission cannot be scoped and reaches Global Administrators; no test described) |
| CISA Zero Trust Maturity Model for the identity pillar (guidance not to synchronize privileged users) | Microsoft Learn | https://learn.microsoft.com/en-us/security/zero-trust/cisa-zero-trust-maturity-model-identity | 2026-10-03 | Primary for Microsoft guidance |
| Deploy Microsoft Defender for Identity sensors | Microsoft Learn | https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-defender-identity | 2026-10-03 | Primary |
| Microsoft Defender for Identity sensor v2.x prerequisites (certification authority servers; active and staging Entra Connect servers) | Microsoft Learn | https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-2 | 2026-10-04 | Primary |
| Filter for devices as a condition in Conditional Access policy | Microsoft Learn | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-condition-filters-for-devices | 2026-10-03 | Primary |
| 45 CFR 164.308 and 164.312 | eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C | 2026-10-03 | Primary |

## Appendix: alternatives H to K

### H. Ordinary groups for the admin policies, with role-targeted companion policies (rejected)

Microsoft's PIM guidance describes a second Conditional Access policy that targets directory roles and sets the requirements for signing in with a role active. Paired with ordinary admin groups, it would cover an account removed from its group only while a role is active. It would not cover activation, because the user does not hold the role yet. The removal itself would still need no Tier 0 step: a Groups Administrator or an application holding Group.ReadWrite.All could make it, and an alert would report it after the fact. That is the weakness alternative F rejects for the emergency access group. The companion policies would also have to track every change to the tier role lists. Role-assignable groups close the path at its source (decision 6), and CA-06 targeting all users keeps activation's method, device compliance, and reauthentication requirements whatever an account's group membership (decision 4).

### I. Application administration in Tier 1, with SN-03 as the control (rejected)

Application Administrator and Cloud Application Administrator manage credentials for every application in the tenant. Left in Tier 1, where most activations need no approval, either role could add a credential to a Tier 0 application and act as it, outside every Tier 0 control. The credential would also outlive the activation that added it. SN-03 alerts at High on that change, but an alert reports a takeover; it does not prevent one. This is alternative F's reasoning applied to applications. Tenant-scoped application administration therefore costs Tier 0 governance, and routine application work uses app-scoped assignments.

### J. Windows 365 Administrator below Tier 0, on the strength of Microsoft's Graph note (rejected)

Microsoft's reference for updating a device says the role can update only basic device properties, but the role's definition includes the extension attribute permissions. The design does not settle a conflict between Microsoft's pages in its own favor without a test, the same stance it takes on the Temporary Access Pass read permissions (decision 1). Making the role Tier 0 was also considered. It would add an eligible role to govern and review that Contoso has no use for, while never assigning it costs nothing until Contoso adopts Windows 365 (decision 6).

### K. Review only the roles Microsoft labels privileged (rejected)

Microsoft describes its privileged label as a preview, and Windows 365 Administrator's definition carries no label although it includes the permission to update the device tag that CA-04 and CA-05 read. A review keyed to the label would have missed Windows 365 Administrator, the role this design found with that reach outside Tier 0. Every role is checked against the Tier 0 scope before its first assignment instead, whichever system grants it (Consequences).
