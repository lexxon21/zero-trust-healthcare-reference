# Notices and attribution

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

This file lists the third-party frameworks, identifier sets, names, and quoted material used in this repository, and the terms each comes with. Each source's terms were checked at the source on 2026-10-04 (table at the end).

The repository's own licenses cover original content only: the [MIT License](LICENSE) for code, and [CC BY 4.0](LICENSE-docs) for documentation and data (the README's License section lists the files each covers). Third-party material stays under its owner's terms. Naming an organization, product, or framework here or anywhere in the repository does not imply affiliation with, sponsorship by, or endorsement by its owner.

## MITRE ATT&CK

- **Used:** technique and tactic IDs and names from MITRE ATT&CK Enterprise v19.2, in the threat model, the detection rules (header lines and Sigma tags), the coverage map, and the incident response playbook, with occasional short quotations of technique descriptions.
- **Terms:** MITRE's Terms of Use license ATT&CK for research, development, and commercial use, on condition that copies reproduce MITRE's copyright designation and the license. Both follow, as published on MITRE's Terms of Use page:

  The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.

  "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."

- **Trademarks:** MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.

## NIST publications

- **Used:** NIST Cybersecurity Framework (CSF) 2.0 subcategory identifiers throughout, and the CSF 2.0 subcategory outcome statements reproduced in `grc/zero-trust-healthcare/crosswalk.yaml` (`metadata.csf_subcategories`); the component model and section references of NIST SP 800-207 in the architecture; NIST SP 800-61 Rev. 3 as the structure of the incident response playbook; and other NIST publications where they are cited.
- **Terms:** NIST states that works authored by NIST employees are not subject to copyright protection within the United States, that foreign rights are reserved, and that to the extent NIST may assert rights outside the United States, the public is granted a royalty-free, worldwide right to reprint them. NIST asks reprints to carry its recommended citation followed by "Republished courtesy of the National Institute of Standards and Technology."
- **Credit:** the CSF 2.0 outcome text in `crosswalk.yaml` comes from National Institute of Standards and Technology, The NIST Cybersecurity Framework (CSF) 2.0, NIST CSWP 29, February 26, 2024, https://doi.org/10.6028/NIST.CSWP.29. Republished courtesy of the National Institute of Standards and Technology.

## CISA Zero Trust Maturity Model

- **Used:** the pillar, cross-cutting capability, function, and stage names of the CISA Zero Trust Maturity Model Version 2.0 (April 2023), in the maturity roadmap and the architecture's control mappings. Stage descriptions are paraphrased.
- **Terms:** the model is a publication of the Cybersecurity and Infrastructure Security Agency, a United States government agency. Under 17 U.S.C. 105, copyright protection under Title 17 "is not available for any work of the United States Government." No seal or logo of the agency is used.

## HHS, the HIPAA rules, and other US government sources

- **Used:** citations to and short quotations from 45 CFR Parts 160 and 164 (the HIPAA Security, Privacy, and Breach Notification Rules) as published in the eCFR; Federal Register documents, including the HIPAA Security Rule notice of proposed rulemaking (90 FR 898, January 6, 2025), which is a proposed rule and not final; and publications of HHS, the FBI, CISA, and the FDA cited in the threat model and the notification clock matrix.
- **Terms:** publications of federal agencies are works of the United States Government, for which copyright protection under Title 17 is not available (17 U.S.C. 105). Advisories issued jointly with non-federal partners, such as AA25-203A (with MS-ISAC), are cited and paraphrased only. Every source is cited in the document that uses it.

## PCI Security Standards Council

- **Used:** PCI DSS v4.0.1 requirement numbers in the crosswalk (on rows scoped to the cardholder data environment only) and in the documents that discuss the cardholder data environment. Every requirement is summarized in this repository's own words, and no PCI DSS text is reproduced: `crosswalk.yaml` records that "Requirement summaries are paraphrased, never reproduced." PCI SSC's Self-Assessment Questionnaires and summaries of changes are cited for eligibility and wording checks.
- **Terms:** PCI DSS and PCI SSC's other documents are the copyrighted work of PCI Security Standards Council, LLC. Its Terms and Conditions (last updated 12 August 2020) restrict publishing, copying, and preparing derivative works of its content beyond the rights they expressly grant. No PCI SSC logo is used.

## HITRUST

- **Used:** the name only. The scenario states that the leadership of Contoso Regional Health (fictional) is considering HITRUST certification, and `grc/zero-trust-healthcare/crosswalk.md` section 4 explains why the crosswalk includes no HITRUST content.
- **Decision:** after a review of the HITRUST CSF License Agreement (HITRUST CSF Version 11.9) and HITRUST's Terms of Use, the crosswalk contains no HITRUST CSF identifiers, text, or mapping. `crosswalk.yaml` records `identifiers_included: false`, and its schema enforces that value.
- **Marks:** HITRUST's Terms of Use (last modified January 8, 2024) state that "HITRUST, and all related names, logos, product and service names, designs, and slogans" are marks of HITRUST or its affiliates or licensors. No HITRUST logo is used; the name appears only to identify HITRUST and its framework.

## Microsoft

- **Products:** the scenario uses Microsoft products as example implementations of logical components. Microsoft and the names of the Microsoft products and services referred to in this repository are trademarks of the Microsoft group of companies.
- **Quoted material:** the documents, and comments in some rules, cite Microsoft Learn and Microsoft Support pages and quote short passages from them. Each quotation is cited to its page in the file that uses it, and the Markdown documents also give the date each page was checked. That content is Microsoft's and is not covered by this repository's licenses. Microsoft publishes the source of many Microsoft Learn pages in public MicrosoftDocs repositories under their own licenses: for example, [MicrosoftDocs/azure-docs](https://github.com/MicrosoftDocs/azure-docs) carries a CC BY 4.0 LICENSE file and an MIT LICENSE-CODE file, and [MicrosoftDocs/entra-docs](https://github.com/MicrosoftDocs/entra-docs) carries the MIT License. Where such a license covers a quoted page, its terms apply to the quoted text.
- **Contoso:** Contoso is one of the fictional company names used in Microsoft's documentation and learning material; an archived Microsoft TechNet Wiki page lists it as "Contoso Ltd." Contoso Regional Health is a fictional organization created for this repository. It is not affiliated with Microsoft and does not describe any real organization.

## Sigma

- **Format:** the six rules in `detections/zero-trust-healthcare/sigma/` use the Sigma rule format. SigmaHQ states that the Sigma specification and the Sigma logo are public domain. No Sigma logo is used.
- **Rules from SigmaHQ:** SigmaHQ states that the content of its rule repository is released under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License). When the rules are shared, including in modified form, DRL 1.1 requires keeping the identification of each rule's authors, a link to the rule, and a statement that the rule is licensed under DRL 1.1 with the license text or a link to it. Four detections in this repository follow SigmaHQ rules: SG-01, SG-05, SG-06, and DX-01. Each file that does carries all three items in a comment and links the rule in its references, and SG-01, SG-05, and SG-06 also credit the rule in their `description` field.

  | SigmaHQ rule | Id | Authors | Where it is used here |
  |---|---|---|---|
  | [Windows Recovery Environment Disabled Via Reagentc](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_reagentc_disable_windows_recovery_environment.yml) | db1c21e4-cd66-4b4e-85ca-590f0780529c | Daniel Koifman (KoifSec), Michael Vilshin | SG-01's `reagentc` selection; DX-01 follows it for the `reagentc.exe` original file name |
  | [Suspicious Kerberos RC4 Ticket Encryption](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_rc4_kerberos.yml) | 496a0e47-0a33-4dca-b009-9e6ca3591f39 | Florian Roth (Nextron Systems) | SG-05 follows its logic. It requires Status 0x0 where the SigmaHQ rule requires a TicketOptions value, and also excludes krbtgt |
  | [Active Directory Replication from Non Machine Account - DcSync Indicator](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_ad_replication_non_machine_account.yml) | 17d619c1-e020-4347-957e-1d1207455c93 | Roberto Rodriguez @Cyb3rWard0g | SG-06 follows its logic. It adds the ObjectServer and AccessMask conditions, uses three of the SigmaHQ rule's four replication GUIDs, and omits its NT AUT and Window Manager exclusions |

- **Written for this repository:** SG-02, SG-03, and SG-04, and the parts of SG-01, SG-05, and SG-06 that differ from the credited rules. When any of these files is shared, the DRL 1.1 conditions above stay with the parts taken from the credited rules.

## Validation libraries and tools named

Atomic Red Team (Red Canary), Apache Caldera (incubating), Microsoft's Attack simulation training and Defender for Endpoint demonstration scenarios, and the pySigma Kusto backend are named in the purple team plan and in rule notes as places an operator would select tests or run conversions. None of their content is included.

## Card brand rules

`grc/zero-trust-healthcare/notification-clocks.md` cites Visa's What To Do If Compromised (Version 10.0), American Express's Data Security Operating Policy (United States, April 2026), Discover's Contact Us page, and Mastercard's Security Rules and Procedures, Merchant Edition.

- Visa's clocks are paraphrased with section references, and Discover's clock is quoted briefly.
- American Express marks its policy confidential and trade secret, so the matrix cites it by title, edition, and section only, with no paraphrase.
- Mastercard's rules could not be retrieved, so the matrix gives no Mastercard time limit.

Visa, Mastercard, American Express, and Discover are trademarks of their respective owners.

## Other sources and names

- Documents list their sources in a Sources section, with publisher, URL, date checked, and a quality label, or point to the companion documents whose Sources sections they rely on. Short quotations are attributed where they appear. Third-party content remains its owners' and is not covered by this repository's licenses.
- All other product names, company names, and marks belong to their respective owners and are used only to identify them.

## Terms checked for this notice

| Title | Publisher | URL | Date checked | Quality |
|---|---|---|---|---|
| Terms of Use (ATT&CK license, copyright designation, and trademark notice) | MITRE | https://attack.mitre.org/resources/legal-and-branding/terms-of-use/ | 2026-10-04 | Primary |
| Copyright, Fair Use, and Licensing Statements for SRD, Data, Software, and Technical Series Publications (updated June 24, 2025) | NIST | https://www.nist.gov/open/copyright-fair-use-and-licensing-statements-srd-data-software-and-technical-series-publications | 2026-10-04 | Primary |
| Copyright Law of the United States, Chapter 1, section 105 (United States Government works) | U.S. Copyright Office | https://www.copyright.gov/title17/92chap1.html | 2026-10-04 | Primary |
| Terms and Conditions (last updated 12 August 2020) | PCI Security Standards Council | https://www.pcisecuritystandards.org/terms_and_conditions/ | 2026-10-04 | Primary |
| Terms of Use for Site and Services (last modified January 8, 2024) | HITRUST | https://hitrustalliance.net/terms-of-use | 2026-10-04 | Primary |
| Trademark and Brand Guidelines | Microsoft | https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks | 2026-10-04 | Primary |
| Terms of Use, Microsoft Learn (updated 2025-05-12) | Microsoft | https://learn.microsoft.com/en-us/legal/termsofuse | 2026-10-04 | Primary |
| MicrosoftDocs/azure-docs repository (LICENSE: CC BY 4.0; LICENSE-CODE: MIT) | Microsoft, on GitHub | https://github.com/MicrosoftDocs/azure-docs | 2026-10-04 | Primary |
| MicrosoftDocs/entra-docs repository (LICENSE and LICENSE-CODE: MIT) | Microsoft, on GitHub | https://github.com/MicrosoftDocs/entra-docs | 2026-10-04 | Primary |
| List of fictional companies used in Microsoft material (archived community wiki page) | Microsoft Learn archive | https://learn.microsoft.com/en-us/archive/technet-wiki/1117.list-of-fictional-companies-used-in-microsoft-material | 2026-10-04 | Secondary |
| Sigma specification repository (LICENSE: specification and logo are public domain) | SigmaHQ | https://github.com/SigmaHQ/sigma-specification | 2026-10-04 | Primary |
| Sigma rules repository (README: released under DRL 1.1) | SigmaHQ | https://github.com/SigmaHQ/sigma | 2026-10-04 | Primary |
| Detection Rule License (DRL) 1.1 | SigmaHQ | https://github.com/SigmaHQ/Detection-Rule-License | 2026-10-04 | Primary |
| Windows Recovery Environment Disabled Via Reagentc (Sigma rule; author and id) | SigmaHQ | https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_reagentc_disable_windows_recovery_environment.yml | 2026-10-04 | Primary |
| Suspicious Kerberos RC4 Ticket Encryption (Sigma rule; author, id, and detection logic) | SigmaHQ | https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_rc4_kerberos.yml | 2026-10-04 | Primary |
| Active Directory Replication from Non Machine Account - DcSync Indicator (Sigma rule; author, id, and detection logic) | SigmaHQ | https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_ad_replication_non_machine_account.yml | 2026-10-04 | Primary |
| Attribution 4.0 International legal code (the text in LICENSE-docs) | Creative Commons | https://creativecommons.org/licenses/by/4.0/legalcode.txt | 2026-10-04 | Primary |
| MIT License template (the text in LICENSE) | GitHub, choosealicense.com | https://github.com/github/choosealicense.com/blob/gh-pages/_licenses/mit.txt | 2026-10-04 | Primary |
