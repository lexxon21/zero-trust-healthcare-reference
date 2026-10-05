# Validator fixture: minimal crosswalk.md

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

Test fixture for validate-crosswalk.ps1; the rows are placeholders, not analysis. tests\run-tests.ps1 compares them with good.yaml on CSF targets and relationships, coverage, and PCI DSS targets.

| Measure | Count |
|---|---|
| HIPAA rows | 65 |

## 1. Administrative safeguards (45 CFR 164.308)

| HIPAA | Standard or specification (R/A) | CSF 2.0 targets | Coverage | PCI DSS v4.0.1 (CDE only) |
|---|---|---|---|---|
| [164.308(a)(1)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Security management process (standard) | GV.PO-01 (partial); PR.AA-05 (related) | designed | none |
| [164.308(a)(1)(ii)(a)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Risk analysis (R) | ID.RA-05 (partial) | partial | 1.2.3 |
| [164.308(a)(1)(ii)(B)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Risk management (R) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(1)(ii)(C)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Sanction policy (R) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(1)(ii)(D)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Information system activity review (R) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(2)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Assigned security responsibility (standard) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(3)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Workforce security (standard) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(3)(ii)(A)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Authorization and/or supervision (A) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(3)(ii)(B)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Workforce clearance procedure (A) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(3)(ii)(C)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Termination procedures (A) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(4)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Information access management (standard) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(4)(ii)(A)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Isolating health care clearinghouse functions (R) | None; not applicable | not-applicable | none |
| [164.308(a)(4)(ii)(B)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Access authorization (A) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(4)(ii)(C)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Access establishment and modification (A) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(5)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Security awareness and training (standard) | GV.PO-01 (equivalent) | procedural | none |
| [164.308(a)(5)(ii)(A)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Security reminders (A) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(5)(ii)(B)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Protection from malicious software (A) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(5)(ii)(C)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Log-in monitoring (A) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(5)(ii)(D)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Password management (A) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(6)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Security incident procedures (standard) | ID.IM-04 (partial) | partial | 12.10.1 |
| [164.308(a)(6)(ii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Response and reporting (R) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(7)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Contingency plan (standard) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(7)(ii)(A)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Data backup plan (R) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(7)(ii)(B)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Disaster recovery plan (R) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(7)(ii)(C)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Emergency mode operation plan (R) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(7)(ii)(D)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Testing and revision procedures (A) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(7)(ii)(E)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Applications and data criticality analysis (A) | GV.PO-01 (partial) | procedural | none |
| [164.308(a)(8)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Evaluation (standard) | GV.PO-01 (partial) | procedural | none |
| [164.308(b)(1)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Business associate contracts and other arrangements (standard) | GV.PO-01 (partial) | procedural | none |
| [164.308(b)(3)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308) | Written contract or other arrangement (R) | GV.PO-01 (partial) | procedural | none |

## 2. Physical safeguards (45 CFR 164.310)

| HIPAA | Standard or specification (R/A) | CSF 2.0 targets | Coverage | PCI DSS v4.0.1 (CDE only) |
|---|---|---|---|---|
| [164.310(a)(1)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Facility access controls (standard) | GV.PO-01 (related) | out-of-scope | none |
| [164.310(a)(2)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Contingency operations (A) | GV.PO-01 (related) | out-of-scope | none |
| [164.310(a)(2)(ii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Facility security plan (A) | GV.PO-01 (partial) | procedural | none |
| [164.310(a)(2)(iii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Access control and validation procedures (A) | GV.PO-01 (partial) | procedural | none |
| [164.310(a)(2)(iv)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Maintenance records (A) | GV.PO-01 (partial) | procedural | none |
| [164.310(b)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Workstation use (standard) | GV.PO-01 (partial) | procedural | none |
| [164.310(c)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Workstation security (standard) | GV.PO-01 (partial) | procedural | none |
| [164.310(d)(1)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Device and media controls (standard) | GV.PO-01 (partial) | procedural | none |
| [164.310(d)(2)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Disposal (R) | GV.PO-01 (partial) | procedural | none |
| [164.310(d)(2)(ii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Media re-use (R) | GV.PO-01 (partial) | procedural | none |
| [164.310(d)(2)(iii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Accountability (A) | GV.PO-01 (partial) | procedural | none |
| [164.310(d)(2)(iv)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310) | Data backup and storage (A) | GV.PO-01 (partial) | procedural | none |

## 3. Technical safeguards (45 CFR 164.312)

| HIPAA | Standard or specification (R/A) | CSF 2.0 targets | Coverage | PCI DSS v4.0.1 (CDE only) |
|---|---|---|---|---|
| [164.312(a)(1)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Access control (standard) | GV.PO-01 (partial) | procedural | none |
| [164.312(a)(2)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Unique user identification (R) | GV.PO-01 (partial) | procedural | none |
| [164.312(a)(2)(ii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Emergency access procedure (R) | GV.PO-01 (partial) | procedural | none |
| [164.312(a)(2)(iii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Automatic logoff (A) | GV.PO-01 (partial) | procedural | none |
| [164.312(a)(2)(iv)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Encryption and decryption (A) | GV.PO-01 (partial) | procedural | none |
| [164.312(b)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Audit controls (standard) | GV.PO-01 (partial) | procedural | none |
| [164.312(c)(1)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Integrity (standard) | GV.PO-01 (partial) | procedural | none |
| [164.312(c)(2)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Mechanism to authenticate electronic protected health information (A) | GV.PO-01 (partial) | procedural | none |
| [164.312(d)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Person or entity authentication (standard) | GV.PO-01 (partial) | procedural | none |
| [164.312(e)(1)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Transmission security (standard) | GV.PO-01 (partial) | procedural | none |
| [164.312(e)(2)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Integrity controls (A) | GV.PO-01 (partial) | procedural | none |
| [164.312(e)(2)(ii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Encryption (A) | GV.PO-01 (partial) | procedural | none |

## 4. Organizational requirements (45 CFR 164.314)

| HIPAA | Standard or specification (R/A) | CSF 2.0 targets | Coverage | PCI DSS v4.0.1 (CDE only) |
|---|---|---|---|---|
| [164.314(a)(1)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.314) | Business associate contracts or other arrangements (standard) | GV.PO-01 (partial) | procedural | none |
| [164.314(a)(2)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.314) | Business associate contracts (R) | GV.PO-01 (partial) | procedural | none |
| [164.314(a)(2)(ii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.314) | Other arrangements (R) | None; not applicable | not-applicable | none |
| [164.314(a)(2)(iii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.314) | Business associate contracts with subcontractors (R) | GV.SC-05 (related) | procedural | none |
| [164.314(b)(1)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.314) | Requirements for group health plans (standard) | None; not applicable | not-applicable | none |
| [164.314(b)(2)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.314) | Implementation specifications (R) | None; not applicable | not-applicable | none |

## 5. Policies, procedures, and documentation (45 CFR 164.316)

| HIPAA | Standard or specification (R/A) | CSF 2.0 targets | Coverage | PCI DSS v4.0.1 (CDE only) |
|---|---|---|---|---|
| [164.316(a)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.316) | Policies and procedures (standard) | GV.PO-01 (partial) | procedural | none |
| [164.316(b)(1)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.316) | Documentation (standard) | GV.PO-01 (partial) | procedural | none |
| [164.316(b)(2)(i)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.316) | Time limit (R) | GV.PO-01 (partial) | procedural | none |
| [164.316(b)(2)(ii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.316) | Availability (R) | GV.PO-01 (partial) | procedural | none |
| [164.316(b)(2)(iii)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.316) | Updates (R) | GV.PO-01 (partial) | procedural | none |

