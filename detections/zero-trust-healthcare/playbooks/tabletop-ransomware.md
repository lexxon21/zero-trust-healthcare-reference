# Contoso Regional Health (fictional): ransomware tabletop exercise kit

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

A facilitator-ready discussion exercise for Contoso Regional Health (fictional), built on attack path AP-4 (`threat-models/zero-trust-healthcare/attack-paths.md`) and on the companion playbook `ir-ransomware.md`. Each inject asks the group to make decisions RD1 to RD17 from that playbook with the information a real team would have at that hour, and the evaluation checks the decisions against the playbook, ADR-008, ADR-009, and `grc/zero-trust-healthcare/notification-clocks.md`.

- **Status: reference kit.** It has not been run, and no organization has adopted it. Every role is a fictional role from the reference design, and every number in an inject is an exercise value.
- **Discussion only.** Nothing is touched: no system, account, live data, or real contact. The facilitator plays every outside party.
- **Strategy-only boundary.** The scenario names adversary behavior at the level of MITRE ATT&CK technique names, as `attack-paths.md` does, plus the outcomes the pack's rules report (for example, files renamed in bulk over SMB). It contains no attack procedures, commands, tools, malware names, payloads, or real threat actor names, and none should be added. Technical questions about how a behavior is carried out go to the parking lot; lab validation of the rules belongs to `purple-team-plan.md`, which runs only in an isolated lab.
- **Technique references** use MITRE ATT&CK Enterprise v19.2.

## 1. Purpose and fit

- **What it tests.** The decisions in `ir-ransomware.md`: who makes them, with which inputs, in what order, and where the playbook gives no answer. SP 800-61 Rev. 3 rates ID.IM-02, improvements identified from security tests and exercises, as high priority for incident response, and its note on that outcome points to NIST SP 800-84 for tabletop discussions and other forms of exercises.
- **HIPAA.** The contingency plan standard includes testing and revision procedures, an addressable implementation specification: "Implement procedures for periodic testing and revision of contingency plans." (45 CFR 164.308(a)(7)(ii)(D)). This exercise tests the decisions in `ir-ransomware.md` that start or depend on the emergency mode operation plan (164.308(a)(7)(ii)(C)) and the disaster recovery plan (164.308(a)(7)(ii)(B)), and the security incident procedures themselves (164.308(a)(6)(i)), including response and reporting (164.308(a)(6)(ii)). Contoso's emergency mode procedures and its restore procedures are outside this design set (`ir-ransomware.md` section 3.1; ADR-009), so the exercise tests the decisions that invoke them, not the procedures.
- **What it does not test.** It restores nothing, so it is not a restore test under ADR-009 decision 3, and it does not replace ADR-008's failure-mode drills. Lab validation of the rules that trigger the playbook is designed separately, in `purple-team-plan.md` (PX-01 to PX-04, PX-18, and PX-05 for the Tier 0 option). None has been run, so every rule is still an untested template (`coverage-map.md` section 1), and SG-03 has no exercise in the plan.
- **Proposed rule, not in force.** The January 2025 HIPAA Security Rule NPRM proposes written procedures for testing and revising security incident response plans (proposed 45 CFR 164.308(a)(12)(ii)(A)(2)). It is a proposal, not final as of 2026-10-07 (the 2026 Unified Agenda lists it under Long-Term Actions; `research/zero-trust-healthcare/hipaa-security-rule-nprm-status.md`), and this kit does not rely on it.
- **Format.** The kit follows FEMA's Homeland Security Exercise and Evaluation Program (HSEEP) doctrine (January 2020) for a discussion-based exercise: objectives, a scenario, facilitated discussion, a hot wash, evaluation, and an After-Action Report/Improvement Plan (AAR/IP) that documents strengths, areas for improvement, and corrective actions. The kit's injects are timed scenario updates; HSEEP itself defines an inject as a Master Scenario Events List event for operations-based play. CISA's Tabletop Exercise Packages offer comparable templates, including an after-action report.

## 2. Objectives

| ID | Objective | Playbook decision points | Requirement or outcome |
|---|---|---|---|
| O1 | Declare and scope the incident within the first hour from the pack's signals, set severity, and record Day 0 with its basis | RD1, RD2, RD3 | DE.AE-08; RS.MA-02; 45 CFR 164.404(a)(2) |
| O2 | Contain under the clinical safety gate, and choose downtime and broad containment knowing the clinical consequence of each action | RD4, RD5, RD6 | 164.308(a)(7)(ii)(C); RS.MI-01 |
| O3 | Establish whether recovery is possible, from which copy, in what order, and on what evidence, when no restore test evidence exists (RR-11) | RD7, RD8, RD9 | 164.308(a)(7)(ii)(B) and (D); RC.RP-03; ADR-009 |
| O4 | Run the breach risk assessment from the presumption of breach and document it either way | RD2, RD10, RD11 | 45 CFR 164.402; 164.414(b) |
| O5 | Sequence notices and reports from one timeline: individuals, HHS, media, card brands, business associates, and law enforcement | RD11 to RD14 | RS.CO-02; `notification-clocks.md` section 6 |
| O6 | Run the executive decision process for a ransom demand: who decides, who advises, which inputs, and how the decision is recorded | RD15 | GV.RM-03; GV.RR-02 |
| O7 | Apply return-to-use and closure criteria, including reconciliation of downtime records | RD16, RD17 | RC.RP-04 to RC.RP-06 |

## 3. Participants

| Seat | Fictional role | Decision points it plays |
|---|---|---|
| Facilitator | Exercise lead | Runs the clock, reads injects, answers questions of fact, plays the simulation cell: the FBI, CISA, the cyber insurer, the EHR vendor, a reporter, and the text of the ransom note |
| Evaluators | One per two objectives | Rate the objectives (section 8); do not play |
| Note-taker | Exercise staff | Keeps the decision log (section 8.2) |
| Incident commander | Security operations manager on call, then the CISO at SEV-1 | RD1 to RD4, RD6, RD8, RD9, RD14, RD16, RD17 |
| Executive sponsor | Chief Executive Officer | RD15, enterprise shutdown or rebuild decisions |
| SOC analyst lead | Security operations | Triage and scoping (playbook section 6.1) |
| Identity responder | Tier 0 administrator | RD3 and identity playbook Branches A and D |
| Infrastructure lead | VP Infrastructure | RD6, RD7, RD8 |
| Recovery-plane administrator | Administrator in the recovery plane's own administrative domain (ADR-009 decision 2) | RD7 |
| System owner | Owner of the affected clinical application, for example the EHR | RD8; confirms that each restored application works, sign-in included, before RD16 (ADR-009 decision 3) |
| Clinical lead | Chief Medical Information Officer | RD4 to RD6, RD9, RD16 |
| Nursing operations | Chief Nursing Officer delegate | Clinical notification, downtime on the units |
| Emergency management lead | Emergency management | RD5: emergency operations plan, diversion, regional coordination |
| Clinical engineering | Director of Clinical Engineering | Medical devices under the clinical safety gate |
| Privacy officer | Privacy | RD2, RD10, RD11 |
| Compliance officer | Compliance | RD12 |
| Counsel | Legal | RD13, RD14, advice on RD15 |
| Communications lead | Communications | Holding statements, patients, staff, media |
| Finance lead | Finance | Insurer contact, financial inputs to RD15 |
| Vendor manager | Supplier management | RD13 |

If the group must be small, the minimum is the incident commander, the clinical lead, the infrastructure lead, the privacy officer, counsel, and the executive sponsor; the facilitator then plays the other seats only to supply facts.

## 4. Ground rules

1. **No fault.** The exercise tests the plan and the design, not the people.
2. **Decide with what the inject gives.** Ask the facilitator for facts, not for answers. The facilitator does not say which decision is right.
3. **Use the playbook as written.** Where it gives no answer or the wrong one, say so: that is a finding, not a failure of the group.
4. **Log every decision** with its RD number, owner, exercise time, and the inputs used.
5. **The clock is compressed.** The facilitator moves it. T+0 is the exercise clock, not HIPAA Day 0; the group decides Day 0 at RD2.
6. **Nothing real is touched or contacted.** The simulation cell plays every outside party.
7. **Strategy only.** No attack procedures, commands, tools, malware names, or payloads are introduced, and the actor stays unnamed: the scenario attributes nothing to a real group. "How did they do that" questions go to the parking lot.
8. **Exercise play is not advice.** What counsel says in the exercise is exercise play, not legal advice.
9. **No attribution outside the room.** The after-action report records roles, not names.
10. **Real-world stop.** If a real incident or a patient care need arises, anyone may call the agreed stop phrase and the exercise pauses.

## 5. Logistics and timing

Example timings for a four-hour session:

| Block | Time |
|---|---|
| Welcome, ground rules, scenario read-out | 15 minutes |
| Injects 1 to 3 | 30 minutes each |
| Break | 15 minutes |
| Injects 4 and 5 | 30 minutes each |
| Inject 6 (optional) | 20 minutes |
| Hot wash (section 9) | 25 minutes |

**Materials for every player.** `ir-ransomware.md` (printed); `notification-clocks.md` section 1 (clock summary) and section 6 (decision table); the ADR-008 decision table and its failure modes; the four ADR-009 requirements; the AP-4 one-line summary from `attack-paths.md`; a blank decision log.

**Facilitator preparation.**

- Choose the recovery condition (A or B) and the Tier 0 option (on or off) in section 6.2, and whether to run inject 6.
- Assign evaluators to objectives and give them section 8.
- Agree the real-world stop phrase.
- Read section 6.2 and the facilitator notes in every inject. Players never see them.

## 6. Scenario

### 6.1 Read-out for players

It is an ordinary Monday night at Contoso Regional Health (fictional): three hospitals, 22 clinics, and the datacenter running as normal. The overnight security operations analyst is working the alert queue. Clinical staff are on night shift. Everything else the group learns, it learns from the injects.

### 6.2 Facilitator background (do not read aloud)

The scenario follows AP-4 at the level of `attack-paths.md`:

- **About two weeks before T+0.** A workforce member at Hospital 2 opens a malicious attachment on a managed workstation, T1566.001 (Phishing: Spearphishing Attachment) and T1204.002 (User Execution: Malicious File).
- **The following days.** The intruder runs commands and explores the network, T1059 (Command and Scripting Interpreter), T1018 (Remote System Discovery), and T1135 (Network Share Discovery).
- **About ten days before T+0.** From a Hospital 2 workstation, the intruder requests service tickets for service accounts, T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting). Defender for Identity raises an alert that nobody acts on (inject 3). One of the accounts is the integration engine's laboratory interface account, which the intruder uses from then on (inject 2).
- **Over the last week before T+0.** A group of workstations at Hospital 2 is still waiting for the host firewall policy, because the phased rollout (`05-ztmm-maturity-roadmap.md` WP-2.1) has not reached them: the condition `threat-model.md` TM-A2 describes. The intruder moves between them, T1021.002 (Remote Services: SMB/Windows Admin Shares) and T1570 (Lateral Tool Transfer), and DX-08 returns results that nobody acts on (inject 1).
- **About five days before T+0.** From a Hospital 2 workstation, files from shares on a `RES-FILES` server are copied to an internet storage service, T1567.002 (Exfiltration Over Web Service: Exfiltration to Cloud Storage). No pack rule watches this (`coverage-map.md` section 4).
- **The evening before T+0.** Attempts to turn off endpoint protection on several workstations, T1685 (Disable or Modify Tools), which tamper protection blocks.
- **Tier 0 on only, 00:50 on the night of T+0.** Directory replication is requested from a workstation, T1003.006 (OS Credential Dumping: DCSync), AP-5 step 4 (inject 3).
- **Around T+0.** Recovery inhibition, T1490 (Inhibit System Recovery), then encryption, T1486 (Data Encrypted for Impact), and stopped services, T1489 (Service Stop).

**Adjustable conditions.**

| Condition | Option | What changes |
|---|---|---|
| Recovery | A: decisions 1, 2, and 4 met; decision 3 not met | The copies meet ADR-009 decisions 1 and 2, and the recovery plane's own audit trail (decision 4) shows denied attempts to delete copies. No restore has ever been tested, so decision 3 is not met and restore times are unknown (RR-11) |
| Recovery | B: decisions 1 and 2 not met | The most recent copies were administered with production domain credentials and have been deleted. One offline copy about 30 days old (exercise value) is in custody. This is a finding against ADR-009 decision 2 (production credentials reached the copies) and decision 1 (none of the recent copies was immutable). The 30-day interval between offline copies bounds the data a restore from it loses (ADR-009 consequences) |
| Tier 0 | On | Inject 3 adds a directory replication request from a workstation (DX-06), and the identity playbook's Branch D runs. Tier 0 control gives the intruder its route to the PACS and EHR servers (inject 3 notes) |
| Tier 0 | Off | No Tier 0 signal; the identity playbook's Branch A runs for the accounts involved. How the intruder reached the PACS and EHR servers stays an open question for the after-action report (inject 3 notes) |

Both recovery conditions are exercise states. In the reference design, none of the four ADR-009 requirements is implemented (RR-11).

Do not add technical detail beyond technique names and the rule outputs in the injects. If players ask how a step was done, answer "the logs show the behavior; the method is out of scope for this exercise" and add the question to the parking lot. Questions about which control should have stopped a step are in scope: answer them from the design documents.

## 7. Injects

Each inject has a situation to read aloud, notes for the facilitator only, the decisions the group is expected to reach, and discussion questions. Expected decisions describe what the playbook asks for; the group may decide differently, and the difference is what the evaluation records.

### Inject 1: T+0 (Tuesday, 01:40)

**Situation.** The overnight analyst escalates to the on-call security operations manager. DX-01 has returned two behaviors each, shadow copy deletion and boot recovery turned off, on two PACS servers in `Z-CLIN-APP`, in the datacenter, that serve Hospital 2. Earlier, at 22:15, DX-09 reported attempts to turn off endpoint protection on three shared clinical workstations at Hospital 2, which tamper protection blocked; the alert was triaged as low priority and is still open. DX-08 shows SMB connections between `Z-CLIN-USER` workstations at Hospital 2 over the past week. No clinical complaints have come in.

**Facilitator notes.** The DX-09 alert at 22:15 is the most recent open signal, not the first. DX-08's results from the past week came earlier, and inject 3 surfaces a Kerberoasting alert older still. Each bears on Day 0, because an alert that sat unworked in a queue can set an earlier Day 0 if reasonable diligence would have revealed the breach from it (playbook RD2). Attack disruption has not acted yet. The on-call clinical lead has to be reached at night.

**Expected decisions.** RD1: declare at SEV-1 (the staging pattern on servers in `Z-CLIN-APP`). RD2: open one timeline and decide Day 0. RD3: check for Tier 0 signals. RD4: decide whether to isolate the PACS servers now, which needs the incident commander and the clinical lead.

**Discussion questions.**

1. Who is called first, by whom, and on which channel, if the intruder might be reading Contoso's own messaging?
2. Is a two-behavior DX-01 result on a PACS server enough to declare at 01:40? What would change the answer?
3. The DX-09 alert sat for more than three hours, and DX-08 has returned results for a week. When is Day 0, and who records it?
4. Who can authorize isolating a PACS server at night, and what happens to imaging at Hospital 2 if they do?
5. DX-08 is an assurance rule. What does a week of peer SMB results say about `PEP-HOST` at Hospital 2?

### Inject 2: T+30 minutes

**Situation.** DX-02 fires: a process on a shared clinical workstation is renaming thousands of files on a departmental share in `RES-FILES` over SMB, under a nurse manager's account. Ransom notes appear in the shares. Radiology at Hospital 2 reports that PACS viewers are failing. Defender XDR shows that automatic attack disruption has contained 14 workstations at Hospital 2 and one of the PACS servers, and has disabled the nurse manager's account and a service account that the integration engine uses for its laboratory interface. Laboratory results stop arriving in the EHR at all three hospitals. Clinical engineering reports that the imaging modalities at Hospital 2 are still sending new studies to the PACS server that attack disruption contained.

**Facilitator notes.** ADR-008's attack disruption exclusions cover only medical devices and named clinical accounts, so attack disruption can contain a PACS server on its own. The clinical lead has to hear about it at once, and releasing it is a decision for the incident commander and the clinical lead after evidence that the attacker's access to it is removed (playbook section 6.2). The interface service account should have been an attack disruption exclusion (ADR-008; playbook section 3.1), and it was not: that is a finding. It is also one of the accounts whose service tickets were requested about ten days earlier (inject 3 surfaces the alert), and the intruder has been using it, which is why attack disruption acted. Re-enabling it without the password resets in identity playbook Branch A restores the intruder's access along with the interface, and a reset stops the interface until the integration engine holds the new credential, so the clinical impact check (identity playbook D5) comes first. Had the exclusion been in place, attack disruption would have left a compromised account working: an exclusion moves containment to a person, it does not make the account safe. The preventive answer sits at AP-4 step 6 and AP-5 step 3 in `attack-paths.md` (AES encryption types, group managed service accounts, tiering). The modalities are medical devices, are not compromised, and are not onboarded to Defender for Endpoint. Microsoft documents that containment applies a policy on all onboarded devices to block communication from the contained device, and does not say that traffic from devices that are not onboarded stops, so the playbook plans on the modalities' flow to the contained server continuing (playbook section 6.3). The onboarded workstations that run PACS viewers can no longer reach it, while new studies keep landing on a server with DX-01 results from inject 1. Cutting that flow (F-08) is done at `PEP-NET-ZONE`, through the clinical safety gate for devices in patient use (`04-segmentation.md` section 3), and it stops studies reaching PACS; what each modality does without its server, and the workaround, are for clinical engineering and the clinical lead (playbook section 6.3). The nurse manager is on shift at Hospital 2.

**Expected decisions.** RD4: the identity responder decides about the interface service account after a clinical impact check, and runs identity playbook Branch A for the nurse manager's account with the clinical notification step. RD4: whether to cut the modalities' flow to the contained PACS server (F-08) at `PEP-NET-ZONE`, decided through the clinical safety gate with clinical engineering and the clinical lead, and no action on the modalities themselves. RD5: downtime for PACS at Hospital 2 and for laboratory results at all sites. RD6: decide whether to isolate Hospital 2's WAN path to the datacenter, knowing its consequence.

**Discussion questions.**

1. Do you re-enable the interface service account? What has to be true first?
2. Laboratory results are not reaching the EHR at three hospitals. Who decides downtime for them, and how do clinicians get critical results in the meantime?
3. If you cut Hospital 2's WAN path to the datacenter, what does ADR-008 say happens to clinical access there? Is that better or worse than the risk of spread?
4. Does anyone power anything off? Why or why not?
5. Who tells the nurse manager's unit that her account is disabled, and what do they do instead?
6. Attack disruption contained a PACS server on its own. Who was told, and who decides whether and when it is released?
7. ADR-008 says the interface account should have been excluded from automatic disable. If it had been, what would have stopped the intruder using it?
8. Imaging modalities are still sending studies to the contained PACS server. Do you cut that flow (F-08) at `PEP-NET-ZONE`? Who decides through the clinical safety gate, and what do imaging staff do if it is cut?

### Inject 3: T+2 hours

**Situation.** The EHR database tier stops responding, and DX-02 fires on a database server. The EHR is unavailable at every site. Scoping finds a Defender for Identity Kerberoasting alert from about ten days ago, raised from a Hospital 2 workstation, which DX-05 reported as a single stage. *(Tier 0 on: DX-06 shows directory replication requested from a workstation at 00:50 today.)* SN-05 shows failed attempts to delete backup items that protect the patient portal's Azure workloads. The recovery-plane administrators report *(condition A)* denied attempts in the recovery plane's audit trail to delete copies and shorten their retention, with every copy intact, or *(condition B)* that the backup server was administered with production domain credentials, its recent copies are deleted, and the only surviving copy is an offline copy about 30 days old.

**Facilitator notes.** Enterprise EHR downtime is now a fact. With Tier 0 on, identity playbook D4 and Branch D apply, and the krbtgt resets need clinical scheduling because every site re-authenticates. Condition B is a finding against ADR-009 decisions 1 and 2. With Tier 0 on, the premise is that one of the service accounts whose tickets were requested held rights that let it request directory replication, the exposure `threat-model.md` TB-4 records where silos are incomplete; the after-action report records it as a design finding. Tier 0 control also gives the intruder a route to the PACS and EHR servers through the domain's own management channels, since those servers accept administrative protocols only from `Z-MGMT` (`04-segmentation.md` section 1). DX-05 does not chain the Kerberoasting and replication alerts, because they are about ten days apart and its chain window is 24 hours; DX-06 reports the replication on its own. The identity signals reach AP-5 step 4 and no further. SN-05's failed attempts are an attempt at the Azure part of AP-5 step 9 (playbook section 1); nothing shows the sync servers or the cloud administration behind them (AP-5 steps 6 to 8). With Tier 0 off, how the intruder reached those servers stays open in play: the design leaves `Z-MGMT`, a vendor session, or an exploited application service, and the after-action report records the question. Privileged cloud accounts are cloud-only and not synchronized (ADR-004), so which account made the SN-05 attempts, and how it reached Azure at all, is an RD3 question.

**Expected decisions.** RD5: enterprise downtime for the EHR, and the emergency operations plan activated. RD3: Tier 0 handling if on. RD7: whether the copies are intact and out of reach. RD6: whether broader isolation is now needed.

**Discussion questions.**

1. Who activates enterprise-wide EHR downtime and the emergency operations plan? Who decides about diversion and regional coordination?
2. How does anyone confirm the copies are intact without using production credentials?
3. How long will it take to restore the EHR database? What evidence supports that estimate?
4. *(Tier 0 on.)* When are the krbtgt resets done, and who tells the hospitals that every site will re-authenticate?
5. *(Condition B.)* Is a 30-day-old copy acceptable for the EHR? What does it mean for data entered since then and for the downtime records?

### Inject 4: T+6 hours

**Situation.** Counsel has read the ransom note. It demands payment in cryptocurrency within 72 hours (exercise value) and claims the actor has taken patient data, threatening to publish it. A local reporter calls the communications lead to ask whether ambulances are being diverted. Staff are posting about the downtime on social media. The chair of the board calls the Chief Executive Officer. The cyber insurer, if Contoso has one, asks to be briefed.

**Facilitator notes.** The exercise does not require a decision on payment. The evaluators look at the process: who is in the room, which inputs from playbook section 6.6 are available, and how the decision is recorded. The data theft claim is unverified at this point.

**Expected decisions.** RD15: convene the executive decision group and gather the section 6.6 inputs. RD14: decide on reports to the FBI and CISA, with counsel. RD10: start the breach risk assessment from the presumption of breach. Communications: a holding statement.

**Discussion questions.**

1. Who is in the executive decision group, and who advises it? Who is missing?
2. Which inputs from playbook section 6.6 can you answer now, and which can you not?
3. What does Treasury's OFAC advisory change about the decision process, whatever the decision turns out to be?
4. Has Contoso reported to the FBI and CISA? Who made that call, and on what basis?
5. What does the holding statement say, and what must it not say?
6. HHS presumes a breach in a ransomware attack (HHS Update #4, May 2017; playbook section 7.1). Does the claim of data theft change the breach analysis, and what evidence would the privacy officer need?

### Inject 5: Day 2

**Situation.** Web filter logs show a large outbound transfer five days before T+0, from a Hospital 2 workstation to an internet file-sharing service, of files copied from shares on a `RES-FILES` server. Those shares hold clinical documents for an estimated 40,000 patients living in two States (exercise values). Restore planning has started, and the earliest evidence of intrusion is about two weeks before T+0. The EHR vendor offers remote restore support through the vendor broker. A restored EHR reporting database cannot be opened, because the certificate that protects its encryption key was kept only on the encrypted server. The patient portal team asks whether online payments can resume.

**Facilitator notes.** The transfer is evidence for the third risk assessment factor (whether PHI was actually acquired or viewed). It left through a workstation because that is the route the zone design leaves: `Z-CLIN-USER` reaches file services and filtered internet, while `Z-CORP-APP` initiates only to `Z-T0` and Microsoft cloud (`04-segmentation.md` section 2). The design routes only server and device zones through the egress proxy and leaves the workstation filter unspecified; the exercise assumes it is a web filter that logs transfers. With 500 or more individuals, HHS is notified at the same time as individuals, and media where more than 500 residents of a State are affected (`notification-clocks.md` section 2.3). The certificate is a key custody gap: ADR-009 puts the keys and certificates inside the data in scope of the copies, kept apart from the data they unlock (`02-reference-architecture.md` section 7; ADR-009, scope of the copies). The playbook sets the latest acceptable copy for each system from the earliest evidence that the intruder reached it, and falls back to the intrusion's earliest evidence, about two weeks before T+0, where scoping cannot establish that (playbook section 6.5 step 2). Vendor access needs a new activation approved by the system owner (F-06). `RES-PORTAL` was not encrypted, and the redirect page's change monitoring shows no change, so card data is likely not involved, but only after that check is documented (ADR-007 decision 6).

**Expected decisions.** RD8 and RD9: the restore point, restore or rebuild, and the order. RD10 and RD11: the assessment and the notices. RD12: card data. RD13: vendor access and business associate terms.

**Discussion questions.**

1. Which copy do you restore from, for each system, given an intrusion that started about two weeks before T+0 and the retention you have? How do you show the copy is clean?
2. Restore or rebuild the EHR application servers? In what order do the clinical applications come back, and who decided that order before today?
3. The certificate is gone. What does that mean for that data, and where should it have been kept?
4. With the transfer evidence, can the four-factor assessment show a low probability of compromise? Which notices follow, by when, and counted from which Day 0?
5. Can the EHR vendor connect? What approval is needed, and who watches the session?
6. Can online payments resume? What has to be checked, and recorded, to rule out card data?
7. The transfer went out through the workstation's filtered internet access, which the exercise assumes is a web filter. Why did the filter allow an internet file-sharing service, and who owns that decision?

### Inject 6 (optional): Day 5

**Situation.** An FBI agent calls and says that notifying patients now would impede the criminal investigation, and asks Contoso to hold its patient notices. PACS and the laboratory information system are restored and verified at Hospital 2. The EHR is restored, but its downtime records are not yet reconciled. A file listing that appears to come from Contoso's shares is posted on the actor's leak site.

**Facilitator notes.** 164.412 applies when a law enforcement official states that a notice would impede a criminal investigation or damage national security. An oral statement is documented, including the official's identity, and the delay runs no longer than 30 days from the oral statement unless a written statement follows in that time (`notification-clocks.md` section 2.3). Returning the EHR to use requires reconciliation of downtime records (RR-13).

**Expected decisions.** RD11 timing under 164.412. RD16 for each system. The path to RD17.

**Discussion questions.**

1. How is the FBI's oral request recorded, and how long can it delay the notices without a written statement?
2. Is the EHR ready to leave downtime? What must happen to the downtime records first?
3. What are the closure criteria, and who declares the end of recovery?
4. What would you change in the playbook today?

## 8. Evaluation

### 8.1 Criteria

Rate each objective as Met, Partly met, Not met, or Not observed (this kit's scale). Record the evidence for each rating from the decision log.

| Objective | Met when the group |
|---|---|
| O1 | Declares within inject 1, sets severity, names an incident commander, opens one timeline, records Day 0 with its basis (including the open DX-09 alert, the earlier DX-08 results, and, once inject 3 surfaces it, the Kerberoasting alert), and checks for Tier 0 signals |
| O2 | Names who is told when attack disruption contains a clinical server and who may isolate or release one, applies the clinical notification step, keeps medical devices out of automatic action, hears the clinical consequence before broad containment, and prefers isolation to powering off |
| O3 | Confirms the copies only from recovery-plane devices, states that no restore evidence exists, picks a copy for each system by the earliest evidence that the intruder reached it (falling back to the intrusion's earliest evidence), restores identity systems first, and recognizes the key custody gap |
| O4 | Starts from the presumption of breach, checks whether an exclusion applies and whether the PHI was secured, records what was searched for data theft and over which period, works through the four factors, and documents the result either way |
| O5 | Takes every clock from `notification-clocks.md`, sequences the notices from one timeline, applies business associate terms, handles the oral delay request under 164.412, and schedules nothing under a rule that `notification-clocks.md` section 5 lists as proposed or not final on the day of the exercise (on 2026-10-07: the CIRCIA rule and the HIPAA Security Rule NPRM) |
| O6 | Names the decision group and its advisors, works from the playbook section 6.6 inputs, records the rationale, and keeps any contact with the actor under counsel's direction |
| O7 | States per-system return criteria, reconciles downtime records before ending downtime, names who declares the end of recovery, and assigns the after-action report |

### 8.2 Decision log

| Exercise time | RD | Decision | Owner | Inputs used | Playbook section followed, or missing |
|---|---|---|---|---|---|
| | | | | | |

## 9. Hot wash

Immediately after the last inject:

1. What went well?
2. Where did the playbook give no answer, or the wrong one?
3. What did you need that you did not have?
4. Which decision took longest, and why?
5. What will you change in the next 30 days, and who owns it?

## 10. After-action report template

The template follows the AAR/IP structure that FEMA describes for HSEEP: strengths, areas for improvement, and corrective actions. It records roles, not names.

```markdown
# After-action report: ransomware tabletop, <date>

## 1. Exercise overview
- Date, duration, facilitator role, evaluator roles
- Participating roles (no names)
- Conditions run: recovery A or B; Tier 0 on or off; inject 6 run or not
- Artificialities and limits (discussion only, compressed time)

## 2. Objectives and ratings
| Objective | Rating | Evidence (decision log entries) |
|---|---|---|

## 3. Strengths
- <observation, with objective and RD reference>

## 4. Areas for improvement
| ID | Observation | Objective | RD | Playbook or design reference | Likely cause |
|---|---|---|---|---|---|

## 5. Playbook and design defects
| Document | Section | Defect | Proposed change |
|---|---|---|---|

## 6. Improvement plan
| ID | Corrective action | Owner role | Due date | Status | How completion is verified |
|---|---|---|---|---|---|

## 7. Parking lot
- <questions deferred during the exercise>

## 8. Sign-off
- Incident commander role, clinical lead, CISO; date
```

Changes that come out of the report go back into `ir-ransomware.md`, ADR-008 or ADR-009 where a design gap is found, and `coverage-map.md` where a detection gap is found (ID.IM-02, ID.IM-04).

## Sources

The regulatory clocks rest on primary sources that `notification-clocks.md` cites. The threat and design facts come from the companion documents named in the text.

| Title | Publisher | URL | Date checked | Quality |
|---|---|---|---|---|
| SP 800-61 Rev. 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile (April 2025) | NIST | https://csrc.nist.gov/pubs/sp/800/61/r3/final | 2026-10-07 | primary |
| 45 CFR 164.308(a)(6) and (a)(7), read through the eCFR versioner API at point in time 2026-09-30 | Office of the Federal Register, eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308 | 2026-10-07 | primary |
| HIPAA Security Rule To Strengthen the Cybersecurity of Electronic Protected Health Information (proposed rule), 90 FR 898 | Federal Register | https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information | 2026-10-07 | primary |
| Unified Agenda 2026, RIN 0945-AA22 (Long-Term Actions; final action 07/00/2027) | reginfo.gov | https://www.reginfo.gov/public/do/eAgendaViewRule?pubId=202510&RIN=0945-AA22 | 2026-10-07 | primary |
| HHS Update #4: International Cyber Threat to Healthcare Organizations (Revised), May 16, 2017 | HHS, hosted by ASPR TRACIE | https://files.asprtracie.hhs.gov/documents/hhs-update-4-international-cyber-threat-to-healthcare-orgs.pdf?cb=4339 | 2026-10-07 | primary |
| Homeland Security Exercise and Evaluation Program (HSEEP) doctrine, January 2020 (supersedes the 2013 version; FEMA's HSEEP page says the latest revision was released in February 2020) | FEMA | https://www.fema.gov/emergency-managers/national-preparedness/exercises/hseep (doctrine PDF: https://www.fema.gov/sites/default/files/2020-04/Homeland-Security-Exercise-and-Evaluation-Program-Doctrine-2020-Revision-2-2-25.pdf) | 2026-10-07 | primary |
| CISA Tabletop Exercise Packages | CISA | https://www.cisa.gov/resources-tools/services/cisa-tabletop-exercise-packages | 2026-10-07 | primary |
| #StopRansomware Guide, version 3.0 (October 2023) | CISA, FBI, NSA, and MS-ISAC | https://www.cisa.gov/resources-tools/resources/stopransomware-guide | 2026-10-07 | primary |
| Updated Advisory on Potential Sanctions Risks for Facilitating Ransomware Payments (September 21, 2021) | U.S. Department of the Treasury, Office of Foreign Assets Control | https://ofac.treasury.gov/media/912981/download | 2026-10-07 | primary |
| Automatic attack disruption in Microsoft Defender (Contain device: a policy on all onboarded devices blocks communication from the contained device) | Microsoft Learn | https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption | 2026-10-07 | primary |
| Breach and incident notification clocks (companion artifact, with its own primary sources) | This repository | `grc/zero-trust-healthcare/notification-clocks.md` | 2026-10-07 | secondary (companion summary of primary sources) |
