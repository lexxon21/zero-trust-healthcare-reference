# ADR-006: Medical devices: passive discovery and network-enforced segmentation by device class

> **Reference work.** Fictional scenario built for a public portfolio. Not deployed in, derived from, or describing any employer environment. Not professional advice.

| Field | Value |
|---|---|
| Status | Accepted (reference design) |
| Date | 2026-10-03 |
| Revised | 2026-10-04 |
| Decision owners (fictional roles) | CISO, Director of Clinical Engineering, Chief Nursing Officer, VP Infrastructure |
| Scope | About 6,000 connected medical and IoMT devices (`RES-IOMT`) |
| Related | `04-segmentation.md` section 3, ADR-001, ADR-008 |

## Context

Most of Contoso Regional Health's (fictional) medical devices cannot run an endpoint agent. Their operating systems are patched or changed only by the manufacturer (A-11), and some of them keep patients alive. Verified facts (checked 2026-10-03):

- **ZTNA is out.** Microsoft Entra Private Access traffic can only be captured by the Global Secure Access client, so agentless devices cannot use it.
- **The maturity model does not cover these devices.** The CISA ZTMM v2.0 states that it does not address challenges specific to operational technologies or certain classes of internet of things devices.
- **Passive monitoring of medical protocols exists.** Defender for IoT network sensors monitor agentless devices at the network layer, from switch SPAN, RSPAN, ERSPAN, or network TAPs. Microsoft's supported-protocols list includes the medical protocols ASTM, HL7, DICOM, and POCT1. OT sensor licensing is per site, and Microsoft's definition of a site includes a hospital.
- **Endpoint-based discovery can probe actively.** Defender for Endpoint device discovery in Standard mode uses active scanning. Basic mode only observes passively, and Microsoft recommends it for sensitive or legacy networks. Standard-mode scans can be limited to tagged scanner devices, and subnets can be excluded.
- **Containment by endpoints has limits.** Defender for Endpoint's "contain" action is enforced by onboarded Windows endpoints, so it does not block traffic between two unmanaged devices.
- **Procurement levers.**
  - The MDS2 form is defined by ANSI/NEMA HN 1-2019. FDA recognizes the standard and notes it may not satisfy every requirement in Section 524B.
  - Section 524B of the FD&C Act applies to manufacturers of cyber devices through premarket submissions, and requires a software bill of materials.

## Decision

1. **Discover passively.** `PIP-IOMT-SENSOR` sensors are placed on mirrored traffic at each hospital core. Defender for Endpoint discovery never actively probes medical device subnets: either Basic mode, or Standard mode limited to tagged corporate scanners with medical subnets excluded. Results feed `PIP-ASSET-INV`, joined to clinical engineering's records. The 22 clinics have no sensor: their devices are classified through NAC profiling and clinical engineering's records, with no sensor-based anomaly detection (RR-14).
2. **Segment by device class:** imaging, monitoring, infusion, laboratory, pharmacy, general, and an onboarding and quarantine segment (`04-segmentation.md` section 3). Each segment's allowed flows go only to its own servers, with no lateral traffic between segments and no general internet.
3. **Admission.** `PE-NETWORK` admits devices with 802.1X EAP-TLS where they support it, and otherwise with MAC Authentication Bypass plus classification (the sensor's at the hospitals, NAC profiling alone at the clinics). Unknown devices land in `Z-IOMT-ONBOARD`.
4. **Enforce per segment, in order:** observe, draft, simulate, enforce, monitor. Each move to enforcement happens in a clinical change window, with clinical engineering sign-off and a rollback plan.
5. **Clinical safety gate.** Automated network containment is allowed only for devices that are not medical devices. A medical device in active patient use is never disconnected automatically. Containment is narrowed to the anomalous flow, and clinical leads decide on swapping the device. Automatic attack disruption is configured to match: the medical device segments' address ranges are excluded from its automatic IP containment (ADR-008).
6. **Procurement.** Every networked device purchase requires an MDS2 form and a software bill of materials request, with security requirements written into the contract, including encryption of any ePHI the device stores. Each device's encryption status is recorded in `PIP-ASSET-INV`, and a device that cannot encrypt is an owned, dated exception (RR-15, `02-reference-architecture.md` section 7).
7. **Manufacturer connectivity** goes only through the egress proxy, with per-manufacturer destination allow-lists. Interactive service uses the vendor broker.

## Alternatives considered

### A. Agent-based device trust (rejected)

Most devices cannot run an agent, and manufacturers control their software.

### B. One flat biomedical VLAN (rejected)

A compromised device could reach every other device class. There is no per-class policy and no containment boundary.

### C. 802.1X only, with no MAC Authentication Bypass (rejected)

Most medical devices have no 802.1X supplicant. Refusing them would mean refusing clinical equipment.

### D. Active vulnerability scanning of medical devices (rejected)

Probing can disrupt fragile devices, which is a patient-safety risk. Passive data plus manufacturer advisories replace it.

### E. One segment per device everywhere from the start (rejected as the starting point)

The operational load would stall the program. Device-class segments come first, and per-device segments follow for the highest-risk devices (WP-3.5).

### F. Automated quarantine of any device that behaves anomalously (rejected)

Disconnecting a device in use can harm a patient. The clinical safety gate replaces it.

## Consequences

Positive:

- Blast radius limited per device class.
- One inventory shared by clinical engineering, NAC, vulnerability management, and the threat model.
- Visibility without touching devices.

Negative and residual:

- **MAC impersonation** on MAB ports (RR-05).
- **A compromised device** can still reach its own allowed servers (RR-04).
- **Infrastructure and licensing.** Mirrored traffic capacity is needed at each hospital core. Sensor licensing is per site, or the cost of a specialist platform.
- **Workload.** Clinical engineering carries real ongoing effort.
- **Manufacturer cloud dependencies** need maintained egress allow-lists.
- **Clinics have no passive sensor** (RR-14). Their devices are inventoried through NAC profiling and clinical engineering records, without sensor-based anomaly detection.
- **No automatic attack disruption on medical device segments.** The IP exclusions that enforce the clinical safety gate also mean Defender never contains a compromised medical device on its own (ADR-008).
- **Devices that cannot encrypt stored ePHI** (RR-15). Segmentation limits network access to the data on them; it does not protect a device or drive that is lost or stolen. Physical safeguards, location records, and media sanitization before disposal or return to the manufacturer carry that case.

## Compliance drivers

| Framework | Identifier | Why it matters here |
|---|---|---|
| HIPAA | 45 CFR 164.308(a)(1)(ii)(A), risk analysis (required); 164.308(a)(1)(ii)(B), risk management (required) | A device inventory and segmentation underpin risk analysis and risk reduction |
| HIPAA | 164.310(d)(2)(i), disposal (required); 164.310(d)(2)(ii), media re-use (required) | Decommissioning devices that stored ePHI |
| HIPAA | 164.312(a)(1), access control (standard) | Only the device-class servers reach the devices |
| HIPAA | 164.312(a)(2)(iv), encryption and decryption (addressable) | Device storage encryption where the device supports it. Devices that cannot encrypt are documented exceptions with compensating measures, as 164.306(d)(3) requires for an addressable specification (RR-15). |
| NIST CSF 2.0 | ID.AM-01, ID.AM-03, ID.AM-08, ID.RA-01, PR.IR-01, DE.CM-01, GV.SC-05, GV.SC-06, RS.MI-01 | Inventory, flows, lifecycle, vulnerabilities, network protection, monitoring, supplier requirements, containment |

## ZTMM mapping

Devices: Asset & Supply Chain Risk Management, Policy Enforcement & Compliance Monitoring. Networks: Network Segmentation. These mappings are an interpretation, because the model states that it does not address OT and certain IoT device classes.

## Revisit when

- Manufacturers broadly support 802.1X and device certificates.
- CISA publishes a model version that covers these device classes.
- The sensor platform or its licensing changes.
- Contoso's risk analysis shows that clinic devices need sensor-based anomaly detection. The options are a sensor per clinic, or remote mirroring such as ERSPAN to a hospital sensor (RR-14).
- A final HIPAA Security Rule requires automated vulnerability scanning without a medical device exception, or settles whether passive identification counts (companion research note, vulnerability management row).

## Sources

| Title | Publisher | URL | Date checked | Quality |
|---|---|---|---|---|
| Zero Trust Maturity Model Version 2.0 | CISA | https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf | 2026-10-03 | Primary |
| Enhance your OT security with Defender for IoT | Microsoft Learn | https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/overview | 2026-10-04 | Primary |
| Defender for IoT billing | Microsoft Learn | https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/billing | 2026-10-03 | Primary |
| Protocols supported by Microsoft Defender for IoT | Microsoft Learn | https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/concept-supported-protocols | 2026-10-03 | Primary |
| Choose a traffic mirroring methods | Microsoft Learn | https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/best-practices/traffic-mirroring-methods | 2026-10-04 | Primary |
| Configure device discovery in Microsoft Defender for Endpoint | Microsoft Learn | https://learn.microsoft.com/en-us/defender-endpoint/configure-device-discovery | 2026-10-03 | Primary |
| Take response actions on a device in Microsoft Defender for Endpoint | Microsoft Learn | https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts | 2026-10-03 | Primary |
| Automatic attack disruption in Microsoft Defender | Microsoft Learn | https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption | 2026-10-04 | Primary |
| Exclude assets from automated response in attack disruption | Microsoft Learn | https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption-exclusions | 2026-10-04 | Primary |
| What is Global Secure Access? | Microsoft Learn | https://learn.microsoft.com/en-us/entra/global-secure-access/overview-what-is-global-secure-access | 2026-10-03 | Primary |
| FDA Recognized Consensus Standards: ANSI/NEMA HN 1-2019 | U.S. FDA | https://www.accessdata.fda.gov/scripts/cdrh/cfdocs/cfstandards/detail.cfm?standard__identification_no=43890 | 2026-10-03 | Primary |
| Cybersecurity in Medical Devices Frequently Asked Questions | U.S. FDA | https://www.fda.gov/medical-devices/digital-health-center-excellence/cybersecurity-medical-devices-frequently-asked-questions-faqs | 2026-10-03 | Primary |
| 45 CFR 164.306, 164.308, 164.310, 164.312 | eCFR | https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C | 2026-10-04 | Primary |
