# 🛡️ SOC Lab Episode 7: Ransomware Incident Response (NIST 800-61)

![Azure](https://img.shields.io/badge/Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Microsoft Defender](https://img.shields.io/badge/Defender%20for%20Endpoint-0078D4?style=for-the-badge&logo=microsoftdefender&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-blue?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-red?style=for-the-badge)
![NIST 800-61](https://img.shields.io/badge/NIST%20800--61-green?style=for-the-badge)

## 📋 Overview

End-to-end incident response lab simulating a ransomware attack, built around the NIST 800-61 Incident Response Lifecycle. The simulated threat actor is **Akira**, emulated using Atomic Red Team (T1486-10: Data Encrypted for Impact). The lab covers the full IR cycle: preparation, detection and analysis, containment/eradication/recovery, and post-incident lessons learned.

Unlike previous episodes in this series, which focused on individual detection techniques, this lab walks through a single realistic incident from execution to closure, using Microsoft Sentinel and Microsoft Defender for Endpoint (MDE) as the primary detection and response toolset.

## 🎯 Objective

Simulate a ransomware incident on an isolated Azure VM, detect it through KQL analysis in Sentinel, and execute a full response cycle (containment, eradication, recovery) using native MDE capabilities, documenting every phase with real telemetry and timestamps.

## 🏗️ Environment

| Resource | Name |
|---|---|
| Resource Group | `rg-soc-lab-ir` |
| Log Analytics Workspace | `law-soc-lab-ir` |
| Virtual Machine | `vm-soc-lab-ir01` (Windows 11 Pro) |
| SIEM | Microsoft Sentinel (connected to `law-soc-lab-ir`) |
| EDR | Microsoft Defender for Endpoint |
| Simulation Framework | Atomic Red Team |

As with previous episodes, all Azure resources were deleted after completing the lab and rebuilt fresh for this exercise.

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|---|---|---|---|
| Impact | Data Encrypted for Impact | T1486 | Akira ransomware simulation: mass file creation with `.akira` extension and ransom note drop |

## 🔬 Simulation Details

The attack was executed using Atomic Red Team's Invoke-AtomicTest module:

```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
Invoke-AtomicTest T1486 -TestNumbers 10
```

This test (T1486-10, Akira Ransomware drop Files with .akira Extension and Ransomnote) creates 100 test files with randomized byte content under `C:\` with the `.akira` extension, then drops a ransom note (`akira_readme.txt`) on the victim's desktop, line by line, mimicking the extortion note style used by the real Akira ransomware family.

**Note:** during setup, Windows Defender flagged the Atomic Red Team atomics folder as suspicious (`Trojan:Win64/Malgent!MSR`, generic ML-based detection), since the repository bundles real offensive tooling used as prerequisites for other techniques. A scoped exclusion was applied to `C:\AtomicRedTeam` to allow the framework to operate without interference. This is expected and documented behavior for adversary emulation tooling.

---

## Phase 1: Preparation

Before executing the simulation, the environment was validated:

- MDE onboarding confirmed on `vm-soc-lab-ir01`
- MDE data connector linked to the `law-soc-lab-ir` Sentinel workspace
- Live Response capability enabled at the tenant level (`Settings > Endpoints > Advanced features`)

📸 `screenshots/01-preparation/`
- `live-response-enabled.png`
- `sentinel-workspace-connected.png`

---

## Phase 2: Detection & Analysis

### Confirming the attack executed

After running the test, the `.akira` files and the ransom note were visible directly on the file system.

📸 `screenshots/02-detection-analysis/akira-test-files-explorer.png`
📸 `screenshots/02-detection-analysis/ransom-note-desktop-icon.png`

### Finding #1: DeviceFileEvents did not capture the mass file creation

The first hunting attempt targeted `DeviceFileEvents` directly for the 100 files created in the burst:

```kql
DeviceFileEvents
| where Timestamp > ago(6h)
| where DeviceName == "vm-soc-lab-ir01"
| where FileName endswith ".akira"
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by Timestamp asc
```

This query returned no results. A broader, unfiltered query against the same table confirmed the table itself was healthy and ingesting data, but the individual `.akira` file creation events were simply not present, most likely due to MDE throttling under high-volume file creation bursts in a short time window (100 files created in under a second).

### Finding #2: Pivoting to DeviceProcessEvents

Since the file-level telemetry did not capture the burst, the investigation pivoted to process-level telemetry, which reliably captured the full command line of the process that executed the attack:

```kql
DeviceProcessEvents
| where Timestamp > ago(6h)
| where DeviceName == "vm-soc-lab-ir01"
| where ProcessCommandLine contains "akira" or ProcessCommandLine contains "Invoke-AtomicTest"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

This returned a single `powershell.exe` process event containing the entire script: a `{1..100}` loop generating randomized-content files with the `.akira` extension, followed by a series of `echo` commands writing the ransom note line by line.

📸 `screenshots/02-detection-analysis/device-process-events-query-result.png`
📸 `screenshots/02-detection-analysis/device-process-events-full-commandline.png`

### Finding #3: The ransom note was fully captured in DeviceFileEvents

Unlike the batch-created `.akira` files, the ransom note (written incrementally via multiple `echo >>` commands) was fully logged:

```kql
DeviceFileEvents
| where DeviceName == "vm-soc-lab-ir01"
| where FileName has "akira_readme"
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by Timestamp asc
```

The result showed one `FileCreated` event followed by a rapid sequence of `FileModified` events, one per line written to the file, matching the structure of the ransom note script.

📸 `screenshots/02-detection-analysis/device-file-events-ransom-note-timeline.png`
📸 `screenshots/02-detection-analysis/ransom-note-content.png`

### Detection query used for this incident

Given the findings above, the most reliable detection query for this scenario relies on process command line content rather than file event volume:

```kql
DeviceProcessEvents
| where DeviceName == "vm-soc-lab-ir01"
| where ProcessCommandLine contains ".akira" or ProcessCommandLine contains "akira_readme"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName
| order by Timestamp asc
```

---

## Phase 3: Containment, Eradication & Recovery

### Eradication

Since Live Response did not become available in time (see Lessons Learned below), the malicious artifacts were removed directly via RDP:

```powershell
Get-ChildItem 'C:\' -Filter '*.akira' | Remove-Item -Force
Remove-Item 'C:\Users\admin1\Desktop\akira_readme.txt' -Force
```

📸 `screenshots/03-containment-eradication-recovery/akira-files-before-eradication.png`
📸 `screenshots/03-containment-eradication-recovery/akira-files-after-eradication.png`
📸 `screenshots/03-containment-eradication-recovery/ransom-note-removed-desktop.png`

A process check confirmed no malicious activity remained active on the system:

```powershell
Get-Process powershell -ErrorAction SilentlyContinue
```

📸 `screenshots/03-containment-eradication-recovery/no-malicious-process-active.png`

### Containment

With the system confirmed clean, the device was isolated from MDE as the documented containment action:

- Action: **Isolate device** (Full isolation, no communication exceptions)
- Comment: *"Post-eradication containment - Simulated T1486-10 Akira Ransomware incident - SOC Lab Episode 7"*
- Submission time: Sep 3, 2026, 11:07 AM
- Status: Completed

The isolation effect was confirmed live: the active RDP session dropped immediately after the action completed, verifying that network isolation was actually enforced, not just reported as successful in the portal.

📸 `screenshots/03-containment-eradication-recovery/isolate-device-comment-confirm.png`
📸 `screenshots/03-containment-eradication-recovery/isolate-device-action-completed.png`
📸 `screenshots/03-containment-eradication-recovery/rdp-connection-lost-isolation-effect.png`

### Recovery

In a production environment, recovery would include full system integrity scanning, restoration from immutable/offline backups if legitimate data had been affected, and isolation removal only after confirming zero residual indicators of compromise. Since the malicious artifacts in this lab were synthetic and fully removed during eradication, the system was considered clean and isolation was released to close the incident cycle.

- Action: **Release from isolation**
- Comment: *"System validated clean - No residual IOCs found - Recovery phase complete - SOC Lab Episode 7"*
- Submission time: Sep 3, 2026, 11:12 AM
- Status: Completed

📸 `screenshots/03-containment-eradication-recovery/release-from-isolation-completed.png`

Total time from containment to recovery closure: **5 minutes**.

---

## Phase 4: Post-Incident Activity (Lessons Learned)

### What worked well

- Detection did not depend on file creation volume. Pivoting to `DeviceProcessEvents` and capturing the full command line of the initiating process proved to be the most reliable evidence source in the entire investigation.
- MDE's device isolation provided a clear, auditable containment action with an exact timestamp, useful for measuring incident response times.
- The ransom note was fully traceable in `DeviceFileEvents`, serving as solid confirmation of the attack's impact.

### What didn't work / limitations found

- `DeviceFileEvents` did not log the 100 individually created `.akira` files, most likely due to MDE throttling under high-volume file creation bursts. An analyst relying solely on this table for detection would have missed the core artifact of the attack.
- Live Response was enabled at the tenant configuration level but never became available on the device during the lab session, forcing a shift from remote-shell-based eradication to direct RDP access. This highlights the importance of validating response capabilities ahead of time, not during an active incident.

### Recommendation

Ransomware detection rules should prioritize process-level telemetry (command line content, parent process) over raw file event counts, since file-event volume can be under-reported by EDR sensors during high-throughput bursts, which is precisely the behavior real ransomware exhibits.

---

## 📁 Repository Structure

```
SOC-Lab-Ransomware-Incident-Response-NIST-800-61/
├── README.md
└── screenshots/
    ├── 01-preparation/
    ├── 02-detection-analysis/
    └── 03-containment-eradication-recovery/
```

## 🔗 Related Work

This lab connects to [SOC-Lab-Advanced-Threat-Hunting-KQL](../SOC-Lab-Advanced-Threat-Hunting-KQL) (Episode 6). A bonus episode is planned covering three additional T1486 sub-tests (PureLocker, GPG4Win, DiskCryptor) as a comparative TTPs/threat hunting exercise, building on the KQL hunting patterns established in Episode 6.

## 👤 Author

**Guillermo Costa**
Cybersecurity Analyst | SOC Tier 1
[GitHub](https://github.com/GjcCS) | [LinkedIn](https://linkedin.com/in/guillermo-costa)
