# Windows Endpoint Threat Investigation Report

**Investigation Date:** November 18, 2026  
**Analyst:** Clark Mitchell  
**Case ID:** WIN-ENDPOINT-001  
**Severity:** High (Investigative Priority)  
**Status:** Investigation Completed — Synthetic Lab  
**Affected Host:** WIN10-LAB  
**Account:** LAB\jsmith

## 1. Executive Summary

This investigation analyzed synthetic Windows Sysmon event logs to identify potentially suspicious endpoint activity involving PowerShell execution, an outbound network connection, and child-process creation.

A Python-based endpoint analyzer identified three suspicious activity patterns across five Sysmon events. The investigation also included process timeline reconstruction, MITRE ATT&CK mapping, and development of a Sigma detection rule for encoded PowerShell commands.

The activity was flagged for investigation because encoded PowerShell execution, external network communications, and command-shell activity can be associated with malicious behavior.

However, these behaviors can also occur during legitimate administration. The synthetic evidence does not establish malware execution, command-and-control activity, or confirmed system compromise.

## 2. Investigation Scope and Methodology

The investigation was conducted on Bazzite Linux using Python, VS Code, pySigma, and synthetic Windows Sysmon logs.

The investigation included:

1. Parsing Sysmon Event ID 1 (Process Creation) and Event ID 3 (Network Connection).
2. Identifying encoded PowerShell execution.
3. Correlating process activity with network connections and child processes.
4. Reconstructing a chronological endpoint activity timeline.
5. Mapping observed behaviors to MITRE ATT&CK techniques.
6. Developing and validating a Sigma detection rule.
7. Testing detection logic against suspicious and benign synthetic events.

**Evidence Source:** `logs/sysmon_events.json`

## 3. Investigation Findings

### Finding 1 — Encoded PowerShell Execution

**Severity:** High  
**Timestamp:** 2026-11-18 14:02:15  
**Host:** WIN10-LAB  
**User:** LAB\jsmith

**Observed Command:**

`powershell.exe -NoProfile -EncodedCommand SQBFAFgA`

A PowerShell process was launched with an encoded-command argument.

Encoded PowerShell commands can be used for legitimate administrative automation but may also be used to conceal suspicious instructions.

**MITRE ATT&CK:** T1059.001 — PowerShell

**Assessment:** Suspicious execution behavior requiring further investigation. The available evidence does not establish malicious intent.

### Finding 2 — PowerShell Network Connection

**Severity:** Medium  
**Timestamp:** 2026-11-18 14:02:30  
**Destination:** 203.0.113.50:443  
**Protocol:** TCP

A Sysmon network connection event was associated with the PowerShell process approximately 15 seconds after the encoded-command execution event.

The destination address belongs to a documentation-reserved IP range and is used here exclusively for the synthetic investigation.

**Assessment:** The connection provides useful process-to-network correlation, but it does not independently establish malicious communications or command-and-control activity.

### Finding 3 — PowerShell Child Process

**Severity:** Medium  
**Timestamp:** 2026-11-18 14:03:10  
**Child Process:** cmd.exe  
**Observed Command:** `cmd.exe /c whoami`  
**Parent Process:** powershell.exe

A command-shell process was created by PowerShell and executed `whoami`.

This command retrieves information about the current security context and may be used during legitimate administration or attacker reconnaissance.

**MITRE ATT&CK:** T1059.003 — Windows Command Shell

**Assessment:** The observed command-shell execution is consistent with the mapped ATT&CK technique, but it is not sufficient evidence of compromise.

## 4. Correlated Endpoint Timeline

| Timestamp (UTC) | Event | Observation |
|---|---|---|
| 14:00:00 | Process Creation | explorer.exe started |
| 14:02:15 | Process Creation | PowerShell launched with encoded-command argument |
| 14:02:30 | Network Connection | PowerShell connected to 203.0.113.50:443 |
| 14:03:10 | Process Creation | PowerShell spawned cmd.exe to execute whoami |
| 14:05:00 | Process Creation | notepad.exe started |

The timeline demonstrates how process creation and network telemetry can be correlated to reconstruct endpoint activity.

## 5. MITRE ATT&CK Mapping

| Technique | ID | Observed Behavior |
|---|---|---|
| PowerShell | T1059.001 | PowerShell executed with an encoded-command argument |
| Windows Command Shell | T1059.003 | cmd.exe launched from PowerShell |

The encoded-command argument may warrant additional investigation for obfuscation, but the available evidence does not establish a confirmed obfuscation technique.

## 6. Sigma Detection Engineering

A Sigma rule was developed to identify PowerShell process creation events containing encoded-command arguments.

**Rule:** `detections/powershell_encoded_command.yml`

**Rule Title:** Suspicious PowerShell Encoded Command Execution

**Detection Logic:**

- Match PowerShell executable names, including powershell.exe and pwsh.exe.
- Identify command-line arguments containing `-EncodedCommand` or `-enc`.
- Require both the executable and command-line conditions to match.

The rule was parsed and validated using pySigma.

A lightweight Python matcher was also developed to test the rule's supported field conditions against synthetic Sysmon events.

### Automated Test Results

| Test | Result |
|---|---|
| Encoded PowerShell execution detected | PASS |
| Normal PowerShell execution ignored | PASS |
| Suspicious synthetic Sysmon event detected | PASS |
| Unrelated process ignored | PASS |

**Total:** 4 tests passed, 0 failures.

The tests validate the implemented matching behavior for the selected synthetic scenarios. They do not establish compatibility with every Sigma backend or production SIEM environment.

## 7. Recommended Response Actions

For an equivalent alert in a production environment, recommended investigative actions include:

1. Review the full PowerShell command line and decode the encoded argument in a controlled analysis environment.
2. Verify whether the PowerShell execution was authorized.
3. Examine the process tree and related process identifiers.
4. Review network telemetry for the destination and associated traffic.
5. Investigate related authentication events and account activity.
6. Examine endpoint security alerts, PowerShell logging, and available forensic artifacts.
7. Escalate or contain the endpoint if additional evidence establishes a credible threat.

No production containment or remediation was performed because this investigation used synthetic data.

## 8. Conclusion

The investigation successfully identified three suspicious activity patterns within a five-event synthetic Sysmon dataset.

The project demonstrated Python-based security log analysis, endpoint event correlation, MITRE ATT&CK mapping, Sigma detection development, and automated testing.

The findings illustrate how a SOC analyst can combine endpoint telemetry and detection engineering to prioritize suspicious activity while avoiding unsupported conclusions about system compromise.

**Final Disposition:** Suspicious activity identified in synthetic telemetry; no real-world compromise established.
