# PowerShell Script Block Logging Detection — Splunk (Event ID 4104)
---

## What this is

A Splunk detection for suspicious PowerShell activity using Windows Script Block Logging (Event ID 4104). The rule catches common attacker patterns encoded commands, download cradles, `Invoke-Expression`, obfuscation keywords  by matching against the script content logged by PowerShell itself.

Getting this working was less about writing the SPL query and more about figuring out why nothing was showing up in Splunk. Troubleshooting took longer than the actual detection logic.

---

## Environment

| Component | Details |
|-----------|---------|
| SIEM | Splunk Enterprise 10.2.3 |
| OS | Windows VM |
| Log source | Microsoft-Windows-PowerShell/Operational |
| Event ID | 4104 |
| Forwarder | Splunk Universal Forwarder |

---

## Detection query

```spl
index=* EventCode=4104
| eval script=coalesce(ScriptBlockText, Message)
| search script="*ScriptBlockLogging*"
    OR script="*Invoke-Expression*"
    OR script="*IEX*"
    OR script="*-enc*"
    OR script="*DownloadString*"
    OR script="*bypass*"
    OR script="*FromBase64String*"
| eval user=coalesce(User, SubjectUserName, "unknown")
| table _time, ComputerName, user, script
| sort - _time
```

### Why `coalesce(ScriptBlockText, Message)`

In this environment, `ScriptBlockText` wasn't populated. The script content was inside the `Message` field instead. Using `coalesce` handles both cases without breaking the query when one field is missing.

---

## What it detects

Keyword matching inside 4104 events for patterns commonly associated with:

- encoded execution (`-enc`, `FromBase64String`)
- download cradles (`DownloadString`)
- dynamic execution (`Invoke-Expression`, `IEX`)
- policy bypasses (`bypass`)
- logging recon (`ScriptBlockLogging`)

It's keyword-based, so it won't catch everything. See the evasion section below.

---

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| PowerShell | T1059.001 |
| Command and Scripting Interpreter | T1059 |
| Obfuscated Files or Information | T1027 |

---

## Test activity

Three payloads were used to generate real telemetry:

**Registry recon**
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
```

**Invoke-Expression**
```powershell
Invoke-Expression 'Write-Host test123'
```

**Encoded command**
```powershell
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Host pwned'))
powershell -enc $encoded
```

All three appeared in Splunk after fixing the issues below.

---

## Issues hit along the way

**Script Block Logging was off by default.**  
Had to enable it in Group Policy before any 4104 events appeared.

**Forwarder was sending to port 997 instead of 9997.**  
No events reached Splunk until this was corrected. Confirmed the fix with `tcpdump` to watch traffic hit the listener.

**`ScriptBlockText` wasn't populated.**  
The raw content existed in `Message` instead. Updated the query to use `coalesce()` to handle this.

**Index name assumptions failed.**  
Using `index=*` worked. Named index assumptions didn't.

Some 4104 events also had this in the description field:
```
Splunk could not get the description for this event
```
The raw data was still there and searchable — this was a display issue, not an ingestion failure.

---

## Sigma rule

```yaml
title: Suspicious PowerShell Script Block Logging Activity
id: b7f31d40-4104-demo
status: experimental
description: Detects suspicious PowerShell Script Block Logging keywords
author: Harilal
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    Message|contains:
      - 'Invoke-Expression'
      - 'IEX'
      - '-enc'
      - 'DownloadString'
      - 'bypass'
      - 'FromBase64String'
      - 'ScriptBlockLogging'
  condition: selection
level: medium
tags:
  - attack.execution
  - attack.t1059.001
```

---

## False positives

This rule will fire on legitimate admin activity. Common sources:

- Automation scripts using encoded commands
- Monitoring tooling that calls `Invoke-Expression`
- Internal maintenance operations
- Legitimate PowerShell modules that reference `bypass` in strings

Tune by excluding known-good `ComputerName` or `user` values, or by adding a whitelist to the query.

---

## Evasion

This detection is keyword-based, so attackers can avoid it with:

- String concatenation (`"Inv" + "oke-" + "Expression"`)
- Heavy obfuscation
- Alternate execution methods (COM objects, .NET reflection)
- Disabling PowerShell logging before execution
- In-memory frameworks that don't hit Script Block Logging at all

A more robust version would combine this with process creation events (4688) and parent-child process analysis.

---

## Screenshots

| | |
|--|--|
| Raw 4104 event | `screenshots/raw-4104-event.png` |
| Detection query firing | `screenshots/detection-firing.png` |

---

## What I took away from this

The detection query itself took maybe 20 minutes. The rest of the time was spent figuring out why logs weren't showing up — wrong port, logging disabled, wrong field name. That troubleshooting is probably more useful to document than the SPL, because the same kinds of silent failures happen in real environments all the time.

---
