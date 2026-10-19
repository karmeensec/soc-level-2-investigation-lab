# NW-005 - Domain Account Incident Simulation

**Project:** SOC Level 2 Investigation Lab  
**Analyst:** Kamil Ismayilzada  
**Disposition:** Authorized lab simulation; containment and cleanup validated within the tested scope  
**Evidence period:** October 14-15, 2026; all timestamps below are UTC

## Executive assessment

The investigation correlated repeated failed authentication, successful account use, encoded PowerShell execution, a per-user registry startup entry, and subsequent network authentication to a domain controller. The dedicated standard domain account was `NIGHTWATCH\nw-case5`. Execution and persistence were observed on NW-WS01; account management and authentication were observed on NW-DC01.

All activity was deliberately generated in an isolated lab. The encoded command printed harmless test text, and the startup entry pointed to Notepad. The exercise demonstrates investigation and response to an account-abuse pattern; it does not demonstrate credential theft, privilege escalation, remote code execution on the domain controller, or an Active Directory takeover.

Response included disabling the account, deleting its startup value, checking SMB sessions, stopping remaining account-owned processes, and testing a fresh login. The final login failed with the disabled-account substatus.

## Evidence and method

Primary evidence: `nightwatch-case5-incident-timeline.csv`, containing **217 selected rows**, spanning **2026-10-14 21:24:59.897** through **2026-10-15 18:41:20.446**. The CSV was exported from Splunk, using `nightwatch_windows` and `nightwatch_sysmon`.

| Host | Role | Evidence represented in this export |
|---|---|---|
| NW-WS01 / 192.168.56.20 | Domain workstation | Authentication, process creation, registry changes |
| NW-DC01 / 192.168.56.10 | Domain controller | Kerberos, network logons, account disablement |

The export contains 20 Sysmon process-creation rows, 165 registry value-set rows, one selected registry deletion, and 31 selected Windows Security rows. Many rows reflect initialization or ordinary application activity; row counts are not counts of attacks. The text search also matches commands mentioning the account and system activity referencing its profile, rather than exclusively actions performed by that account.

Live process and SMB checks were supplied separately by the lab operator. The export omits raw XML, event record identifiers, process GUIDs, parent-process fields, logon identifiers, and registry EventType. Those omissions limit exact event joins and independent revalidation. Prior pasted evidence supplies the deletion EventType and selected GUIDs. The original export should be retained unchanged.

## Key timeline

| UTC timestamp | Host | Evidence | Interpretation |
|---|---|---|---|
| Oct 14 21:25:08.750 | WS01 | 4624 and 4648, Alex supplying credentials for nw-case5 | Baseline successful explicit-credential use |
| Oct 14 21:26:20-21 | DC01 | 4768/4769 and 4624 from 192.168.56.20 | Baseline domain authentication |
| Oct 14 21:31:34.004 | WS01 | 4625; substatus 0xc000006a | Initial wrong-password control |
| Oct 14 21:36:32.562-21:36:48.758 | WS01 | Five 4625 events for nw-case5 | Repeated-failure test; five events in approximately 16 seconds |
| Oct 14 21:36:53.884 | WS01 | 4624 and 4648 | Successful use approximately five seconds after the final failure |
| Oct 14 21:45:47.648 | WS01 | Sysmon 1, PowerShell with -EncodedCommand, user nw-case5 | Encoded execution confirmed |
| Oct 15 17:02:40.023 | WS01 | Sysmon 13, Run\NightWatchCase5 | Per-user startup value set to Notepad |
| Oct 15 17:06:02.437-17:06:02.465 | DC01 | 4768/4769 and 4624 from 192.168.56.20 | Authentication during the operator's SYSVOL access test |
| Oct 15 17:12:25.111 | DC01 | 4725, Administrator targeting nw-case5 | Account disabled |
| Oct 15 17:13:45.843 | WS01 | Sysmon 12 at the same startup value | Deletion; earlier detailed evidence identifies DeleteValue |
| Oct 15 18:37:54 | WS01 | Registry activity attributed to nw-case5 processes | Activity persisted after account disablement; separate live checks found remaining processes |
| Oct 15 18:41:20.446 | WS01 | 4625; status 0xc000006e, substatus 0xc0000072 | Fresh authentication rejected for a disabled account |

The exercise was performed across two days. The long gap between execution and persistence reflects the lab schedule; it must not be described as attacker dwell time.

## Investigation findings

### Authentication and execution

The failed logons used loopback source `::1` on WS01, with Alex Morgan as the initiating subject in the reviewed events. These were local `runas` tests, not evidence of a remote password attack. The known correct password was subsequently supplied; the sequence does not show password cracking.

The encoded PowerShell payload decodes to:

```powershell
Write-Output "NightWatch Case 5 execution test"
```

The previously captured process GUID is `{347e54a1-f80b-6acf-780f-000000001a00}`. Encoding is a triage signal, not proof of malicious content.

### Persistence and scope

PowerShell wrote `C:\Windows\System32\notepad.exe` to:

```text
HKU\S-1-5-21-2151012017-1686449940-4250341324-1105\Software\Microsoft\Windows\CurrentVersion\Run\NightWatchCase5
```

The SID and account context distinguish this value from the earlier Alex Morgan and local-administrator exercises. A startup value was created, but this Case 5 evidence does not validate its execution at an interactive login as nw-case5. Login-triggered execution was tested separately in Case 4 under Alex Morgan.

DC01 recorded successful network authentication from WS01 during the SYSVOL listing test. The selected authentication rows do not independently identify the exact file/share operation. No DC process execution, privileged group change, or domain takeover is established by this export. Absence from a filtered export is not a comprehensive negative finding.

## Response and validation

1. Disabled only the dedicated nw-case5 domain account; DC01 logged 4725.
2. Removed NightWatchCase5 from that user's Run key; WS01 logged the registry deletion.
3. Queried DC01 SMB sessions for nw-case5; the operator reported blank output, meaning no matching sessions at that check.
4. Queried WS01 processes by owner. PowerShell PID 7044 and conhost PID 4276 remained despite account disablement.
5. Stopped processes owned by nw-case5 and repeated the check; the operator confirmed the cleanup step passed. Process-termination events were not included in this export.
6. Attempted fresh authentication with the known correct password. The resulting 4625 substatus 0xc0000072 supports disabled-account enforcement for that tested logon path.

These checks do not prove universal ticket revocation or elimination of every possible session. Host isolation, credential reset, memory acquisition, and forensic imaging were not performed. The test account remains disabled; no evidence was deleted as part of cleanup.

## Detection coverage and lessons

- The existing repeated-failure rule covers at least five failures per host/domain/account in a fixed five-minute bucket. Boundary splitting and local-versus-network context affect interpretation.
- The encoded-PowerShell rule covers the full -EncodedCommand spelling in powershell.exe, not every abbreviation or interpreter.
- The Run-key modification rule detects registry value sets, including legitimate startup software. Creation can still alert after the value has been removed.
- Separate validation established these rules; this CSV does not contain scheduler or triggered-alert records proving which Case 5 events generated notifications.
- Reliable clock synchronization is necessary for relative-time searches and scheduled detection. Recurring VM clock skew was observed earlier; a permanent resume-time correction was not validated.
- Account disablement and process/session termination are distinct response actions. The remaining processes provided direct evidence of this distinction.

## Evidence to retain with the case

Keep the original CSV alongside the authentication baseline, failures-then-success, encoded execution, persistence, DC network authentication, account-scope, account-disablement, registry-removal, process-cleanup, and disabled-account-test screenshots collected during the exercise. Screenshot filenames are references to operator-held evidence; their bytes were not inspected as part of this report.

## Closure

The tested account-abuse simulation was contained within the verified scope: the domain account was disabled, the startup value was removed, reported remaining processes were stopped, no matching SMB session was found, and the fresh logon test was blocked. The defensible case title is **domain account incident simulation**, rather than confirmed domain-controller compromise.
