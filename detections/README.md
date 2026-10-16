# Detection Rules

## Shared alert settings
- Schedule: */5 * * * * (every five minutes)
- Search window: Last 15 minutes
- Trigger: Number of Results greater than 0
- Mode: For each result
- Action: Add to Triggered Alerts
- Severity: Medium
- Triggered-alert retention: 24 hours

## Throttling
- NW-001: ProcessGuid; 1 hour
- NW-002: host,TargetDomainName,TargetUserName; 15 minutes
- NW-003: host,ProcessGuid; 1 hour
- NW-004: host,ProcessGuid,TargetObject; 1 hour

## Validation and limitations
- NW-001: Encoded PowerShell matched; ordinary PowerShell did not. Covers the full -EncodedCommand argument in powershell.exe.
- NW-002: Five failures in a fixed five-minute bucket matched; groups of one and four did not. Attempts split across bucket boundaries can be missed.
- NW-003: WScript-launched PowerShell matched; direct PowerShell did not. Other script hosts and indirect launches are outside scope.
- NW-004: Test Run-key writes matched. Edge startup entries also matched and require triage. RunOnce and other persistence locations are outside scope.

A match requires investigation and does not establish malicious intent.

Accurate clocks are required. Recurring VM clock skew was observed; a permanent fix was not validated.
