Alert: NW - Encoded PowerShell Execution
Host / user: NW-WS01 / nwlocaladmin
Finding: PowerShell ran with -EncodedCommand; the scheduled alert triggered.
Decoded command: Write-Output "NightWatch dutection test" — harmless test text.
Activity reviewed: Temporary PowerShell policy-test files and certificate-store registry key creation. No child processes appeared in the returned results.
Negative test: Normal PowerShell execution returned NO MATCH.
Disposition: Authorized benign test. Detection worked; encoding alone does not prove malicious activity.

<!-- evidence-gallery -->
## Evidence screenshots

### encoded powershell detected

![encoded powershell detected](../evidence/screenshots/case-01/nightwatch-encoded-powershell-detected.png)

### encoded powershell decoded

![encoded powershell decoded](../evidence/screenshots/case-01/nightwatch-encoded-powershell-decoded.png)

### encoded powershell negative test

![encoded powershell negative test](../evidence/screenshots/case-01/nightwatch-encoded-powershell-negative-test.png)
