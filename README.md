# PowerShell Abuse CTF

## **Scenario**
**Environment**: Simulated cyber range mimicking enterprise infrastructure

**Trigger**: Suspicious activity resembling prior compromise

**Threat Profile**: APT-style, stealthy attacker simulating long-term access across multiple sectors

**Objectives**: Detect persistence, lateral movement, and exfiltration techniques used by a simulated threat actor

## **Mission & Hypothesis**

**Mission**

- Identify any compromised systems, map the attacker’s movement across the environment, and determine persistence, exfiltration, or intent.

**Hypothesis**

- The threat actor used stealth initial access methods (e.g., dropper/phishing), followed by memory-resident tooling (e.g., PowerShell), registry persistence, and exfiltration via uncommon cloud endpoints.

## **Methodology**

- Used Microsoft Defender for Endpoint to investigate the CTF environment.
- Ran KQL queries in MDE Advanced Hunting to identify attacker behaviour.
- Followed each CTF flag as an individual detection objective.
- Mapped query logic, behaviour observed, and MITRE mapping per flag.

## **Key Findings**

- **Suspicious Scheduled Task (`RemoteC2Task`)** was created to launch `C2.ps1` at user logon using PowerShell with execution policy bypass, classic persistence via scheduled task abuse.
- **Registry Run Key (`WalletUpdater`)** was added under the current user hive to trigger PowerShell on startup. The name was crafted to blend into a crypto environment.
- **Attacker used `mshta.exe`** to execute a local malicious HTA payload (`client_update.hta`) from the Temp directory, abusing a trusted signed binary (LOLBin).
- **Staged a fake binary (`ledger_viewer.exe`)** in a directory themed around finance, clearly attacker-crafted, not user-triggered. Prepped for later execution.
- **Used `bitsadmin.exe`** to pull down a remote payload (`crypto_toolkit.exe`). This was stored in the user’s Temp folder and hidden from casual inspection.
- **Manually opened `QuarterlyCryptoHoldings.docx`** using WordPad, confirming hands-on collection of sensitive local documents prior to exfil.
- **Executed `psexec` from `michaelvm` to `centralsrvr`** using stolen credentials, launching another instance of `C2.ps1` , clear lateral movement.
- **Exfiltration via PowerShell to Dropbox, Pastebin, and Google Drive** was observed from `centralsrvr`. These outbound connections all share similar hashes and patterns across both hosts.
- **Used `powershell.exe -Version 2`** on `centralsrvr`, a known AMSI bypass trick and part of the attacker’s consistent trade-craft.
- **Executed `whoami` via `cmd.exe`** early in the chain to confirm access context, typical post-compromise recon.
- **Cleared Windows Security Event Log** using `wevtutil cl security`, a final anti-forensics move found in process creation logs, not standard timestamp field.

## **Starting Point**
<img width="639" height="233" alt="image" src="https://github.com/user-attachments/assets/44274d0d-4a3a-4ae9-9329-04ce44239dc8" />

### **Findings**

Due to the high volume of activity in the cyber range, I focused on identifying persistence. Instead of scanning broadly for PowerShell usage, I filtered for scheduled task creation events and found two tied to suspicious payloads.

Both tasks used `ONLOGON` triggers and launched PowerShell with execution policy bypasses. The payloads were stored in commonly abused directories: `AppData\Local\Temp` and `Public`. This aligned with CTF intel indicating Temp-based execution around June 15.

### **KQL Query**

```
// Identify Compromised System
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "schtasks" and ProcessCommandLine has "/create"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```
<img width="1404" height="397" alt="image" src="https://github.com/user-attachments/assets/9a5a0b66-3485-4c60-a074-78ff50702fed" />


