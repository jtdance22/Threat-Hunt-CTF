# PowerShell Abuse CTF

## **Scenario**
This hunt takes place in a simulated cyber range environment that mimics a multi-stage Advanced Persistent Threat (APT) campaign. The scenario involves a coordinated threat actor group leveraging stealth techniques across sectors (telecom, defence, manufacturing) in Southeast Asia and Eastern Europe. Anomalous outbound activity, irregular PowerShell bursts, registry modifications, and credential traces were observed. The scenario suggests long-term, persistent access, indicating a nation–state–level actor or a well-funded mercenary group.

Expected TTPs include:

- Fileless execution via PowerShell
- Registry persistence
- Credential access tools masquerading as red team tooling
- Data staging in public directories
- Beaconing via uncommon cloud endpoints

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

After confirming that `michaelvm` was the compromised host, I identified two scheduled tasks tied to persistence mechanisms. The first, `MarketHarvestJob`, launched `client_update.hta` from the Temp directory. A known LOLBin abuse pattern. The second, `RemoteC2Task`, was created on `centralsrvr`, the lateral target, and executed `C2.ps1` from the Public folder. Notably, this same script was used in the earlier compromise, confirming a repeated TTP pattern.

**Task 1: MarketHarvestJob** (Local Persistence)

```bash
schtasks /Create /SC ONLOGON /TN MarketHarvestJob /TR "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Users\MICH34~1\AppData\Local\Temp\client_update.hta" /RL HIGHEST /F
```

---

**Task 2: RemoteC2Task** (Remote Persistence on `centralsrvr`)

```bash
schtasks.exe /Create /S centralsrvr /U centralsrvr\adminuser /P ********** /TN RemoteC2Task /TR "powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\C2.ps1" /SC ONLOGON
```

These findings will support multiple flags, especially those related to execution, persistence, and lateral movement.

I also reviewed logon activity on `michaelvm` and confirmed that the account `mich34l_id` authenticated from **49.147.196.23** on **15 June 2025 at 06:52 UTC**. The same IP reappeared on **16 June**, initiating multiple **RemoteInteractive (RDP)** sessions.

While the IP doesn’t appear in public threat intelligence feeds, I previously observed it during the first compromise. Its reuse confirms that this system (`michaelvm`) was compromised and suggests the earlier breach may have served as a dry run for a broader campaign as indicated in the threat intel briefing.

This finding also helps establish the timeline of initial access, which will be critical for reconstructing the attacker’s full activity path across the environment.

MITRE ATT&CK mappings for these persistence and lateral movement behaviours are detailed in the respective flag sections that follow.

### **KQL Query**
```
//Identify Login Activity
DeviceLogonEvents
| where DeviceName =~ "michaelvm"
| where AccountName =~ "mich34l_id"
| where Timestamp between(datetime(2025-06-15) .. datetime(2025-06-17))
| project Timestamp, LogonType, AccountName, RemoteIP, InitiatingProcessAccountName, ReportId
| order by Timestamp asc
```
<img width="938" height="531" alt="image" src="https://github.com/user-attachments/assets/b34a5a56-5006-4d8b-afaa-8dabd824f6fc" />
<img width="1303" height="559" alt="image" src="https://github.com/user-attachments/assets/7238f131-eee9-4459-a35d-b9200b6fe7a7" />


## 🏴Flag 1 - Initial PowerShell Execution Detection

<img width="639" height="338" alt="image" src="https://github.com/user-attachments/assets/23e60d9b-1a3a-4600-8dd3-f30b6e4f20b4" />

### **Findings**

To pinpoint the intruder’s entry point, I filtered `DeviceProcessEvents` for `powershell.exe` executions on `michaelvm`, scoped to the `mich34l_id` account. I narrowed results further by focusing on `.ps1` script executions.

The earliest suspicious command was:

```bash
"powershell.exe" -ExecutionPolicy Bypass -File "C:\Users\Mich34L_id\CorporateSim\Investments\Crypto\wallet_gen_0.ps1"
```

This execution occurred within the expected activity window (June 15–16) and matches the CTF hint about Temp-based or non-standard paths. The script name `wallet_gen_0.ps1` suggests potential targeting of cryptocurrency data, though the script’s function remains unconfirmed at this stage.

I included both `DeviceName` and `AccountName` filters to reduce noise and focus on the account we previously identified as compromised. This approach helps isolate attacker behaviour from system background activity.

### MITRE ATT&CK Technique

- **Technique:** [**T1059.001 – Command and Scripting Interpreter: PowerShell**](https://attack.mitre.org/techniques/T1059/001/)
- **Tactic:** Execution
- **Description:** The attacker executed `.ps1` scripts using `powershell.exe` with `ExecutionPolicy Bypass`, consistent with abuse of PowerShell to run malicious code while evading default system protections.

### **KQL Query**
```
DeviceProcessEvents
| where DeviceName contains "michaelvm"
| where AccountName contains "mich34l_id"
| where Timestamp between (ago(30d) .. now())
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has ".ps1" // Targeting PowerShell script executions
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```
<img width="1841" height="202" alt="image" src="https://github.com/user-attachments/assets/923d1275-7ad0-4c61-ab27-00aa7cf07696" />
