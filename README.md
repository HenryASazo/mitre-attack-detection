# Lab 1: MITRE ATT&CK Detection Engineering (Through Exercise 1)

Cybersecurity lab from the **Mandiant Cyber Defense Validation Engineer Prep** guide. This repo documents **Lab 1** and **Exercise 1: Credential Dumping Detection (T1003)** — environment setup, Wazuh deployment, Atomic Red Team, and a custom detection rule for LSASS access.

---

## Lab Overview

- **Goal:** Build detection for common ATT&CK techniques and validate with attack simulation.
- **Skills:** MITRE ATT&CK mapping, detection rule writing, EDR configuration and testing.
- **Exercise 1 focus:** Detect credential dumping from LSASS memory (MITRE ATT&CK **T1003.001**).

---

## Environment Setup

### Virtual Machines (VirtualBox)

| VM | Role | OS | Network Adapters |
|----|------|-----|------------------|
| **VM 1** | Wazuh **agent** | Windows 10 | Host-Only + NAT |
| **VM 2** | Wazuh **manager** | Ubuntu Linux | Host-Only + NAT |

Both VMs use:

1. **Host-Only Adapter** — so the Windows agent and Ubuntu manager can talk to each other (and the host can reach the Wazuh UI).
2. **NAT** — for internet (installs, updates, downloads).

After full setup, the manager was reached at **192.168.56.101** (Host-Only) and the Windows agent at **192.168.56.102**.

---

## What I Did

### 1. Wazuh Manager (Ubuntu VM)

- Installed Wazuh 4.14.2 using the all-in-one script:

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a -o
```

- The script installed the Wazuh indexer, dashboard, and manager, generated certificates and the `wazuh-install-files.tar` bundle (used for agent enrollment).
- Post-install summary showed dashboard URL and generated admin credentials.

![Wazuh manager installation in progress](Screenshot%202026-02-08%20170951.png)

![Install summary – dashboard URL and credentials](Screenshot%202026-02-08%20171009.png)

- Verified network: `ip a s` showed the NAT interface (e.g. `10.0.2.15`) and later Host-Only gave the IP used for the dashboard (**192.168.56.101**).

![Network interfaces on Ubuntu (ip a s)](Screenshot%202026-02-08%20171523.png)

- Opened the Wazuh dashboard in the browser. First access to the manager IP triggered a certificate warning (self-signed); accepted to continue.

![Browser certificate warning when accessing Wazuh](Screenshot%202026-02-08%20171816.png)

- Logged in and confirmed the dashboard loaded with no agents registered yet.

![Wazuh login page](Screenshot%202026-02-08%20172538.png)

![Wazuh overview – no agents registered](Screenshot%202026-02-08%20172747.png)

---

### 2. Wazuh Agent (Windows 10 VM)

- Configured the agent to point to the manager. During setup, used manager address **10.0.2.15** (NAT IP seen on Ubuntu before Host-Only was in use) and agent name **Windows-client**.

![Agent configuration – manager address and agent name](Screenshot%202026-02-08%20174134.png)

- Installed the agent via PowerShell (Administrator):

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.2-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='10.0.2.15' WAZUH_AGENT_NAME='Windows-client'
```

![PowerShell – download and install Wazuh agent](Screenshot%202026-02-08%20174856.png)

- Used the Wazuh service name `WazuhSvc` for checks and restarts (e.g. `Get-Service -Name WazuhSvc`, `Restart-Service -Name WazuhSvc`).

![Wazuh agent management commands (Windows)](Screenshot%202026-02-10%20181208.png)

After both adapters were in place and the manager was reachable on the Host-Only network, the agent showed as **Active** in the dashboard with name **Windows-Client1** and IP **192.168.56.102**.

![Wazuh overview – 1 active agent](Screenshot%202026-02-10%20181655.png)

![Endpoints – Windows-Client1 active](Screenshot%202026-02-10%20182701.png)

---

### 3. Atomic Red Team (Windows 10 VM)

- Installed Atomic Red Team so I could run ATT&CK-mapped tests (e.g. credential dumping).

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

- Verified: `Test-Path C:\AtomicRedTeam\atomics` returned `True`.
- When the folder already existed, re-running the installer reported “Atomic Redteam already exists” and suggested `-Force` for a clean reinstall.

![Installing Atomic Red Team (install script)](Screenshot%202026-02-10%20181959.png)

![Atomic Red Team already installed message](Screenshot%202026-02-10%20182044.png)

- For **Exercise 1**, ran the credential-dumping test (T1003.001 – LSASS memory):

```powershell
Invoke-AtomicTest T1003.001
```

![Running Invoke-AtomicTest T1003.001](Screenshot%202026-02-10%20182144.png)

This simulates access to LSASS so we can validate detection.

---

### 4. Exercise 1: Credential Dumping Detection (T1003.001)

- **Objective:** Detect when something accesses LSASS (credential dumping).
- **Steps taken:**
  1. Simulated the attack with `Invoke-AtomicTest T1003.001` on the Windows agent.
  2. Added a **custom Wazuh rule** on the manager to detect LSASS access and map it to T1003.001.

- On the **Ubuntu (Wazuh manager)** VM, edited the local rules file:

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

![Editing local_rules.xml on the manager](Screenshot%202026-02-10%20215425.png)

- Added a rule that triggers on Windows events where the target image is `lsass.exe`, with level 12 and MITRE ID **T1003.001**:

![Custom rule for credential dumping (LSASS)](Screenshot%202026-02-10%20215515.png)

![Full local_rules.xml with multiple custom rules](Screenshot%202026-02-10%20220445.png)

- Reloaded and restarted the manager so the new rule loaded:

```bash
systemctl daemon-reload
systemctl restart wazuh-manager
```

![Restarting Wazuh manager after rule change](Screenshot%202026-02-10%20215717.png)

#### Custom detection rules in `local_rules.xml`

The Wazuh manager’s custom rules file (`/var/ossec/etc/rules/local_rules.xml`) on the Ubuntu VM contains the following detection rules (from the screenshots):

| Rule ID | Level | What it detects | MITRE ATT&CK |
|--------|--------|------------------|--------------|
| **(partial)** | — | **Signed Binary Proxy Execution using Regsvr32** — abuse of `regsvr32.exe` for execution | T1218 (Signed Binary Proxy Execution), T1117 |
| **115004** | 10 | **Security Software Discovery** — attempt to discover security/AV software on the host | T1518 (Software Discovery) |
| **115005** | 10 | **Privilege Escalation / UAC Bypass** — Bypass User Access Control detected | T1548.002 (Bypass User Account Control), T1088 |
| **100100** | 12 | **Credential Dumping – LSASS** — access to `lsass.exe` (chains on existing rule SID 61612; matches `win.eventdata.TargetImage` with `(?i)lsass.exe`) | T1003.001 (OS Credential Dumping: LSASS Memory) |

- Rules **115004** and **115005** use `<if_group>windows</if_group>` and match on `win.eventdata.ruleName` with PCRE2 (e.g. `technique_id=T1518.001`, `technique_id=T1548.002`).
- Rule **100100** uses `<if_sid>61612</if_sid>` (process-access events) and `<field name="win.eventdata.TargetImage">(?i)lsass.exe</field>` to raise a level-12 alert and map it to T1003.001.

![Full local_rules.xml with multiple custom rules](Screenshot%202026-02-10%20220445.png)

---

## Findings

- **Agent–manager connectivity:** The Windows agent (Windows-Client1, 192.168.56.102) stayed **Active** and events were visible in the Wazuh dashboard under the MITRE ATT&CK and Events views (manager hostname: **LinuxUbuntuLabs**).
- **Event volume:** In the MITRE ATT&CK Events view for Windows-Client1, **117 hits** were logged between Feb 10–11, 2026 (24h). The main Overview also showed 617 medium- and 339 low-severity alerts in that window.

#### Other attacks and events logged in the dashboard

Besides the Exercise 1 credential-dumping (T1003.001), the dashboard showed many other techniques from built-in and custom rules. Examples from the screenshots:

| MITRE ID(s) | Tactic(s) | Rule description (short) | Wazuh rule ID | Level |
|-------------|------------|---------------------------|---------------|-------|
| **T1003.001** | Credential Access | Lsass process was accessed | 92900 | 12 |
| **T1055** | Defense Evasion, Privilege Escalation | Explorer process (injection) | 92910 | 12 |
| **T1073 T1574** | Persistence, Privilege Escalation, Defense Evasion | DLL Side-Loading | 115002 | 10 |
| **T1105** | Command and Control | Executable file dropped | 92213 | 15 |
| **T1105 T1059** | Command and Control, Execution | C:\Windows\Sys... (system path execution) | 92201 | 9 |
| **T1059.001** | Execution | PowerShell process execution | 92027 | 4 |
| **T1059.003** | Execution | Windows command execution | 92052 | 4 |
| **T1070.004** | Defense Evasion | PowerShell was used | 92021 | 3 |
| **T1087** | Discovery | Discovery activity | 92031 | 3 |

- **T1003.001** is from the custom rule 100100 (LSASS access) and was triggered by `Invoke-AtomicTest T1003.001`.
- **T1055** (Explorer process) and **T1073/T1574** (DLL Side-Loading) indicate possible process injection and persistence/evasion activity detected by Wazuh’s rules.
- **92213** (Executable file dropped, level 15) was the highest-severity event shown; **92021** and **92031** (PowerShell usage, Discovery) appeared as lower-severity background activity.

Filtering on **LSASS** (`data.win.eventdata.targetImage` exists) in the Events view surfaced the T1003.001 and T1055 events together, confirming the credential-access detection and related privilege-escalation/defense-evasion alerts.

![MITRE ATT&CK events – Windows-Client1](Screenshot%202026-02-10%20220041.png)

![MITRE ATT&CK table including T1003.001 and other techniques](Screenshot%202026-02-10%20220253.png)

![LSASS filter and T1003.001 / T1055 events](Screenshot%202026-02-10%20220801.png)

- **What was detected:** The custom rule (100100) and built-in Windows event collection allowed Wazuh to detect the simulated credential-dumping activity (T1003.001) and surface it in the dashboard with correct MITRE mapping. The same 24h window showed a broad mix of tactics (Execution, Discovery, Command and Control, Defense Evasion, Credential Access, Persistence, Privilege Escalation) from both default and custom rules in `local_rules.xml`.
- **What I’d do next:** Compare with Windows Security/Event Logs (e.g. Event ID 4656 for LSASS access) to confirm alignment and document any gaps (e.g. events that appear in Windows but not in Wazuh, or the other way around).

---

## Summary

| Item | Detail |
|------|--------|
| **Lab** | Lab 1 – MITRE ATT&CK Detection Engineering, through Exercise 1 |
| **VMs** | Windows 10 (Wazuh agent), Ubuntu (Wazuh manager), both in VirtualBox with Host-Only + NAT |
| **Wazuh** | Manager 4.14.2 on Ubuntu; agent 4.14.2 on Windows 10, registered as Windows-Client1 |
| **Attack simulation** | Atomic Red Team, `Invoke-AtomicTest T1003.001` (credential dumping – LSASS) |
| **Custom rules** | `local_rules.xml`: Regsvr32 proxy execution, Security Software Discovery (115004), UAC Bypass (115005), Credential Dumping/LSASS (100100) |
| **Dashboard (24h)** | 117 MITRE ATT&CK events; other techniques logged: T1055, T1073/T1574, T1105, T1059.x, T1070.004, T1087 (rule IDs 92900, 92910, 115002, 92213, 92201, 92027, 92052, 92021, 92031) |
| **Result** | Credential-dumping (T1003.001) detected via custom rule 100100; multiple other tactics (Execution, Discovery, C2, Defense Evasion, Credential Access, Persistence, Privilege Escalation) visible in dashboard |

---

## References

- [Cybersecurity Lab Guide](Cybersecurity_Lab_Guide.pdf) (local)
- [MITRE ATT&CK T1003.001 – OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
