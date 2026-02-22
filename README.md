# HomeLab: MITRE ATT&CK Detection

A hands-on lab for building and validating detection of MITRE ATT&CK techniques in an EDR-style setup. You get endpoint visibility (Wazuh agent + Sysmon on Windows), a central manager for detection rules, and Atomic Red Team to simulate attacks and confirm that detections fire. The exercise focuses on writing a custom rule to detect credential dumping from LSASS (T1003.001).

**Screenshots throughout this README are from my own lab environment** — captured on my machine as I completed each step (Wazuh manager on Ubuntu, agent on Windows 10 in VirtualBox). They document the setup, configuration, and detection results from this run.

**Note on IPs in screenshots:** Some screenshots show the manager at **10.0.2.15**. That was the Ubuntu VM’s NAT address *before* I added a Host-Only adapter to both VMs. After I set up Host-Only on both so the two VMs could talk to each other, the manager’s IP became **192.168.56.101** and the Windows agent’s **192.168.56.102**. So earlier steps (agent config, install commands) reference 10.0.2.15; later screenshots show the 192.168.56.x addresses.

---

## Table of Contents

- [Lab Overview](#lab-overview)
- [Environment Setup](#environment-setup)
  - [Virtual Machines (VirtualBox)](#virtual-machines-virtualbox)
- [What I Did](#what-i-did)
  - [1. Wazuh Manager (Ubuntu VM)](#1-wazuh-manager-ubuntu-vm)
  - [2. Wazuh Agent (Windows 10 VM)](#2-wazuh-agent-windows-10-vm)
  - [3. Sysmon (Windows 10 VM)](#3-sysmon-windows-10-vm)
  - [4. Atomic Red Team (Windows 10 VM)](#4-atomic-red-team-windows-10-vm)
  - [5. Exercise 1: Credential Dumping Detection (T1003.001)](#5-exercise-1-credential-dumping-detection-t1003001)
- [Findings](#findings)
- [Things I Learned](#things-i-learned)
  - [EDR (Endpoint Detection and Response)](#edr-endpoint-detection-and-response)
  - [Wazuh as a SIEM and dashboard](#wazuh-as-a-siem-and-dashboard)
  - [MITRE ATT&CK](#mitre-attck)
  - [Detection rules (Wazuh)](#detection-rules-wazuh)
  - [Atomic Red Team](#atomic-red-team)
  - [VM and lab networking](#vm-and-lab-networking)
- [Summary](#summary)
- [References](#references)

---

## Lab Overview

- **Goal:** Build detection for common ATT&CK techniques and validate it with attack simulation — the same workflow used when tuning or testing EDR (endpoint detection and response).
- **Skills:** MITRE ATT&CK mapping, detection rule writing, EDR-style configuration and testing (endpoint agent, Sysmon, custom rules, and validation with Atomic Red Team).
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

![Wazuh manager installation in progress](screenshots/Screenshot%202026-02-08%20170951.png)

- Verified network: `ip a s` showed the NAT interface (e.g. `10.0.2.15`) and later Host-Only gave the IP used for the dashboard (**192.168.56.101**).

![Network interfaces on Ubuntu (ip a s)](screenshots/Screenshot%202026-02-08%20171523.png)

- Opened the Wazuh dashboard in the browser. First access to the manager IP triggered a certificate warning (self-signed); accepted to continue.

- Logged in and confirmed the dashboard loaded with no agents registered yet.

![Wazuh login page](screenshots/Screenshot%202026-02-08%20172538.png)

![Wazuh overview – no agents registered](screenshots/Screenshot%202026-02-08%20172747.png)

---

### 2. Wazuh Agent (Windows 10 VM)

The Wazuh agent on the Windows endpoint collects logs and events (including Sysmon data) and sends them to the manager — providing the endpoint visibility needed for EDR-style detection.

- Configured the agent to point to the manager. During setup, used manager address **10.0.2.15** (NAT IP seen on Ubuntu before Host-Only was in use) and agent name **Windows-client**.

![Agent configuration – manager address and agent name](screenshots/Screenshot%202026-02-08%20174134.png)

- Installed the agent via PowerShell (Administrator):

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.2-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='10.0.2.15' WAZUH_AGENT_NAME='Windows-client'
```

![PowerShell – download and install Wazuh agent](screenshots/Screenshot%202026-02-08%20174856.png)

- Used the Wazuh service name `WazuhSvc` for checks and restarts (e.g. `Get-Service -Name WazuhSvc`, `Restart-Service -Name WazuhSvc`).

After both adapters were in place and the manager was reachable on the Host-Only network, the agent showed as **Active** in the dashboard with name **Windows-Client1** and IP **192.168.56.102**.

![Wazuh overview – 1 active agent](screenshots/Screenshot%202026-02-10%20181655.png)

![Endpoints – Windows-Client1 active](screenshots/Screenshot%202026-02-10%20182701.png)

---

### 3. Sysmon (Windows 10 VM)

Before installing and invoking Atomic Red Team, **Sysmon** had to be installed on the Windows sandbox so that the tests (e.g. credential dumping) would generate the right events for Wazuh to collect. The lab guide describes using a disposable Windows 10 VM for this.

- **Sysmon** is downloaded from the [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) page and is installed with a configuration file that maps Sysmon rules to MITRE ATT&CK techniques.
- **Installation command** (run from the folder where `sysmon.exe` and your config file are located, in an elevated PowerShell):

```powershell
sysmon.exe -accepteula -i sysmonconfig.xml
```

The `sysmonconfig.xml` file defines which events Sysmon logs (process creation, network, file access, etc.); using a config that aligns with MITRE ATT&CK helps ensure Atomic Red Team tests produce detectable activity.

---

### 4. Atomic Red Team (Windows 10 VM)

- Installed Atomic Red Team so I could run ATT&CK-mapped tests (e.g. credential dumping).

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

- Verified: `Test-Path C:\AtomicRedTeam\atomics` returned `True`.
- When the folder already existed, re-running the installer reported “Atomic Redteam already exists” and suggested `-Force` for a clean reinstall.

![Installing Atomic Red Team (install script)](screenshots/Screenshot%202026-02-10%20181959.png)

![Atomic Red Team already installed message](screenshots/Screenshot%202026-02-10%20182044.png)

- For **Exercise 1**, ran the credential-dumping test (T1003.001 – LSASS memory):

```powershell
Invoke-AtomicTest T1003.001
```

![Running Invoke-AtomicTest T1003.001](screenshots/Screenshot%202026-02-10%20182144.png)

This simulates access to LSASS so we can validate detection.

---

### 5. Exercise 1: Credential Dumping Detection (T1003.001)

- **Objective:** Detect when something accesses LSASS (credential dumping).
- **Steps taken:**
  1. Simulated the attack with `Invoke-AtomicTest T1003.001` on the Windows agent.
  2. Added a **custom Wazuh rule** on the manager to detect LSASS access and map it to T1003.001.

- On the **Ubuntu (Wazuh manager)** VM, edited the local rules file:

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

![Editing local_rules.xml on the manager](screenshots/Screenshot%202026-02-10%20215425.png)

#### Detection rules I added for T1003.001

- Added a rule that triggers on Windows events where the target image is `lsass.exe`, with level 12 and MITRE ID **T1003.001**:

![Custom rule for credential dumping (LSASS) – T1003.001](screenshots/Screenshot%202026-02-10%20215515.png)

- Reloaded and restarted the manager so the new rule loaded:

```bash
systemctl daemon-reload
systemctl restart wazuh-manager
```

![Restarting Wazuh manager after rule change](screenshots/Screenshot%202026-02-10%20215717.png)

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

![Full local_rules.xml with multiple custom rules](screenshots/Screenshot%202026-02-10%20220445.png)

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

![MITRE ATT&CK events – Windows-Client1](screenshots/Screenshot%202026-02-10%20220041.png)

![MITRE ATT&CK table including T1003.001 and other techniques](screenshots/Screenshot%202026-02-10%20220253.png)

![LSASS filter and T1003.001 / T1055 events](screenshots/Screenshot%202026-02-10%20220801.png)

- **What was detected:** The custom rule (100100) and built-in Windows event collection allowed Wazuh to detect the simulated credential-dumping activity (T1003.001) and surface it in the dashboard with correct MITRE mapping. The same 24h window showed a broad mix of tactics (Execution, Discovery, Command and Control, Defense Evasion, Credential Access, Persistence, Privilege Escalation) from both default and custom rules in `local_rules.xml`.
- **What I’d do next:** Compare with Windows Security/Event Logs (e.g. Event ID 4656 for LSASS access) to confirm alignment and document any gaps (e.g. events that appear in Windows but not in Wazuh, or the other way around).

---

## Things I Learned

### EDR (Endpoint Detection and Response)

- **What EDR-style detection looks like in practice:** Endpoint visibility (agent + Sysmon on Windows) feeding a central manager, custom detection rules, and validating that detections fire by running simulated attacks. This lab followed that same workflow — tune rules, run Atomic Red Team, confirm in the dashboard.
- **Why Sysmon matters for EDR:** Sysmon generates detailed Windows events (process creation, network, file access, etc.). Without it (or a similar data source), many ATT&CK techniques wouldn’t produce events for the SIEM/EDR to detect. The config file (`sysmonconfig.xml`) can be aligned with MITRE ATT&CK so tests produce the right telemetry.

### Wazuh as a SIEM and dashboard

- **Wazuh stack:** Manager (rules + correlation), indexer (storage), and dashboard (web UI). The dashboard is the main place you see agents, alerts, and MITRE ATT&CK coverage.
- **Dashboard views I used:** **Overview** (alert counts, severity), **Agents / Endpoints** (agent status: Active, IP, name), **MITRE ATT&CK** (techniques and tactics per agent), and **Events** (raw/correlation events with filters). Filtering in Events (e.g. on `data.win.eventdata.targetImage` for LSASS) made it easy to confirm T1003.001 and related alerts.
- **Agent–manager model:** The Windows machine runs a **Wazuh agent** that collects logs and events and sends them to the **manager**. The manager runs the detection rules and stores/indexes data; the dashboard queries that. Agent status (Active vs disconnected) and correct manager address are critical for seeing any data.

### MITRE ATT&CK

- **Techniques and tactics:** Techniques (e.g. T1003.001 – LSASS credential dumping) sit under tactics (Credential Access, Execution, Discovery, etc.). The Wazuh dashboard surfaces both — you see which techniques fired and which tactics they belong to.
- **Mapping rules to ATT&CK:** Custom and built-in rules can tag alerts with MITRE technique IDs so the SIEM dashboard can show coverage and help prioritize what’s in scope (e.g. T1003.001, T1055, T1073/T1574).

### Detection rules (Wazuh)

- **Where rules live:** Custom rules go in `local_rules.xml` on the manager (`/var/ossec/etc/rules/local_rules.xml`). After editing, the manager must be restarted (e.g. `systemctl restart wazuh-manager`) so new rules load.
- **Rule structure:** Rules use XML — rule ID, level (severity), description, and conditions. They can **chain** on other rules via `<if_sid>` (e.g. rule 100100 chains on 61612 for process-access events). Conditions use things like `<field name="win.eventdata.TargetImage">(?i)lsass.exe</field>` (PCRE2). Adding `<mitre>` blocks links the alert to ATT&CK in the dashboard.
- **Testing rules:** Run an Atomic Red Team test that triggers the technique (e.g. `Invoke-AtomicTest T1003.001`), then check the dashboard to see if the alert fires and shows up under the right technique.

### Atomic Red Team

- **Purpose:** Pre-built tests that simulate ATT&CK techniques (e.g. credential dumping, execution, persistence). You run them on a test endpoint to validate that your detection rules and SIEM/EDR actually see the activity.
- **Workflow:** Install Atomic Red Team (and Sysmon) on the Windows VM, run a specific test (e.g. T1003.001), then look at the Wazuh dashboard to confirm the corresponding alert and MITRE mapping.

### VM and lab networking

- **Connecting two VMs:** Initially the Ubuntu manager only had NAT (IP 10.0.2.15), and the Windows agent couldn’t reliably reach it. I added a **Host-Only adapter** to both VMs so they’re on the same virtual network. After that, the manager was **192.168.56.101** and the agent **192.168.56.102**, and the agent stayed Active. The IP change in the screenshots (10.0.2.15 vs 192.168.56.x) reflects that — the first IP was before the VMs were properly connected; 192.168.56.x is after.
- **NAT vs Host-Only:** NAT gives the VMs internet (installs, updates). Host-Only gives a stable, private network between the host and the VMs so the agent can talk to the manager and the host can open the Wazuh dashboard in a browser.

---

## Summary

| Item | Detail |
|------|--------|
| **Lab** | Lab 1 – MITRE ATT&CK Detection Engineering, through Exercise 1 |
| **VMs** | Windows 10 (Wazuh agent), Ubuntu (Wazuh manager), both in VirtualBox with Host-Only + NAT |
| **Wazuh** | Manager 4.14.2 on Ubuntu; agent 4.14.2 on Windows 10, registered as Windows-Client1 |
| **Sysmon** | Installed on Windows 10 VM with `sysmonconfig.xml` before Atomic Red Team (required for ART tests to generate detectable events) |
| **Attack simulation** | Atomic Red Team, `Invoke-AtomicTest T1003.001` (credential dumping – LSASS) |
| **Custom rules** | `local_rules.xml`: Regsvr32 proxy execution, Security Software Discovery (115004), UAC Bypass (115005), Credential Dumping/LSASS (100100) |
| **Dashboard (24h)** | 117 MITRE ATT&CK events; other techniques logged: T1055, T1073/T1574, T1105, T1059.x, T1070.004, T1087 (rule IDs 92900, 92910, 115002, 92213, 92201, 92027, 92052, 92021, 92031) |
| **Result** | Credential-dumping (T1003.001) detected via custom rule 100100; multiple other tactics (Execution, Discovery, C2, Defense Evasion, Credential Access, Persistence, Privilege Escalation) visible in dashboard |

---

## References

- [Cybersecurity Lab Guide](Cybersecurity_Lab_Guide.pdf) (local)
- [Microsoft Sysinternals – Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK T1003.001 – OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
