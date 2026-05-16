# 🔍 SOC Investigation Report — Day 01
## Reconnaissance: Port Scan Detection & Analysis

---

| Field | Details |
|-------|---------|
| **Report ID** | SOC-2026-001 |
| **Date** | May 16, 2026 |
| **Analyst** | [Your Name] |
| **Severity** | 🟡 Medium |
| **Status** | ✅ Detected & Documented |
| **MITRE Technique** | T1595 — Active Scanning |

---

## 1. Executive Summary

On May 16, 2026 at approximately 05:15:48, a TCP SYN port scan was detected originating from internal host `192.168.56.101` (Kali Linux — Attacker Machine) targeting the Windows production host at `192.168.56.1`. The scan was performed using **Nmap 7.99** and successfully identified 6 open ports including the critically vulnerable **SMB port 445**.

The attack was detected by **Wazuh SIEM v4.7.3** via Windows Filtering Platform audit logs (Event ID 5157). Initial SIEM configuration required tuning — Event IDs 5156 and 5157 were excluded by default and had to be re-enabled to achieve detection. This highlights a common real-world SIEM gap: default configurations are rarely sufficient for comprehensive threat detection.

A critical security gap was also identified during this investigation: **Wazuh SIEM infrastructure ports were visible to the attacker**, enabling potential defender discovery. Firewall remediation was applied immediately.

---

## 2. Lab Architecture

```
┌─────────────────────┐         ┌──────────────────────┐
│   Kali Linux VM     │         │   Windows 11 Host    │
│   192.168.56.101    │─────────│   192.168.56.1       │
│   (Attacker)        │  ATTACK │   (Victim/Defender)  │
└─────────────────────┘         └──────────────────────┘
                                          │
                                          │ Logs
                                          ▼
                                ┌──────────────────────┐
                                │   Wazuh SIEM 4.7.3   │
                                │   (Docker Container) │
                                │   https://localhost  │
                                └──────────────────────┘
```

**Tools Running on Windows Host:**
- Sysmon (SwiftOnSecurity config) — process & file monitoring
- Wazuh Agent v4.7.3 — log forwarding to SIEM
- Windows Audit Logging — network connection events

---

## 3. Attack Details

### 3.1 Attack Tool
**Nmap 7.99** — Industry standard network scanner used by both attackers and security professionals.

### 3.2 Commands Executed

**Scan 1 — Full Deep Scan (Reconnaissance):**
```bash
sudo nmap -sS -sV -O -p- 192.168.56.1
```

| Flag | Meaning |
|------|---------|
| `-sS` | SYN Scan — stealthy, half-open connection |
| `-sV` | Service version detection |
| `-O` | OS fingerprinting |
| `-p-` | All 65,535 ports scanned |

**Duration:** 171.93 seconds  
**Result:** 21 open ports discovered

---

**Scan 2 — Targeted Quick Scan (Verification):**
```bash
sudo nmap -sS 192.168.56.1
```
**Duration:** 4.65 seconds  
**Result:** 6 open ports confirmed

---

### 3.3 Attack Timeline

| Time (UTC-4) | Event |
|---|---|
| `05:15:48` | Nmap SYN scan initiated from `192.168.56.101` |
| `05:15:48` | Windows Filtering Platform begins blocking packets |
| `05:15:48` | Event ID 5157 generated — multiple instances |
| `05:15:49` | Wazuh audit failure alerts begin firing |
| `05:15:56` | Final audit failure event captured |
| `05:16:00` | Scan completes — attacker has full port map |

---

## 4. Findings — Open Ports Discovered

The attacker successfully mapped the following open ports:

| Port | Protocol | Service | Risk Level | Notes |
|------|----------|---------|------------|-------|
| `135` | TCP | Microsoft Windows RPC | 🟡 Medium | Remote procedure calls |
| `139` | TCP | NetBIOS-SSN | 🔴 High | Legacy protocol, multiple vulnerabilities |
| `445` | TCP | Microsoft SMB | 🔴 **Critical** | EternalBlue/WannaCry attack vector |
| `5357` | TCP | WSDAPI / HTTP | 🟡 Medium | Windows device discovery |
| `8000` | TCP | Splunk HTTP | 🟡 Medium | SIEM interface exposed |
| `8089` | TCP | Splunk API | 🟡 Medium | Management API visible |

### ⚠️ Critical Finding — Port 445 (SMB)

Port 445 is the attack surface used by:
- **WannaCry Ransomware** (2017) — infected 200,000+ systems globally
- **EternalBlue Exploit (MS17-010)** — NSA-developed exploit leaked by Shadow Brokers
- **NotPetya** — destructive wiper disguised as ransomware

**This port being open and visible to an attacker is a critical risk.**

---

### 4.1 Additional Finding — SIEM Infrastructure Exposed

During the initial deep scan, the attacker also discovered:

| Port | Service | Implication |
|------|---------|-------------|
| `443` | Wazuh Dashboard | Attacker knows a SIEM is running |
| `9200` | Wazuh Indexer (OpenSearch) | Database port exposed |
| `55000` | Wazuh API | Management API accessible |
| `1514/1515` | Wazuh Agent ports | Agent communication visible |

This is **MITRE ATT&CK T1518.001 — Software Discovery: Security Software Discovery**. A sophisticated attacker would use this information to attempt to disable the SIEM before launching further attacks.

**Remediation Applied:**
```powershell
New-NetFirewallRule -DisplayName "Block Kali from Wazuh Dashboard" `
  -Direction Inbound `
  -RemoteAddress 192.168.56.101 `
  -LocalPort 443,9200,55000,1514,1515 `
  -Protocol TCP `
  -Action Block
```

**Verification — After Fix:**
```
PORT      STATE    SERVICE
443/tcp   filtered https       ← was: open
9200/tcp  filtered wap-wsp     ← was: open
55000/tcp filtered unknown     ← was: open
```
✅ SIEM ports successfully hidden from attacker.

---

## 5. Detection Evidence

### 5.1 How Detection Was Achieved

| Component | Role |
|-----------|------|
| Windows Audit Policy | Enabled logging for `Filtering Platform Connection` and `Filtering Platform Packet Drop` |
| Event ID 5157 | Windows blocked inbound connection — logged each Nmap probe |
| Wazuh Agent | Forwarded Security logs to SIEM |
| Wazuh SIEM | Aggregated events and raised alerts |

**Audit Policy Commands Used:**
```powershell
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
```

### 5.2 Wazuh Alert Details

| Field | Value |
|-------|-------|
| Agent | Windows-Host |
| Rule Description | Windows audit failure event |
| Rule Level | 5 |
| Rule ID | 60104 |
| Event ID | 5157 |
| Source IP | `192.168.56.101` |
| Destination IP | `192.168.56.1` |
| Direction | Inbound |
| Action | Blocked |

### 5.3 SIEM Configuration Gap — Identified & Fixed

> **Important Finding:** Default Wazuh agent configuration explicitly excluded Event IDs 5156 and 5157:
>
> ```xml
> <query>Event/System[EventID != 5156 and EventID != 5157...]</query>
> ```
>
> These exclusions prevented port scan detection entirely. The configuration was modified to remove these exclusions, enabling full network connection visibility.
>
> **Lesson:** Default SIEM configurations are never sufficient. SOC analysts must audit and tune their detection rules for their specific environment.

---

## 6. MITRE ATT&CK Mapping

```
TACTIC: Reconnaissance (TA0043)
│
├── T1595 — Active Scanning
│   └── T1595.001 — Scanning IP Blocks
│       ├── Tool: Nmap 7.99
│       ├── Method: TCP SYN Scan (-sS)
│       └── Target: 192.168.56.1
│
└── T1518.001 — Software Discovery: Security Software Discovery
    ├── Finding: Wazuh SIEM ports exposed (443, 9200, 55000)
    └── Risk: Attacker aware of defensive tooling
```

| ATT&CK Field | Value |
|---|---|
| Tactic | Reconnaissance |
| Technique | T1595 — Active Scanning |
| Sub-technique | T1595.001 — Scanning IP Blocks |
| Secondary Technique | T1518.001 — Security Software Discovery |
| Tool Used | Nmap 7.99 |
| Platform | Windows |

---

## 7. OS Fingerprinting Result

Nmap successfully identified the target operating system:

```
Running: Microsoft Windows 11
Confidence: 97%
CPE: cpe:/o:microsoft:windows_11
```

**Implication:** With OS information confirmed, an attacker can now look up Windows 11 specific exploits, unpatched CVEs, and default misconfigurations to target in follow-up attacks.

---

## 8. Recommendations

### Immediate Actions

| Priority | Action | Command/Method |
|----------|--------|----------------|
| 🔴 Critical | Verify MS17-010 patch (EternalBlue) | `Get-HotFix -Id KB4012212` |
| 🔴 Critical | Restrict SMB (445) from untrusted segments | Windows Firewall rule |
| 🔴 High | Disable NetBIOS (139) | Network adapter → WINS → Disable |
| 🟡 Medium | Move SIEM to isolated management VLAN | Network segmentation |
| 🟡 Medium | Restrict Splunk ports to localhost only | Splunk config |
| 🟢 Low | Disable WSDAPI (5357) if not needed | Services → Disable |

### Long-term SOC Improvements

1. **Create custom Wazuh rule** for port scan detection — trigger alert when more than 15 connection failures occur from same IP within 60 seconds
2. **Implement network segmentation** — SIEM should never be on the same network segment as untrusted hosts
3. **Enable VPN-only SIEM access** — dashboard should not be reachable without authentication at network level
4. **Set up automated active response** — Wazuh can automatically block IPs that trigger port scan alerts

---

## 9. Lessons Learned

| # | Lesson |
|---|--------|
| 1 | Default SIEM configurations require tuning — 5156/5157 excluded by default |
| 2 | SIEM infrastructure must be hidden from attacker-accessible networks |
| 3 | Port 445 being open represents a critical unmitigated risk |
| 4 | Reconnaissance detection is the first line of defense — catch attackers before they attack |
| 5 | OS fingerprinting gives attackers a significant advantage — consider TCP/IP stack hardening |

---

## 10. Evidence Files

| Evidence | Description |
|----------|-------------|
| `nmap-scan-1-full.txt` | Full Nmap output — 65,535 port scan |
| `nmap-scan-2-quick.txt` | Quick scan output — 6 open ports |
| `nmap-scan-3-wazuh-ports.txt` | Verification scan — filtered ports confirmed |
| `wazuh-alert-screenshot.png` | Wazuh dashboard showing audit failure alerts |
| `wazuh-event-detail.png` | Expanded event showing sourceAddress 192.168.56.101 |
| `wazuh-mitre-dashboard.png` | MITRE ATT&CK mapping in Wazuh |
| `wazuh-agent-active.png` | Windows-Host agent active confirmation |

---

## 11. Analyst Notes

> This was the first investigation conducted in this SOC home lab environment. Several configuration challenges were encountered and resolved during this investigation, including fixing a corrupt Kali history file, reconfiguring the VM network adapter from NAT to Host-Only, enabling Windows Firewall audit logging, and tuning the Wazuh agent configuration to capture network events.
>
> Each challenge encountered represents a real-world SOC scenario — production environments frequently have misconfigured agents, incomplete logging pipelines, and detection gaps that analysts must identify and remediate. Documenting these issues and their resolutions is as valuable as the detection itself.

---

*Report generated as part of Home SOC Lab — Daily Investigation Series*  
*GitHub: [your-github-url] | LinkedIn: [your-linkedin-url]*
