# SOC Investigation Report — Day 01
## Port Scan Detection & Analysis

---

| Field | Details |
|-------|---------|
| **Report ID** | SOC-2026-001 |
| **Date** | May 16, 2026 |
| **Analyst** | ryzil07 |
| **Severity** | Medium |
| **Status** | Detected & Documented |
| **MITRE Technique** | T1595 — Active Scanning |

> **Security Notice:** All hostnames, usernames, and personal
> identifiers have been redacted. Lab IPs (192.168.56.x/24)
> are private host-only addresses — no external exposure.

---

## 1. What Happened

I ran a port scan from my Kali Linux VM against my Windows machine
to simulate what an attacker does during the reconnaissance phase
of an attack. The scan used Nmap's SYN technique — the same method
real attackers use because it's stealthy and doesn't complete a
full connection.

The scan found 6 open ports. The most dangerous one was **port 445
(SMB)** — the same port exploited by WannaCry ransomware in 2017.

During the investigation I also discovered that my **Wazuh SIEM
dashboard was visible to the attacker** on port 443. A real attacker
would use that to identify and potentially disable my defenses before
attacking. I fixed this immediately with a firewall rule.

Detection wasn't straightforward either — the default Wazuh config
was **actively filtering out** the exact Event IDs needed to detect
port scans (5156 and 5157). I had to dig into the agent config,
identify the exclusion, and remove it before detection worked. This
is a common real-world gap in SIEM deployments.

---

## 2. Lab Setup

```
┌─────────────────────┐         ┌──────────────────────┐
│   Kali Linux VM     │         │   Windows 11 Host    │
│   192.168.56.101    │─────────│   192.168.56.1       │
│   (Attacker)        │  ATTACK │   (Victim/Defender)  │
└─────────────────────┘         └──────────────────────┘
                                          │
                                          │ logs forwarded
                                          ▼
                                ┌──────────────────────┐
                                │   Wazuh SIEM 4.7.3   │
                                │   Docker on Windows  │
                                └──────────────────────┘
```

**Running on Windows host:**
- Sysmon with SwiftOnSecurity ruleset
- Wazuh Agent v4.7.3
- Windows Security Audit Logging (enabled manually)

---

## 3. The Attack

### Commands I Ran from Kali

**Full scan — all 65,535 ports:**
```bash
sudo nmap -sS -sV -O -p- 192.168.56.1
```

| Flag | What it does |
|------|-------------|
| `-sS` | SYN scan — sends half-open packets, never completes handshake |
| `-sV` | Detects service versions on open ports |
| `-O` | Tries to identify the OS |
| `-p-` | Scans every single port, not just common ones |

Took 171 seconds. Found 21 open ports.

**Quick follow-up scan:**
```bash
sudo nmap -sS 192.168.56.1
```
Took 4 seconds. Confirmed 6 key open ports.

---

### What the Scan Found

| Port | Service | Risk | Why it matters |
|------|---------|------|----------------|
| 135 | Windows RPC | Medium | Remote procedure calls |
| 139 | NetBIOS | High | Old protocol — disabled after this investigation |
| 445 | SMB | **Critical** | WannaCry/EternalBlue vector |
| 5357 | WSDAPI | Medium | Windows device discovery |
| 8000 | Splunk | Medium | SIEM web interface visible |
| 8089 | Splunk API | Medium | Management port exposed |

**Port 445 is the critical finding here.** This is exactly what
EternalBlue targets — the exploit behind WannaCry (2017) and
NotPetya. In a real engagement this would be flagged immediately
for emergency patching.

---

### Bonus Finding — My SIEM Was Visible

The deep scan also found these ports open:

| Port | What it revealed |
|------|-----------------|
| 443 | Wazuh dashboard login page |
| 9200 | Wazuh database (OpenSearch) |
| 55000 | Wazuh management API |

An attacker seeing this knows I'm running Wazuh and could try to
access or disable it before attacking. I fixed this with a firewall
rule blocking those ports from the attacker IP:

```powershell
New-NetFirewallRule -DisplayName "Block Attacker from Wazuh" `
  -Direction Inbound `
  -RemoteAddress 192.168.56.101 `
  -LocalPort 443,9200,55000,1514,1515 `
  -Protocol TCP `
  -Action Block
```

After the fix, those ports showed as `filtered` on a follow-up scan.

---

## 4. Timeline

| Time | What happened |
|------|--------------|
| 05:15:48 | Nmap SYN scan starts from 192.168.56.101 |
| 05:15:48 | Windows Filtering Platform starts dropping packets |
| 05:15:48 | Event ID 5157 begins generating |
| 05:15:49 | Wazuh starts firing audit failure alerts |
| 05:15:56 | Last alert captured |
| 05:16:00 | Scan complete — attacker now has full port map |

---

## 5. How I Detected It

### Step 1 — Enable Windows Network Logging

Windows doesn't log network connections by default. I had to
manually enable this:

```powershell
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
```

This generates **Event ID 5157** for every blocked connection —
which is exactly what an Nmap SYN scan creates hundreds of.

### Step 2 — Fix the Wazuh Config

This was the tricky part. After enabling logging, alerts still
weren't showing in Wazuh. I dug into the agent config at:

```
C:\Program Files (x86)\ossec-agent\ossec.conf
```

And found this in the Security log collection section:

```xml
<query>Event/System[EventID != 5156 and EventID != 5157...]</query>
```

The default config was **deliberately excluding** Event IDs 5156
and 5157. Removed both exclusions, restarted the agent, and
detection worked immediately.

### Step 3 — What Wazuh Caught

| Field | Value |
|-------|-------|
| Rule | Windows audit failure event |
| Rule Level | 5 |
| Event ID | 5157 |
| Source IP | 192.168.56.101 (Kali — attacker) |
| Destination | 192.168.56.1 (Windows — victim) |
| Direction | Inbound |
| Action | Blocked |

---

## 6. MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Reconnaissance (TA0043) |
| Technique | T1595 — Active Scanning |
| Sub-technique | T1595.001 — Scanning IP Blocks |
| Secondary | T1518.001 — Security Software Discovery |
| Tool | Nmap 7.99 |

The secondary technique (T1518.001) applies because Nmap revealed
my SIEM infrastructure — a defender discovery scenario.

---

## 7. What I Fixed After This Investigation

| Action | Status |
|--------|--------|
| Disabled NetBIOS (port 139) | ✅ Done |
| Blocked SIEM ports from attacker | ✅ Done |
| Enabled Windows network audit logging | ✅ Done |
| Fixed Wazuh config (5156/5157) | ✅ Done |
| Verify EternalBlue patch (KB4012212) | Pending |
| Restrict SMB (445) from untrusted segments | Pending |

---

## 8. What I Learned

The biggest takeaway from this investigation wasn't the port scan
itself — it was discovering that my SIEM had a blind spot by default.
Event IDs 5156 and 5157 are some of the most useful events for
detecting network reconnaissance, and Wazuh was silently dropping
them. In a real SOC environment this kind of gap could mean missing
an attacker's early reconnaissance entirely.

The second lesson was OPSEC — exposing your SIEM on the same network
as potential attackers is a real problem. In enterprise environments,
SIEM infrastructure sits on a dedicated management VLAN with no
direct access from user or untrusted networks.

---

*Part of my Home SOC Lab daily investigation series.*
*GitHub: https://github.com/ryzil07/SOC-Analyst-Homelab*
