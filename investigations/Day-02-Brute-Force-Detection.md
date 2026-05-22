# SOC Investigation Report — Day 02
## Credential Attack: SSH Brute Force Detection & Analysis

---

| Field | Details |
|-------|---------|
| **Report ID** | SOC-2026-002 |
| **Date** | May 22, 2026 |
| **Analyst** | ryzil07 |
| **Severity** | High |
| **Status** | Detected & Documented |
| **MITRE Technique** | T1110 — Brute Force |

> **Security Notice:** All hostnames, usernames, and personal
> identifiers have been redacted. Lab IPs are private host-only
> addresses with no external exposure.

---

## 1. What Happened

Following Day 01's port scan reconnaissance, I moved to the next
phase of a simulated attack — credential brute forcing. This is
what real attackers do after mapping open ports: they pick a login
service and hammer it with password attempts until something works.

I used **Hydra** to run two brute force attacks against an SSH
service running on the lab machine. The first attack used a small
custom wordlist and cracked the password in **5 seconds**. The
second attack used the **rockyou.txt** wordlist — 14 million
real-world passwords leaked from actual data breaches — to
generate a high-volume attack and observe how the SIEM responds
under load.

The results were dramatic. Wazuh went from around 128 alerts
baseline to **1,227 total alerts** during the attack. The alert
spike was clearly visible in the dashboard timeline. More
importantly, a **Level 12 critical alert** fired — the highest
severity in our setup — because the brute force volume was so
intense it flooded the Wazuh agent's event queue. That's a
real-world detection gap worth documenting.

---

## 2. Lab Setup

```
┌─────────────────────┐         ┌──────────────────────┐
│   Kali Linux VM     │         │   Windows 11 Host    │
│   [ATTACKER-IP]    │─────────│   [VICTIM-IP]       │
│   (Attacker)        │  ATTACK │   (Victim/Defender)  │
└─────────────────────┘         └──────────────────────┘
                                          │
                                          │ logs forwarded
                                          ▼
                                ┌──────────────────────┐
                                │   Wazuh SIEM [version redacted]   │
                                │   containerized deployment  │
                                └──────────────────────┘
```

**Attack target:** SSH service on lab attacker VM
**Tool used:** Hydra v9.6
**Wordlists:** Custom 10-password list + rockyou.txt (14M passwords)

---

## 3. The Attack

### Phase 1 — Small Wordlist Attack

I created a custom password file with 10 common passwords and
ran Hydra against the SSH service:

```bash
# Create password list
nano ~/passwords.txt

# Contents:
# [common passwords redacted]


# Launch attack
hydra -l [username] -P ~/passwords.txt ssh://[LOCALHOST] -t 4 -v
```

**What every flag does:**

| Flag | Meaning |
|------|---------|
| `-l [username]` | Single username to try |
| `-P ~/passwords.txt` | Use our password file |
| `ssh://[LOCALHOST]` | Target SSH on localhost |
| `-t 4` | 4 parallel threads |
| `-v` | Show every attempt live |

**Result:**
```
[22][ssh] host: [LOCALHOST] login: [redacted] password: [redacted]
1 of 1 target successfully completed, 1 valid password found
Time taken: 5 seconds
```

Password cracked in 5 seconds. The target account had weak credentials that appeared early in common password lists. This is exactly the kind of misconfiguration that gets real systems compromised — and it takes an attacker less time to exploit than it takes to read this sentence.

---

### Phase 2 — Rockyou Wordlist Attack (High Volume)

To generate a realistic high-volume attack pattern visible in
the SIEM, I ran a second attack using the rockyou wordlist:

```bash
# Extract the wordlist first
# extract the wordlist — command varies by OS

# Launch high-volume attack
sudo hydra -l [username] -P /usr/share/wordlists/rockyou.txt ssh://[LOCALHOST] -t 2 -W 3 -v -f
```

**Additional flags:**

| Flag | Meaning |
|------|---------|
| `-t 2` | Reduced to 2 threads — SSH was rate-limiting at 4 |
| `-W 3` | 3 second wait between attempts — avoids lockout |
| `-f` | Stop immediately when password found |
| rockyou.txt | 14,344,399 real passwords from actual data breaches |

**Why rockyou.txt matters:** This wordlist was leaked from the
RockYou website breach in 2009. It contains real passwords that
real people used. Attackers use it because if your password is
in this list, it will be found.

---

### Finding — SSH Rate Limiting Activated

During the rockyou attack, SSH started rejecting connections:
```
[ERROR] could not connect to target port 22: Socket error:
Connection reset by peer
```

This is **SSH's built-in brute force protection** kicking in —
it temporarily blocks IPs that make too many failed attempts.
This is a good defensive control but it's not enough on its own
because:
- Attackers slow down their attacks to stay under the threshold
- Distributed attacks use multiple IPs to avoid rate limits
- The `-W 3` flag in our command was specifically designed to
  bypass this protection

---

## 4. Evidence from SSH Logs

After the attack I pulled the SSH authentication logs to document
every attempt:

```bash
sudo journalctl -u ssh --since "[REDACTED]" --until "[REDACTED]"
```

The logs showed the complete attack chain:

| Log Entry | Meaning |
|-----------|---------|
| `password check failed for user [redacted]` | Wrong password — Hydra trying next one |
| `authentication failure; rhost=[LOCALHOST]` | Failed login recorded |
| `Failed password for [redacted] from [LOCALHOST]` | Another failed attempt |
| `Accepted password for [redacted] from [LOCALHOST]` | Password cracked — attacker in |
| `session opened for user [redacted]` | Attacker has active session |
| `session closed for user [redacted]` | Session ended |

Multiple failures all at the same second, then one success —
this is the textbook brute force pattern in authentication logs.

---

## 5. Attack Timeline

| Time | Event |
|------|-------|
| `16:36:23` | Hydra starts — first password attempt |
| `16:36:23` | Multiple authentication failures in parallel |
| `16:36:23` | SSH logs show rapid `password check failed` entries |
| `16:36:23` | `Accepted password` — credentials found |
| `16:36:23` | `session opened` — attacker has shell access |
| `16:36:28` | Attack complete — password [redacted] confirmed |
| `16:44:02` | Rockyou attack starts — 14M password list |
| `16:45:36` | SSH rate limiting activates — connections reset |
| `16:46:37` | Attack stops — rate limiting too aggressive |

---

## 6. What Wazuh Detected

### Alert Volume

| Metric | Value |
|--------|-------|
| Alerts before attack | ~128 (baseline from Day 01) |
| Alerts after attack | 1,227 |
| New alerts generated | ~1,099 |
| Peak alert rate | 500+ alerts per 30 minutes |
| Highest severity alert | Level 12 — Critical |

### The Critical Level 12 Alert

The most significant finding from Wazuh wasn't the brute force
alerts themselves — it was this:

```
Rule ID: [redacted]
Level: 12 (Critical)
Description: Agent event queue is flooded.
             Check the agent configuration.
Time: May 22, 2026 @ 00:57:48
```

**What this means:** The brute force generated so many events
so quickly that the Wazuh agent's internal queue filled up and
started dropping events. This is a critical finding because it
means during a high-volume attack, our SIEM was losing evidence.

This is a real-world problem in SOC environments — high-volume
attacks can overwhelm detection pipelines and create blind spots
at exactly the moment you need visibility most.

**Fix for this:** Increase the Wazuh agent event queue size — refer to official Wazuh documentation for recommended values


---

## 7. MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access (TA0006) |
| Technique | T1110 — Brute Force |
| Sub-technique | T1110.001 — Password Guessing |
| Secondary | T1078 — Valid Accounts (after cracking) |
| Tool | Hydra v9.6 |
| Wordlist | rockyou.txt — 14,344,399 entries |

```
TACTIC: Credential Access (TA0006)
│
├── T1110.001 — Password Guessing
│   ├── Tool: Hydra v9.6
│   ├── Target: SSH port 22
│   └── Result: Credentials found in 5 seconds
│
└── T1078 — Valid Accounts
    ├── Finding: Default credentials in use
    └── Risk: Attacker gained authenticated shell access
```

---

## 8. Key Findings

### Finding 1 — Default Credentials (Critical)
The target account was using default credentials — same value for both username and password.
Default credentials are in every brute force wordlist and will
always be found. In a real environment this would mean immediate
full system compromise.

### Finding 2 — SIEM Queue Flooding (High)
The attack volume triggered a Level 12 critical alert about the
agent event queue being flooded. During high-volume attacks, the
SIEM was dropping events — creating a detection blind spot. This
needs to be fixed before this environment is used for more
intensive simulations.

### Finding 3 — SSH Rate Limiting Present but Bypassable (Medium)
SSH has built-in rate limiting that activated during the rockyou
attack. However this protection is bypassable by slowing down
the attack rate — which is exactly what the `-W 3` flag does.
Rate limiting alone is not sufficient protection.

### Finding 4 — No Account Lockout Policy (High)
After repeated failed attempts the account was never locked out.
A proper account lockout policy (e.g. lock after N failed
attempts for 15 minutes) would have stopped this attack
completely.

---

## 9. Post-Investigation Remediation

All services enabled specifically for this simulation were
disabled immediately after the investigation completed. Any
firewall rules created for lab testing purposes were removed.
The lab environment was restored to its pre-investigation
state before this report was published.

The event queue limitation identified during the attack has
been documented for configuration review. No production
systems or real credentials were involved in this simulation.

---

## 10. Recommendations

| Priority | Recommendation | Why |
|----------|---------------|-----|
| 🔴 Critical | Change default credentials immediately | Found in 5 seconds |
| 🔴 Critical | Implement account lockout policy | Stops brute force completely |
| 🔴 High | Increase Wazuh event queue size | Prevent evidence loss during attacks |
| 🟡 Medium | Deploy automated IP blocking on authentication services | Auto-blocks IPs after failed attempts |
| 🟡 Medium | Use key-based authentication instead of passwords | Keys cannot be brute forced |
| 🟢 Low | Set up Wazuh active response | Auto-block attacker IPs in real time |

### How to Implement fail2ban (Recommended)
```bash
sudo apt install fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

fail2ban monitors SSH logs and automatically blocks IPs that
exceed a failed login threshold. It would have blocked this
attack after the first few attempts.

### How to Disable SSH Password Auth
```bash
# open SSH config file in your preferred editor
# Change: PasswordAuthentication yes
# To:     PasswordAuthentication no
sudo systemctl restart ssh
```

After this change, only SSH key pairs work — brute force
against passwords becomes impossible.

---

## 11. Comparison with Day 01

| Aspect | Day 01 — Port Scan | Day 02 — Brute Force |
|--------|-------------------|---------------------|
| Phase | Reconnaissance | Credential Access |
| Tool | Nmap | Hydra |
| MITRE | T1595 | T1110 |
| Alerts generated | ~9 new | ~1,099 new |
| Max alert level | 5 | 12 (Critical) |
| Outcome | Port map obtained | Credentials cracked |
| Most critical finding | SMB port 445 open | Default credentials in use |

The progression here mirrors a real attack chain — reconnaissance
first to understand the target, then credential attack to gain
access. Day 03 will simulate what happens after access is gained.

---

## 12. Lessons Learned

The most interesting thing about this investigation wasn't the
brute force itself — it was the Level 12 alert about the event
queue flooding. I didn't expect the SIEM to struggle under the
attack volume, and finding that gap is genuinely useful. In a
real SOC, missing events during an active attack is one of the
worst things that can happen. Tuning the agent buffer size is
now on the remediation list before any more high-volume
simulations.

The second takeaway is how fast default credentials fall. Five
seconds with a 10-word list. In the real world, automated
scanners are constantly sweeping the internet for SSH, RDP, and
other services with default or weak credentials. If you expose
a service with default creds, it will be compromised — it's not
a question of if, just when.

---

*Home SOC Lab — Daily Investigation Series*
*GitHub: https://github.com/ryzil07/SOC-Analyst-Homelab*
