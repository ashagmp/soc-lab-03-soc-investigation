# Investigation 05: Password Spray → Account Lockout

| Field | Value |
|---|---|
| Date | 2026-10-01 |
| Attacker Host | attack01 (Kali Linux, 192.168.10.70) |
| Target Host | DC01 (192.168.10.10) |
| Target Accounts | `hruser`, `finuser`, `Administrator` (ashag.local) |
| MITRE ATT&CK Technique | T1110.003 — Brute Force: Password Spraying |
| Severity (assessed) | High (multiple domain accounts targeted; one account locked out) |
| Status | Investigated / Closed |

## 1. Scenario

Fifth investigation. Unlike the brute force techniques in Investigations 02 and 03 (many passwords against one account), a password spray uses **one password against many accounts** — staying under the lockout threshold per account to avoid detection while still testing credentials across the domain user base.

This investigation also tests the account lockout policy configured as part of the lab environment — specifically confirming that EventCode 4740 (account lockout) fires on the Domain Controller when the threshold is exceeded, and that the policy itself is a meaningful detective and preventive control.

## 2. Pre-Attack: Account Lockout Policy Configuration

Prior to this investigation, the Default Domain Policy had no lockout threshold configured (`LockoutThreshold: 0` — effectively disabled). This was confirmed during the investigation as the reason brute force in Investigation 03 succeeded without any lockout.

The policy was configured on DC01 before running the spray:

| Setting | Value |
|---|---|
| Account lockout threshold | 5 invalid logon attempts |
| Account lockout duration | 30 minutes |
| Reset account lockout counter after | 30 minutes |

Applied via Group Policy Management → Default Domain Policy → Account Lockout Policy, then enforced with `gpupdate /force` on DC01 and HR-PC01.

## 3. Attack Execution

**Tool:** `netexec` (nxc) — successor to crackmapexec, pre-installed on Kali Linux

**Step 1 — Password spray: one password against three domain accounts:**
```bash
nxc smb 192.168.10.10 -u hruser -p 'Password1!' -d ashag.local
nxc smb 192.168.10.10 -u finuser -p 'Password1!' -d ashag.local
nxc smb 192.168.10.10 -u Administrator -p 'Password1!' -d ashag.local
```

All three returned `STATUS_LOGON_FAILURE` — password incorrect, but no lockout triggered (each account only received one failed attempt, staying under the threshold of 5).

**Step 2 — Deliberate lockout: six attempts against hruser:**
```bash
nxc smb 192.168.10.10 -u hruser -p 'WrongPass1!' -d ashag.local
nxc smb 192.168.10.10 -u hruser -p 'WrongPass2!' -d ashag.local
nxc smb 192.168.10.10 -u hruser -p 'WrongPass3!' -d ashag.local
nxc smb 192.168.10.10 -u hruser -p 'WrongPass4!' -d ashag.local
nxc smb 192.168.10.10 -u hruser -p 'WrongPass5!' -d ashag.local
nxc smb 192.168.10.10 -u hruser -p 'WrongPass6!' -d ashag.local
```

**Key output:**
```
[-] ashag.local\hruser:WrongPass1! STATUS_LOGON_FAILURE
[-] ashag.local\hruser:WrongPass2! STATUS_LOGON_FAILURE
[-] ashag.local\hruser:WrongPass3! STATUS_LOGON_FAILURE
[-] ashag.local\hruser:WrongPass4! STATUS_LOGON_FAILURE
[-] ashag.local\hruser:WrongPass5! STATUS_LOGON_FAILURE
[-] ashag.local\hruser:WrongPass6! STATUS_ACCOUNT_LOCKED_OUT
```

The status change from `STATUS_LOGON_FAILURE` to `STATUS_ACCOUNT_LOCKED_OUT` on attempt 6 confirms the lockout policy triggered after exactly 5 failures.

**Note on tooling:** Initial spray attempts targeted HR-PC01 (192.168.10.100) directly via SMB but encountered NETBIOS connection timeouts. Authentication attempts were redirected to DC01 (192.168.10.10), the domain's authentication authority, which responded correctly. This is consistent with how real attackers target DCs for domain credential validation rather than individual workstations.

## 4. Detection

```spl
index=windows host=DC01 source="XmlWinEventLog:Security" EventCode=4625 OR EventCode=4740
| table _time, EventCode, TargetUserName, IpAddress, Status
| sort _time
```

**Results: 10 events total**

| EventCode | TargetUserName | Count | Meaning |
|---|---|---|---|
| 4625 | hruser | 6 | Failed logon attempts — spray + lockout sequence |
| 4625 | finuser | 1 | Failed logon attempt — spray |
| 4625 | Administrator | 2 | Failed logon attempts — spray (earlier run included) |
| 4740 | hruser | 1 | Account locked out |

**Password spray pattern indicators:**
- Multiple distinct accounts (`hruser`, `finuser`, `Administrator`) receiving failed logon attempts
- All failures originating from the same source IP (`192.168.10.70`) within a short time window
- Low per-account failure count (1 each for `finuser` and `Administrator`) — consistent with deliberate threshold-avoidance
- `Status: 0xc000006d` on all 4625 events — authentication failure (wrong password)

**Lockout indicator:**
- EventCode **4740** for `hruser` at `10:50:02` — fired on the Domain Controller when the threshold was exceeded

## 5. Investigation Timeline

| Time (UTC) | Event | Source |
|---|---|---|
| 10:41:56 | First failed logon for `Administrator` from `192.168.10.70` | DC01 Security log |
| 10:48:32 | Failed logon for `hruser` — spray begins | DC01 Security log |
| 10:48:54 | Failed logon for `finuser` | DC01 Security log |
| 10:49:23 | Failed logon for `Administrator` | DC01 Security log |
| 10:49:45–10:50:02 | Four more failed logons for `hruser` (WrongPass2–5) | DC01 Security log |
| 10:50:02 | **EventCode 4740 — hruser locked out** | DC01 Security log |
| 10:50:02 | Final failed logon for `hruser` (WrongPass6) — `STATUS_ACCOUNT_LOCKED_OUT` | DC01 Security log |

## 6. Indicators of Compromise (IOCs)

- Source IP: `192.168.10.70` (attack01)
- Target host: `192.168.10.10` (DC01, authentication endpoint)
- Accounts targeted: `hruser`, `finuser`, `Administrator`
- Pattern: multiple accounts, single source IP, short time window, low per-account failure count
- `Status: 0xc000006d` — wrong password across all spray attempts
- EventCode 4740 — `hruser` locked out

## 7. Response & Remediation

**Lab response:**
- Unlock `hruser`: `Unlock-ADAccount -Identity hruser` on DC01
- Block `192.168.10.70` from reaching DC01's SMB port (445)

**Production considerations:**
- The account lockout policy (configured as part of this investigation's setup) is now in place and working — EventCode 4740 fired correctly when the threshold was exceeded. This is a confirmed detective and preventive control.
- A Splunk alert on EventCode 4740 would notify the SOC immediately when any account is locked out — a single lockout warrants investigation; multiple lockouts in a short window is a high-confidence spray indicator
- Consider alerting also on the spray pattern itself, before lockout occurs:
```spl
index=windows host=DC01 source="XmlWinEventLog:Security" EventCode=4625
| bucket _time span=5m
| stats dc(TargetUserName) as unique_accounts, count by _time, IpAddress
| where unique_accounts > 2
```
This fires when a single source IP fails authentication against more than 2 distinct accounts within a 5-minute window — catches the spray before it triggers lockout.

## 8. Lessons Learned / Detection Gaps

- **EventCode 4740 always fires on the Domain Controller, not the workstation.** Account lockout events are recorded where authentication is processed — on DC01. A SOC analyst investigating only endpoint logs (HR-PC01, web01) would miss this event entirely without SIEM-centralised log collection from DC01.
- **Password spray is designed to evade per-account lockout policies.** One failed attempt per account does not trigger lockout — the spray pattern is only visible when aggregating across accounts and correlating by source IP and time window. Single-account logon monitoring cannot catch this; multi-account correlation is required.
- **Lockout policy was disabled by default.** The Default Domain Policy shipped with `LockoutThreshold: 0`, meaning all previous brute force attempts in this lab ran against an environment with no lockout protection. Enabling the lockout policy is a basic hardening step that should be confirmed in any new AD deployment.
- **The status code change is definitive evidence.** The shift from `STATUS_LOGON_FAILURE` (0xc000006d) to `STATUS_ACCOUNT_LOCKED_OUT` on the 6th attempt is unambiguous proof that the lockout policy functioned correctly — and that the attacker's tool detected the lockout state in real time.

## Evidence

- [nxc-spray-output.txt](../evidence/05-password-spray-lockout/nxc-spray-output.txt) — full netexec output showing STATUS_LOGON_FAILURE and STATUS_ACCOUNT_LOCKED_OUT
- [splunk-dc01-4625-4740.png](../evidence/05-password-spray-lockout/splunk-dc01-4625-4740.png) — Splunk search showing 10 events: failed logons across three accounts and EventCode 4740 lockout
