# Investigation 04: Windows → Linux Lateral Movement via SSH

| Field | Value |
|---|---|
| Date | 2026-09-30 |
| Attacker Host | attack01 (Kali Linux, 192.168.10.70) → HR-PC01 (192.168.10.100) |
| Target Host | web01 (192.168.10.20) |
| Target Account | `ashag` |
| MITRE ATT&CK Technique | T1021.004 — Remote Services: SSH |
| Severity (assessed) | High (lateral movement from compromised Windows host to Linux server) |
| Status | Investigated / Closed |

## 1. Scenario

Fourth investigation, continuing directly from Investigation 03. The attacker has an active RDP session on `HR-PC01` as `hruser` (established via brute force in Investigation 03). Using that Windows foothold as a pivot point, the attacker SSHes from `HR-PC01` into `web01` — moving laterally across OS boundaries from the compromised Windows workstation to the Linux server.

This is the realistic lateral movement pattern: the SSH connection originates from an internal, trusted IP (`192.168.10.100`, HR-PC01), not from the attacker's Kali machine (`192.168.10.70`). To a defender looking only at `web01`'s auth log without correlating against HR-PC01's RDP events, this would appear to be a legitimate internal SSH connection.

## 2. Attack Chain

```
attack01 (192.168.10.70)
      │
      │ RDP brute force → successful login (Investigation 03)
      ▼
HR-PC01 (192.168.10.100) — compromised Windows foothold
      │
      │ SSH from inside RDP session
      ▼
web01 (192.168.10.20) — lateral movement target
```

## 3. Attack Execution

**Step 1 — re-establish RDP session to HR-PC01 from attack01:**
```bash
xfreerdp /u:hruser /p:'Aa1111!' /v:192.168.10.100
```

**Step 2 — from inside the RDP session on HR-PC01, SSH into web01:**
```cmd
ssh ashag@192.168.10.20
```

**Step 3 — post-access reconnaissance commands run on web01:**
```bash
whoami
hostname
cat /etc/passwd
ls /home
```

**Step 4 — exit sessions:**
```bash
exit    # exits web01 SSH session
```
RDP session closed.

## 4. Detection

Detection for this investigation requires **correlating events across two hosts** — a single-host view is insufficient to see the full lateral movement chain.

**Search 1 — SSH login on web01 (identifies the lateral movement):**
```spl
index=linux host=web01 source="/var/log/auth.log" "Accepted password"
| table _time, _raw
| sort -_time
```

Result: `Accepted password for ashag from 192.168.10.100 port 59489 ssh2`

The source IP `192.168.10.100` (HR-PC01) is the critical indicator — this is an internal Windows workstation, not a known Linux admin host. An SSH login from a Windows workstation to a Linux server is anomalous and warrants immediate investigation.

**Search 2 — RDP session on HR-PC01 (identifies the pivot point):**
```spl
index=windows host=HR-PC01 source="XmlWinEventLog:Security" EventCode=4624 IpAddress=192.168.10.70
| table _time, EventCode, TargetUserName, IpAddress, LogonType
| sort -_time
```

Result: LogonType 10 (RemoteInteractive) for `hruser` from `192.168.10.70` at 11:17:22 — the RDP session that preceded the lateral movement.

**Why cross-host correlation matters:** neither search alone proves lateral movement. Search 1 shows an SSH login from an internal IP — suspicious but not conclusive on its own. Search 2 shows an RDP session on a Windows workstation — also suspicious but not conclusive alone. Together they prove the chain: attacker → RDP into HR-PC01 → SSH from HR-PC01 into web01.

## 5. Investigation Timeline

**Note on timestamps:** web01 auth log timestamps are in UTC+00:00; HR-PC01 Splunk events are displayed in local time (IST, UTC+5:30). The RDP session at 11:17 IST corresponds to approximately 05:47 UTC — consistent with the SSH login on web01 at 05:49 UTC approximately two minutes later.

| Time (UTC) | Event | Source |
|---|---|---|
| ~05:47 | RDP session established on HR-PC01 as `hruser` from `192.168.10.70` (LogonType 10, EventCode 4624) | HR-PC01 Security log |
| 05:49:47 | SSH login accepted on web01 for `ashag` from `192.168.10.100` (HR-PC01) | web01 /var/log/auth.log |

## 6. Indicators of Compromise (IOCs)

- **Pivot host:** `192.168.10.100` (HR-PC01) — Windows workstation used as SSH source
- **Target host:** `192.168.10.20` (web01)
- **Target account:** `ashag`
- **Original attacker IP:** `192.168.10.70` (attack01) — only visible in HR-PC01's logs, not web01's
- **Key indicator:** SSH login to a Linux server originating from a Windows workstation IP

## 7. Response & Remediation

**Lab response:**
- Terminate the SSH session on web01
- Terminate the RDP session on HR-PC01
- Reset both `hruser` (HR-PC01) and `ashag` (web01) credentials

**Production considerations:**
- Restrict SSH access on `web01` to known management hosts only — a Windows workstation should never be an authorized SSH source for a Linux server
- Implement host-based firewall rules on web01 allowing SSH only from specific IPs (e.g., a dedicated jump/bastion host)
- The attacker's original IP (`192.168.10.70`) is invisible in web01's logs — this highlights the importance of correlating logs across hosts rather than investigating each host in isolation
- Contain HR-PC01 immediately upon detecting anomalous outbound SSH: the workstation is the pivot point, and its traffic to other internal hosts should be reviewed for further lateral movement

## 8. Lessons Learned / Detection Gaps

- **Cross-host correlation is essential for lateral movement detection.** Investigating web01's auth log alone shows an SSH login from an internal IP — suspicious, but could be mistaken for a legitimate admin action. Only by correlating it with HR-PC01's RDP logon events does the attacker's chain become clear. This is exactly the kind of investigation a SOC L1 analyst would escalate to L2 for timeline reconstruction.
- **Internal IP ≠ trusted source.** The SSH login came from `192.168.10.100` — an internal address — which might initially appear lower priority than an external IP. In lateral movement scenarios, internal source IPs are often more significant, not less, because they indicate a host inside the perimeter has already been compromised.
- **The original attacker's IP is not visible on the final target.** `web01` has no record of `192.168.10.70` (attack01) — only `192.168.10.100` (HR-PC01). Without the HR-PC01 logs, attribution back to the original attacker would be impossible. This underscores the value of centralised log collection in Splunk: if HR-PC01 were not forwarding to the SIEM, this connection would be untraceable.

## Evidence

- [splunk-web01-ssh-accepted.png](../evidence/04-lateral-movement-ssh/splunk-web01-ssh-accepted.png) — SSH accepted password from 192.168.10.100 on web01
- [splunk-hrpc01-rdp-logon.png](../evidence/04-lateral-movement-ssh/splunk-hrpc01-rdp-logon.png) — RDP LogonType 10 on HR-PC01 from 192.168.10.70 preceding the lateral movement
