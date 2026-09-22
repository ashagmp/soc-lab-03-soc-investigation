# Investigation 01: Nmap Service/OS Enumeration Scan Against DC01

| Field | Value |
|---|---|
| Date | 2026-09-22 |
| Attacker Host | attack01 (Kali Linux, 192.168.10.70) |
| Target Host | DC01 (192.168.10.10) |
| MITRE ATT&CK Technique | T1046 — Network Service Discovery |
| Severity (assessed) | Low (recon only, no exploitation) |
| Status | Investigated / Closed |

## 1. Scenario

First investigation in the low-to-high complexity progression: a service/OS detection scan run from attack01 against DC01, simulating early-stage attacker reconnaissance against a domain controller. The goal was to establish what a baseline recon action looks like in Splunk before running anything more aggressive.

## 2. Attack Execution

```bash
nmap -sV -O 192.168.10.10
```

Full output:

```
Nmap scan report for 192.168.10.10
Host is up (0.00045s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-22 11:04:17Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ashag.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: ashag.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
MAC Address: 08:00:27:C1:E8:E2 (Oracle VirtualBox virtual NIC)

Aggressive OS guesses: Microsoft Windows Server 2022 (97%)
Service Info: Host: DC01; OS: Windows
```

**Analyst note:** the exposed port signature (53/88/389/445/3268/5985) is immediately recognizable as a domain controller. An attacker doesn't need exploitation to identify a high-value target here — enumeration alone reveals the role.

## 3. Detection

Initial hypothesis: Sysmon EventCode 3 (Network Connect) would capture inbound connections from the scan.

```spl
index=windows host=DC01 source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| table _time, DestinationPort, SourceIp, SourcePort
```

**Result: zero events.**

Verified this wasn't a pipeline issue first:
```spl
index=windows host=DC01 source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count by EventCode
```
This returned results for other event codes, but **no EventCode=3 at all** — confirming the gap was in NetworkConnect logging specifically, not a broken forwarder.

## 4. Root Cause

DC01 runs the **SwiftOnSecurity** Sysmon configuration. Its `NetworkConnect` rule is **include-first**: a connection is only logged if it matches one of two conditions —

1. The initiating process image is on a curated list of suspicious binaries (`nmap.exe`, `nc.exe`, `psexec.exe`, `powershell.exe`, `mshta.exe`, etc.), **or**
2. The destination port is on a fixed watchlist: `22, 23, 25, 143, 3389, 5800, 5900, 4444, 1080, 3128, 8080, 1723, 9001, 9030`

Neither condition applied. The scanned ports — **53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985** — are standard AD service ports (DNS, Kerberos, LDAP, SMB, WinRM), none of which are on the include list. The watchlist is built around lateral-movement/C2/remote-access indicators (RDP, VNC, Tor, common backdoor ports), not general domain service traffic. Because the connections landed on `lsass.exe`/`svchost.exe` handling DNS/LDAP/SMB — not a listed suspicious binary — the process-image condition didn't fire either.

Relevant config excerpt (`sysmon64 -c` output):
```
- NetworkConnect   onmatch: include   combine rules using 'Or'
    Image           filter: image   value: 'nmap.exe'
    Image           filter: image   value: 'psexec.exe'
    ...
    DestinationPort filter: is      value: '3389'
    DestinationPort filter: is      value: '5900'
    DestinationPort filter: is      value: '9030'
    ... (port 53/88/135/139/389/445/etc. absent from this list)
```

## 5. Investigation Timeline

| Time (UTC) | Event | Source |
|---|---|---|
| 11:04:17 | Nmap scan executed from attack01 against DC01 | attack01 terminal |
| — | Splunk search for EventCode=3, DC01 — 0 results | splunk01 |
| — | Splunk search confirming other Sysmon event codes present — pipeline healthy | splunk01 |
| — | `sysmon64 -c` reviewed on DC01, NetworkConnect include rule identified as root cause | DC01 |

## 6. Indicators of Compromise (IOCs)

- Source IP: `192.168.10.70` (attack01)
- Target: `192.168.10.10` (DC01)
- Ports probed: 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985
- Tool signature: Nmap `-sV -O` (service + OS detection probes)

## 7. Response & Remediation

In a real environment, this scan would warrant:
- Correlating the source IP against known-good asset inventory (is `.70` an authorized scanner or unexpected?)
- If unauthorized: block at host firewall / investigate the source host

**More significant finding — a detection gap, not just an incident:** this environment currently has **no visibility into reconnaissance/enumeration against core AD service ports** at the Sysmon layer. Recommended remediation for the lab environment itself:
- Enable Windows Filtering Platform (WFP) / Windows Firewall connection logging on DC01 as a supplementary data source
- Add network-layer visibility (Zeek or Suricata on a mirrored/promiscuous interface) to catch port-scan patterns independent of endpoint telemetry — this is the single detection source most likely to have caught this scan
- Consider a supplementary Sysmon config or a custom rule that logs NetworkConnect for inbound connections to core AD ports specifically, without opening up full unfiltered logging (which SwiftOnSecurity avoids intentionally due to log volume)

## 8. Lessons Learned / Detection Gaps

- **Sysmon config choice has real detection consequences that aren't obvious until tested.** SwiftOnSecurity's config is a legitimate, well-regarded baseline — but its NetworkConnect scope is intentionally narrow (built for catching C2/backdoor/lateral-movement indicators, not general recon). This is a tuning tradeoff, not a misconfiguration, and it's the kind of gap a SOC analyst should be able to identify and escalate.
- **Endpoint telemetry alone is insufficient for network-level reconnaissance detection.** This directly validates the need for network-layer monitoring (Zeek/Suricata) as a planned addition to this lab, separate from and complementary to host-based Sysmon telemetry.
- Before assuming "no detection = attack succeeded undetected," always first verify the pipeline is healthy (check for *any* events from the expected event code family) — ruling out a broken forwarder first avoided misdiagnosing this as a pipeline failure instead of a config-scope finding.

## Evidence

- [nmap-scan-dc01.txt](../evidence/01-nmap-recon-dc01/nmap-scan-dc01.txt) — full Nmap output
- [sysmon-networkconnect-config.txt](../evidence/01-nmap-recon-dc01/sysmon-networkconnect-config.txt) — NetworkConnect include/exclude rule blocks
- [splunk-empty-result.png](../evidence/01-nmap-recon-dc01/splunk-empty-result.png) — Splunk search showing 0 events for EventCode=3
