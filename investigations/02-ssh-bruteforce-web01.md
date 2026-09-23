# Investigation 02: SSH Brute Force Against web01

| Field | Value |
|---|---|
| Date | 2026-09-22 |
| Attacker Host | attack01 (Kali Linux, 192.168.10.70) |
| Target Host | web01 (192.168.10.20) |
| MITRE ATT&CK Technique | T1110.001 — Brute Force: Password Guessing |
| Severity (assessed) | Medium (credential access attempt against a live service account) |
| Status | Investigated / Closed |

## 1. Scenario

Second investigation in the low-to-high complexity progression, moving from passive recon (Investigation 01) to active credential access. An SSH brute force was run from attack01 against web01, targeting the real user account `ashag`, using the rockyou.txt wordlist.

## 2. Attack Execution

**Recon before the attack — enumerating valid targets:**
```bash
cat /etc/passwd | grep -E "/bin/bash|/bin/sh"
```
Returned three login-capable accounts: `root`, `ashag`, `splunkfwd`.

**Checked whether root was even a viable target:**
```bash
grep -i "PermitRootLogin" /etc/ssh/sshd_config
```
Result: `#PermitRootLogin prohibit-password` — commented out, meaning the compiled default applies (`prohibit-password`), which disables password-based root login entirely. Root was ruled out as a target for this reason. `splunkfwd` was also excluded — it's lab infrastructure's own monitoring service account, not a realistic brute-force target.

**Attack command (final working version):**
```bash
hydra -l ashag -P /usr/share/wordlists/rockyou.txt -t 1 -W 5 ssh://192.168.10.20
```

## 3. Troubleshooting Note (part of the investigation, not a detour)

Initial attempts at default concurrency (`-t 16`, then `-t 4`) failed entirely with `[ERROR] all children were disabled due too many connection errors`. Ruled out, in order:
- **UFW** — inactive, not the cause
- **fail2ban** — not installed on web01, not the cause
- **`MaxStartups`** — commented out (default `10:30:100`), unlikely to trigger at `-t 4`
- **Memory** — `free -h` showed 995Mi available, not memory-starved

**Root cause identified:** web01 is a single-vCPU VM. SSH's per-connection key exchange is CPU-bound; concurrent connection attempts couldn't complete their handshakes within Hydra's timeout window, so Hydra reported them as connection errors rather than authentication failures. Dropping to `-t 1 -W 5` (single-threaded, 5-second wait between attempts) resolved it — the attack then ran cleanly at ~19 tries/min with no errors.

**This itself is a valid finding:** web01's resource allocation causes it to behave like it's under a rate limit during concurrent connection load, independent of any actual security control being present. Worth flagging as an infrastructure constraint, not a detection.

## 4. Detection

Once the attack was running cleanly, confirmed the sourcetype and searched Splunk:

```spl
index=linux host=web01 source="/var/log/auth.log" "Failed password"
| stats count by src_ip, user
```

This surfaced the failed login attempts from `192.168.10.70` against user `ashag`. Kept deliberately simple over a more complex rex-based aggregation — every part of this query is explainable in one sentence: search the Linux auth log on web01 for the literal string OpenSSH writes on every failed login, then count occurrences grouped by source IP and targeted username.

**How this becomes a real alert:** add a threshold —
```spl
index=linux host=web01 sourcetype=linux_secure "Failed password"
| stats count by src_ip, user
| where count > 10
```
A handful of failed logins is normal (typos); a sustained burst from one source IP against one account is the brute-force signal.

## 5. Investigation Timeline

| Time (UTC) | Event | Source |
|---|---|---|
| 21:36–21:37 | Initial Hydra attempts (`-t 16`, `-t 4`) fail with connection errors | attack01 |
| 21:37–21:47 | Troubleshooting: UFW, fail2ban, MaxStartups, memory ruled out | web01 |
| 21:47 | Attack retried at `-t 1 -W 5`, runs cleanly | attack01 |
| 21:47 onward | Failed login attempts logged to `/var/log/auth.log`, forwarded to Splunk | web01 → splunk01 |

## 6. Indicators of Compromise (IOCs)

- Source IP: `192.168.10.70` (attack01)
- Target account: `ashag`
- Target host: `192.168.10.20` (web01)
- Tool signature: Hydra SSH module, rockyou.txt wordlist

## 7. Response & Remediation

- Block or rate-limit `192.168.10.70` at the host firewall following sustained failed-login volume against a single account
- Consider deploying fail2ban on web01 — its absence meant the attack ran unimpeded once the concurrency issue was resolved, unlike a hardened host that would have auto-banned the source IP after a handful of failures
- `PermitRootLogin prohibit-password` is already a correctly-configured control — confirmed root was never a viable brute-force target, worth noting as a positive finding rather than a gap

## 8. Lessons Learned / Detection Gaps

- **No automated response exists on web01.** Unlike DC01 (Investigation 01, where the finding was a *visibility* gap), this host has a *response* gap — failed logins are logged but nothing acts on them. Deploying fail2ban would close this.
- **Infrastructure resource limits can masquerade as security controls.** The initial connection errors looked like they could be a rate limiter or ban — they were actually just a single-vCPU VM struggling with concurrent SSH handshakes. Ruling out real controls (UFW, fail2ban, MaxStartups) systematically before concluding "resource issue" avoided a wrong diagnosis in the writeup.
- **Detection queries should prioritize clarity, reliability, and explainability over unnecessary complexity.** The simple `stats count by src_ip, user` query was sufficient to identify repeated failed authentication attempts and provided the required fields for investigation.

## Evidence

- [hydra-attack-output.txt](../evidence/02-ssh-bruteforce-web01/hydra-attack-output.txt) — successful attack run output (`-t 1 -W 5`); the earlier failed high-concurrency attempts are documented as narrative in Section 3
- [troubleshooting-checks.jpg](../evidence/02-ssh-bruteforce-web01/troubleshooting-checks.jpg) — single terminal session showing all four checks in sequence: UFW (inactive), fail2ban (not installed), `MaxStartups` (commented/default), and `free -h` (995Mi available) — ruling out each as the cause
- [splunk-failed-logins.png](../evidence/02-ssh-bruteforce-web01/splunk-failed-logins.png) — Splunk search results showing the detection query output
