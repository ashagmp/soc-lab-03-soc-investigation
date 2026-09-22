# Investigation 0X: <Attack Technique Name>

| Field | Value |
|---|---|
| Date | |
| Attacker Host | Kali Linux |
| Target Host | |
| MITRE ATT&CK Technique | T#### — Technique Name |
| Severity (assessed) | Low / Medium / High |
| Status | Detected / Investigated / Closed |

## 1. Scenario

What attack was simulated and why (what real-world behavior it represents).

## 2. Attack Execution

Commands/tools used from Kali, in order. Include exact syntax.

```bash
# example
hydra -l admin -P rockyou.txt ssh://<target-ip>
```

## 3. Detection

The SPL query used to surface the activity, and why it works.

```spl
index=linux sourcetype=... "Failed password"
| stats count by src_ip, user
| where count > 5
```

**Initial indicator found:** *(what first pointed to this activity)*

## 4. Investigation Timeline

| Time (UTC) | Event | Source |
|---|---|---|
| | | |

## 5. Indicators of Compromise (IOCs)

- Source IP:
- Target account(s):
- Process/command line (if applicable):

## 6. Root Cause / Scope

What made this possible, and what was/would have been affected.

## 7. Response & Remediation

What containment and remediation steps apply (e.g., block IP, force password reset, patch).

## 8. Lessons Learned / Detection Gaps

What this exposed about current detection coverage, and what rule/alert should exist going forward.

## Evidence

Screenshots referenced: `screenshots/0X-<technique-name>/`
