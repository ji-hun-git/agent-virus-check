# Severity rubric

Rate impact and exploitability separately, then combine. When unsure between two levels, pick the lower one and say why.

| Severity | Typical impact | Exploitability |
|---|---|---|
| Critical | Remote code execution; full account or tenant takeover; mass data exposure; secrets that grant production access | Unauthenticated or any logged-in user; no user interaction; reliable |
| High | Access to other users' data (IDOR on sensitive objects); privilege escalation; stored XSS in privileged views; SSRF to cloud metadata | Authenticated, or one plausible user action |
| Medium | Limited data exposure; reflected XSS; CSRF on meaningful actions; DoS of one component; secrets with narrow scope | Needs specific conditions, user interaction or insider position |
| Low | Information leaks with little value (versions, stack traces); missing hardening with no demonstrated path | Hard to exploit, or only with prior compromise |

Adjustments:

- Raise one level when the bug is reachable by an AI agent processing untrusted text and leads to a tool action with real effects (prompt injection to code execution or data sending).
- Lower one level when a strong, verified compensating control blocks the realistic path (for example a strict CSP that blocks the injected script).
- Known-vulnerable dependency versions: rate by whether the vulnerable function is reachable from this code. Unreachable is a low "update when convenient" note, whatever the advisory's own score.

Map to CWE in every finding. If the user wants CVSS, compute a v4.0 base vector from the same facts rather than guessing a number.
