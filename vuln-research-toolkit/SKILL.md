---
name: vuln-research-toolkit
description: Cheatsheets, recon scripts, report template and write-ups for vulnerability research. Use when you need a payload reference, a recon one-liner, or a report skeleton.
metadata:
  hermes:
    tags: [security, cheatsheets, recon, reporting]
    category: security
---

# Vulnerability Research Toolkit

Reference material converted from `skraft9/vulnerability-research` (public repo). Cheatsheets
for the common bug classes, three recon/impact scripts, a report template, and three write-ups
as worked examples.

## When to Use

Use when a technique needs a payload reference rather than a methodology — SQLi union/blind/OOB
syntax, XSS context vectors, SSRF cloud-metadata endpoints, RCE separator logic, auth-bypass
checklists, dangerous-function patterns for source review. Also for the report skeleton and the
recon script starting points.

For methodology and testing order, load the hack-skills routers (`hack`, `api-sec`,
`auth-sec`, `recon-for-sec`) or `bug-bounty-recon` instead — this skill is the reference shelf.

## How to Run

Read the file you need directly:

```
~/.hermes/skills/security/vuln-research-toolkit/references/cheatsheets/<topic>.md
~/.hermes/skills/security/vuln-research-toolkit/references/templates/vulnerability_report_template.md
~/.hermes/skills/security/vuln-research-toolkit/references/write-ups/<name>.md
~/.hermes/skills/security/vuln-research-toolkit/scripts/<script>
```

## Quick Reference

### Cheatsheets (`references/cheatsheets/`)

| File | Covers |
|---|---|
| `sqli.md` | Detection, union-based extraction, blind timing, out-of-band exfiltration |
| `xss.md` | Context-specific vectors, modern WAF evasion, polyglots, client-side template injection |
| `ssrf.md` | Cloud metadata endpoints (AWS/GCP/Azure), protocol wrappers, filter bypasses |
| `rce.md` | Separator logic, space/character evasion (Linux/Windows), blind RCE |
| `authentication_bypass.md` | Auth bypass techniques + mitigations for JWT, OAuth, SAML |
| `dangerous_functions.md` | White-box source-review patterns for C, PHP, Python, Java |
| `reverse_engineering.md` | GDB + Ghidra cheatsheet |
| `linux_commands.md` | CLI reference for post-exploitation |

### Scripts (`scripts/`)

| Script | Purpose | Requirements |
|---|---|---|
| `recon.sh` | Subdomain enumeration + live-host detection | `subfinder`, `httpx-toolkit` |
| `ffuf_recon.sh` | Content/directory fuzzing | `ffuf` |
| `victim_monitor.py` | Service availability + latency measurement during DoS testing | Python 3 |

### Templates & write-ups

| File | Purpose |
|---|---|
| `references/templates/vulnerability_report_template.md` | Report skeleton — title, severity, summary, steps, impact, remediation |
| `references/write-ups/ZVE-2026-3795.md` | Worked example |
| `references/write-ups/CVE-2026-9136.md` | Worked example |
| `references/write-ups/api_key_leak.md` | Worked example |
| `references/methodology/mindset_and_tips.md` | Research mindset and practical advice |

## Procedure

1. **Identify the bug class** from the finding or the target's behaviour.
2. **Read the matching cheatsheet** for payload syntax and bypass variants.
3. **Adapt, do not copy.** Cheatsheet payloads are starting points; the target's parser,
   WAF and context decide what actually fires.
4. **For source review**, start at `dangerous_functions.md` — it names the sink functions
   per language, which is faster than grepping for vuln patterns blindly.
5. **Write the report** from the template, using a write-up as the shape reference.

## Pitfalls

- **Payload lists are not findings.** A payload that returns 200 is not a vulnerability until
  impact is demonstrated end-to-end.
- **`victim_monitor.py` is DoS-adjacent.** Only run it against a target whose program
  explicitly permits availability testing; most exclude DoS outright.
- **The recon scripts assume the tools are installed.** Check `~/bounty-hunter/bin` first;
  `subfinder`, `httpx`, `nuclei`, `katana` live there on this box.
- **Cheatsheets age.** Cloud metadata IPs and WAF bypasses drift; verify against the live
  target rather than trusting the sheet.
- **This repo is a reference shelf, not a program list.** Target selection lives in
  `bug-bounty-recon`.

## Verification

A cheatsheet is usable when its payload section is non-empty and its examples name the target
context (MySQL vs PostgreSQL, reflected vs stored). A write-up is usable when it states the
impact, not just the trigger.
