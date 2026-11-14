# API Endpoint Discovery

Frontend JavaScript is the endpoint oracle. Mine it before guessing paths — a guessed
wordlist misses app-specific routes and wastes the rate-limit budget.

## Next.js / React (Turbopack chunks)

The page HTML lists every chunk under `/_next/static/chunks/`. Download them all and
grep for API paths:

```python
import os, re, concurrent.futures, urllib.request
chunks = sorted(set(re.findall(r'src="(/_next/static/chunks/[^"]+\.js)"', html)))
def fetch(c):
    n = os.path.basename(c)
    data = urllib.request.urlopen(urllib.request.Request(BASE + c, headers=UA), timeout=20).read()
    open(n, 'wb').write(data); return n
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
    list(ex.map(fetch, chunks))

api = set()
for f in os.listdir('.'):
    s = open(f, encoding='utf-8', errors='ignore').read()
    api |= set(re.findall(r'["\'](/api/[a-zA-Z0-9/_{}.$\[\]-]{2,70})["\']', s))
```

Fetch chunks with plain `urllib` — static assets are not WAF-gated and routing them
through a SOCKS proxy is needlessly slow.

### The proxy-host trap
A path found in a chunk is not necessarily served by the API subdomain. Next.js apps
commonly proxy their own `/api/next/*` routes through the **www host**, while
`api.example.com` 404s on the same path. Before concluding an endpoint does not exist,
retry it against the www host:

```
curl -s -o /dev/null -w '%{http_code}' https://api.example.com/api/next/features   # 404
curl -s -o /dev/null -w '%{http_code}' https://www.example.com/api/next/features  # 200
```

### The i18n locale prefix is mandatory
A Next.js app with locale middleware routes its API under the locale segment —
`/en/api/...`, not `/api/...`. Without the prefix every endpoint answers
`{"message":"Not found"}`, which reads exactly like a dead route and sends you hunting
for a different API host that does not exist. Recover the prefix from the page's own
redirect chain (`/` -> `/en/restricted`), from the `dl=<locale>` cookie the app sets,
or from the matcher regex in `/_next/static/<buildId>/_clientMiddlewareManifest.js`,
then re-probe the whole endpoint list with it. Read the `x-middleware-rewrite`
response header on every API response — it names the route the middleware actually
dispatched to and is free routing information.

### Method oracle: 405 on both GET and POST
`405` carrying `"Method GET Not Allowed"` on GET and `"Method POST Not Allowed"` on POST
means the route exists and wants a third method — try `PUT` and `PATCH` before
concluding anything. A `400` with an application error body means the route exists, the
method is right, and it is auth-gated; that is the auth boundary, not a dead path. The
`buildId` in the page HTML (`"buildId":"..."`) unlocks
`/_next/static/<buildId>/_buildManifest.js`, which lists every route the build shipped.

### Payload schemas live in the chunks
Zod / validation schemas are shipped to the browser. Grep for `.object({` near the
endpoint string to recover the exact required fields, their types, and constraints
(e.g. `password: string().min(6).max(99)`, `termsAndConditions: literal(true)`). This
tells you what a well-formed request looks like before you send one.

### Feature flags are often public
`/api/next/features`-style endpoints return the full flag map unauthenticated. Useful
for spotting half-built features (`nextweb-cancel-subscription: false`) that may be
reachable by a direct call even though the UI hides them.

## ASP.NET / Kestrel

Probe the conventional paths, then read the error body — Spring-style and Kestrel 404
bodies differ and reveal the framework:

```
/swagger /swagger/index.html /swagger/v1/swagger.json /openapi.json /api-docs
/v3/api-docs /health /healthcheck /status /metrics /.env /web.config /robots.txt
```

A 429 on `/.env` while other paths 404 means a rate limiter fired, not that the file
exists. Wait out the window and retry before recording anything.

Read `x-rate-limit-*` response headers when present — they state the budget directly.

## PHP ajax.php pattern

Many small French/EU apps use a single `ajax.php` dispatcher with an `action` or `cat`
parameter. Recover the action list from the page's own JS, then probe each one both
with and without a session:

```
/ajax.php?action=search&token=<fresh>
/ajax.php?cat=count
```

CSRF tokens are usually rendered into the HTML as a hidden input and are frequently
single-use. Always GET the page first, extract the token, and reuse the cookie jar —
a stale token returns a 500 that looks like a vulnerability but is not.

## OAuth / Keycloak

`/.well-known/openid-configuration` on the auth host reveals the realm, grant types,
and scopes. Test, in order:

1. Dynamic Client Registration (`registration_endpoint`) — usually bearer-protected.
2. `redirect_uri` manipulation with a valid `client_id` — strict validation is the norm;
   a 400 means it is enforced.
3. Whether `authorization_endpoint` serves a real login page for a known client id.

Recover valid client ids from the SPA's JS bundle or its config endpoint
(`config.js`, `env.js`) rather than guessing.

## Flutter web apps

Flutter web bundles ship one enormous `main.dart.js` (5-15MB) containing every API
path as a plain string. Grep it directly:

```
curl -s -m 120 "$HOST/main.dart.js" -o main.dart.js
grep -oE '"/[a-zA-Z0-9/_-]{4,}"' main.dart.js | sort -u
```

Two traps make this stack unlike every other:

1. **The API host is not in the bundle.** It is resolved at runtime from
   `platforms/<tenant>/platform_config.json` (`server_url_override`, `city_id`,
   `tenant`) or built by string concatenation (`"https://router-"+tenant+".live..."`).
   Guessing the host from the JS wastes the rate-limit budget.
2. **Flutter renders to canvas.** There are no DOM inputs, the accessibility tree is
   nearly empty, and screenshots can come back blank. Do not try to drive the UI with
   selectors, coordinates, or clicks.

The reliable way to find the API host is to let the app make its own calls and read
them back from the Resource Timing API:

```python
new_tab(url); wait_for_load(); time.sleep(12)
js("performance.getEntriesByType('resource').map(r => r.name)")
```

The app calls its configuration and settings endpoints on startup, which exposes the
real API host plus several live paths in one shot. Filter the returned list for
non-static hosts.

### Replaying a captured request from inside the page

Once the shape is known, replay it from the page itself rather than from curl — that
attaches the page's cookies, its bot-manager cookies, and any runtime-injected header
without you having to reconstruct them.

`browser_exec`'s `js()` returns before an async callback fires, and the page context does
not survive between calls, so a result stashed on `window` by an async `fetch` reads back
empty in the next call. Use a **synchronous** XHR and return the values from the same
expression:

```python
res = js("""(() => {
  var xhr = new XMLHttpRequest();
  xhr.open('POST', '/LogOn/Authenticate', false);   // false = synchronous
  xhr.setRequestHeader('Content-Type', 'application/json;charset=UTF-8');
  xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
  xhr.setRequestHeader(tv.config.xsrfTokenKey, tv.config.xsrfToken);
  xhr.send(JSON.stringify({UserName:'probe@example.com', Password:'x'}));
  return JSON.stringify({status: xhr.status, body: xhr.responseText.slice(0, 600)});
})()""")
```

This also lets you run a batch of probes (nonexistent identity, malformed identity,
known-domain address) in one call and compare the bodies side by side — which is exactly
what the enumeration negative case requires.

## Angular (lazy chunks + DI-injected config)

Angular SPAs split the app into numbered lazy chunks (`9130.1df4acd03e7f4ad4.js`) that
are only listed in the network log, not in the initial HTML. The endpoint strings are
spread across `main.*.js` (2-10MB) plus those chunks, and they are frequently built by
concatenation, so a plain grep for `/api/...` finds nothing.

**The API base URL is injected, not bundled.** Angular resolves it through a DI token
(`OD_API_CONFIG`, `API_CONFIG`, `environment`) at bootstrap, so it never appears in any
JS file. Do not spend time grepping for the host — capture it from the live page:

```python
new_tab(url); wait_for_load(); time.sleep(10)
# hook BEFORE triggering the action, then submit the login form with a dummy credential
js("""(() => {
  window.__cap = [];
  const oo = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(m,u,...r) {
    try { window.__cap.push({m, u:String(u)}); } catch(e){}
    return oo.call(this,m,u,...r);
  };
  const osh = XMLHttpRequest.prototype.setRequestHeader;
  XMLHttpRequest.prototype.setRequestHeader = function(h,v) {
    try { (window.__cap[window.__cap.length-1].h = window.__cap[window.__cap.length-1].h||{})[h]=v; } catch(e){}
    return osh.call(this,h,v);
  };
  return 'ok';
})()""")
```

Submitting the login form with a wrong password is the cheapest trigger: the auth call
fires immediately and reveals the base URL, the method, and every app-specific header
(`X-API-Version`, `X-OneDoc-App`). The 401 response is the expected outcome and is not
a finding.

Then grep the downloaded chunks for the *paths* only, and read the header names from the
interceptor code (`X-API-Version` is usually added by an `HttpInterceptor` that matches
`v(\d+)/` in the URL — that regex tells you the version prefix convention).

### A published OpenAPI spec beats all of it
Check for a downloadable spec before any of the above. Angular admin/API consoles
commonly ship one at a predictable path, linked from the console page's sidebar:

```
/static/openapi.yaml  /static/postman.json  /openapi.json  /api-docs
```

A spec gives the complete path list, the security scheme (apiKey header name, IP
allowlist), the documented rate limit, the body size cap, and the full error-code table
in one request. Audit the spec locally; only probe the live API for what the spec leaves
ambiguous. Note that `servers[].url` may use a variable host (`https://{host}`) whose
default differs from the host you are testing — resolve it against the console's own
host.

### Angular config endpoints
Look for `/assets/release.json` (version + `minimumRequiredVersion`), `/assets/manifest.json`,
and per-locale i18n JSON. The release file is a reliable fingerprint of the deployed
build and tells you whether you are looking at a stale chunk set.

## Runtime-injected config: `/config.js` and app globals

Two config patterns defeat a pure JS-mining approach, and both are cheap to defeat.

### Plain-var config files
Some SPAs fetch their config as executable JavaScript at startup — `/config.js`,
`/tag-config.js`, `/iubenda-config.js`, `/localize-config.js`, `/cloudflare.js`. The body
is `var NAME = "value";` assignments, not JSON, so `json.loads` fails; grep it directly.

What it reliably exposes:
- API base URL, signup / logout / password-reset endpoints, and the environment name.
- **`ALLOWED_OAUTH_REDIRECTS`** — the OAuth allowlist as a literal string. This is the
  list your `redirect_uri` bypass attempts must beat, so read it before testing.
- **Fallback development / staging hosts** (`https://development-api.example.dev`), used
  when the production global is undefined. These are frequently live and less hardened
  than production — probe every host the config names, including the fallbacks, and
  compare their security headers against production rather than assuming either way.
- Public third-party keys (Turnstile site key, Sentry DSN, LaunchDarkly client id,
  analytics ids). These are public by design; do not report them.

### Config globals that exist in no JS file
Other SPAs inject their config as a runtime global (`tv.config`) assembled at bootstrap.
The header *names* and token *values* an authenticated request needs live only there.
Read them from the live page before replaying anything:

```python
js("typeof tv !== 'undefined' ? JSON.stringify({key: tv.config.xsrfTokenKey, token: tv.config.xsrfToken}) : 'undefined'")
```

The XSRF pattern to expect: `setRequestHeader(config.xsrfTokenKey, config.xsrfToken)` on
send, and on every response
`config.xsrfToken = xhr.getResponseHeader(config.xsrfTokenKey)` — the token **rotates per
response**, so a value captured minutes ago may already be stale. Grab a fresh one in the
same `js()` call that replays the request.

## Gateway fingerprints

Read the `server` and `x-amzn-*` headers before interpreting any error body — the
fingerprint tells you which enumeration vocabulary applies and whether a 404 came from
the gateway (no route) or the application (route exists, resource does not).

| Signature | Gateway |
|---|---|
| `server: kong/<ver>` + `{"request_path":"...","message":"API not found with these values","request_host":[...]}` | Kong |
| `x-amzn-errortype: ForbiddenException` / `MissingAuthenticationTokenException`, `x-amz-apigw-id`, `x-amzn-requestid`, `x-cache: Error from cloudfront` | AWS API Gateway + CloudFront |
| `server: istio-envoy` + `upstream connect error or disconnect/reset before headers` or `RBAC: access denied` | Istio / Envoy |
| `x-dw-request-base-id` | Salesforce Commerce Cloud (see above) |

A gateway 404 (`API not found with these values`) means no route matches — it says
nothing about whether the upstream resource exists, so do not record the path as dead.
Kong's error body echoes `request_path` and `request_host` back, which confirms the route
table is keyed on both and is worth varying independently.

## Let the validator enumerate the schema

When an endpoint is schema-validated, the server will describe its own contract if you
ask wrongly. Send a payload with an unknown field plus an empty object — that combination
triggers the maximum number of distinct validation messages in one response:

```
{"events":[{"type":"x","data":{}}]}
```

One such request against a payment-analytics endpoint returned, in a single body: the
full required-field list (`event_name is required`, `event_properties is required`,
`source_id is required`, `source_type is required`, `timestamp is required`,
`version is required`), the rejection of unknown fields (`Additional properties data,
type are not allowed`), the type expectations (`Invalid type. Expected: integer, given:
string`), and the complete enum of legal values (`must be one of the following:
"checkout.loaded", "checkout.completed", ...`).

That is the entire request contract — required fields, types, and legal enum members —
for the cost of one request, and it works on any JSON-schema-validated API. Mine the
bundle only for what the validator refuses to tell you.

## Salesforce Commerce Cloud (Demandware)

Recognisable from `/on/demandware.store/Sites-<site>-Site/<locale>/<Controller>-<Action>`
URLs and from `x-dw-request-base-id` / `x-error` response headers. Controllers follow a
fixed naming convention, so the whole surface is enumerable by name:

```
/on/demandware.store/Sites-<site>-Site/en_GB/Account-Subscription
/on/demandware.store/Sites-<site>-Site/en_GB/Newsletter-Subscribe
/on/demandware.store/Sites-<site>-Site/en_GB/Cart-Show
/on/demandware.store/Sites-<site>-Site/en_GB/Order-Track
/on/demandware.store/Sites-<site>-Site/en_GB/Search-Show?q=<term>
```

Expect many controllers to 500 without a session — that is a generic error page, not a
stack trace, and by itself is not reportable (most programs exclude it). The useful tests
are input escaping on `Search-Show` (reflect `"`, `<`, `>` and confirm they come back
entity-encoded) and the login/reset flows for enumeration and throttling.

## Ember.js

Ember ships its whole runtime config in a URL-encoded meta tag in `index.html`:

```
<meta name="client/config/environment" content="%7B%22modulePrefix%22...">
```

`urllib.parse.unquote` the content and `json.loads` it. `APP.version` is the deployed
build string, which is often exactly the value a custom API version header
(`Cryptobox-Version`) must carry. Read the header names the API expects from its CORS
preflight `Access-Control-Allow-Headers`, then supply them from the decoded config.

## Nuxt.js

Nuxt inlines its runtime config as `window.__NUXT__={config:{...}}` in the page HTML —
`API_URI`, `FRONT_URI`, CDN/OSS bucket URLs, `appType`, feature flags. Grep the raw HTML
for `window.__NUXT__` before downloading any chunk; it gives the real API host in one
request.

Nuxt SPAs are also a **catch-all**: every unknown path returns 200 with the same
`index.html`. A 200 on a guessed API path therefore proves nothing — compare the body
against the root page (or require that it parses as JSON) before recording the endpoint
as live.

## Webpack Module Federation (micro-frontends)

A host app loads `remote-entry-<Name>App.js` per micro-app; those files are small chunk
loaders, not the code. Download every `remote-entry-*` the host references to map the
micro-app list, then drive the host in a browser so the lazy chunks actually load — the
endpoint strings live in those chunks, which only appear in the network log.

## Recovering the exact request shape (SPA auth flows)

Endpoint paths recovered from JS are only half the request. The other half — method,
body encoding, header set, cookie jar — decides whether the gateway routes the call at
all. An endpoint that answers from the browser but 404s from curl is a shape mismatch,
not a dead path.

### The misleading 404
API gateways commonly answer a request they cannot route with
`{"message":"Your request is blocked, no service match for your request"}`. This reads
exactly like a nonexistent endpoint. Do not record the path as dead on that response —
it means the gateway did not recognise the request, which is a shape problem.

### Capture the real request from the live page
Hook `fetch` and the `Request` constructor BEFORE triggering the action, then read the
resulting `Request` object — it is the only place the final method and headers are
visible:

```python
new_tab(url); wait_for_load(); time.sleep(8)
js("""(() => {
  window.__rp = [];
  const OReq = window.Request;
  window.Request = function(input, init) {
    try {
      const req = new OReq(input, init);
      const hdrs = {};
      req.headers.forEach((v,k)=>hdrs[k]=v);
      window.__rp.push({url: req.url, m: req.method, hdrs, cred: req.credentials, mode: req.mode});
    } catch(e){}
    return new OReq(input, init);
  };
  window.Request.prototype = OReq.prototype;
})()""")
# ... trigger the action (fill input, click button) ...
time.sleep(8)
rp = js("window.__rp")
```

A plain `fetch` wrapper is NOT enough: when the app passes a `Request` object, the
init headers and body are not visible on the wrapper's arguments, and the recorded
method defaults to `GET`. Wrapping the `Request` constructor captures the final,
normalised request every time.

### Shape-mismatch table
Each row below produced a 404 or 400 from curl while the browser succeeded:

| What was guessed | What the app actually sent |
|---|---|
| `GET` with query params | `POST` with a form-encoded **body** |
| `Content-Type: application/json` | `application/x-www-form-urlencoded` |
| body field `email` | body field `identity_value` (+ `identity_type`) |
| `client_id` = `web` | `client_id` = `web-standard` (read from sessionStorage) |
| `identity_type` = `EMAIL` | `identity_type` = `email` (lowercase) |
| no auth headers | `credentials: include` + bot-manager cookies |

Read `client_id`, tenant codes, and other runtime values from `sessionStorage` /
`localStorage` — the SPA stores them there and the JS bundle only holds the *names* of
the slots, not the values.

### Config endpoints are the endpoint map
SPAs on a config-driven framework fetch their endpoint map at startup. Look for
`/config.amg`, `/config-dynamic.amg`, `/config.json`, or `/assets/config.json` — these
return the full route table (endpoint base URLs, resource path fragments, OAuth paths,
feature-flag host and decryption key) in one request. A SPA catch-all returns
`index.html` for unknown paths, so a 200 on a config path is not proof the JSON exists;
check that the body parses as JSON.

### Per-brand / per-tenant values
Multi-brand platforms (one codebase, many storefronts) parameterise the tenant. The
tenant code is in each brand's own `config.amg` (`tenant: bk`, `tenant: pb`, ...).
Sending the wrong tenant returns `tenantId 'X' not supported by this service` — a clear
signal to go read that host's config rather than guess.

## Per-tenant host enumeration

When the API host is `router-<tenant>.<domain>`, the tenant list is usually public in
`platforms/platform_map.json` (URL slug to tenant code, often hundreds of entries).
DNS-resolve the candidate hosts in a small thread pool, then test only the ones that
resolve — most tenants have no web client and therefore no router host at all. A
misconfiguration found on one router host is almost always in the shared gateway, so
test two or three more before writing it up as systemic.
