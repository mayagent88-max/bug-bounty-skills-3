# Grafana source-audit state (v13.4.0-pre, /tmp/grafana)

Audit log for the Grafana OSS repo. Record cleared areas here so a later session
starts on unaudited surface instead of re-walking the same authorizers.

## Why

Grafana pays cash AND accepts reports (only such program left after Nextcloud's
bounty suspension). Two prior passes plus this one have cleared most of the
app-platform and legacy API surface; the remaining bugs are in narrow spots.

## Findings so far (10)

| ID | Area | Bug |
|----|------|-----|
| #362 | annotations | MassDeleteAnnotations nil-deref |
| #363 | library panels | PATCH folderId bypasses destination-folder create-permission |
| #364 | correlations | datasources:read evaluated without resource scope |
| #365 | datasource proxy | API-group / datasource-type confusion |
| #372 | cloud migration | CancelSnapshot: no org scoping + process-global cancelFunc |
| #373 | preferences (legacy) | team delete assigns caller's USER id as team id |
| #374 | logsdrilldown | list/get authorized for ALL users, no ownership check |

## Cleared — do NOT re-audit

- ngalert authz internals; datasource proxy + /api/ds/query; dashboards, folders,
  permissions, teams, library panels (except folderId, found); apikey,
  serviceaccounts, oauth, login, oauthtoken, org-invites; pluginsintegration,
  live, notebooks; dashboard import/export/versions; legacy alerting (removed);
  query/search SQL backends (moved to plugin repos; search is bleve); authn/authz
  framework; dashboard snapshots; playlists; userstorage app; quotas; annotations
  store SQLi (sql_concat false positives at xorm_store.go:292/307).
- **Pass 3 additions (2026-11):**
  - collections app (stars): `AuthorizeFromName` + storage double-parse; unknown
    owner names pass the authorizer but storage rejects them (same pattern in
    preferences legacy store — both safe).
  - preferences app-platform app: merged route is GET-only; ListPreferences scopes
    to caller identifier + member teams + namespace.
  - iam app authorizers: authinfo (service/admin only), users (self + RBAC),
    teams (subresource checks), ssosettings (redacting store), resourcepermission
    (watch blocked), whoami, display (org-scoped name/avatar only).
  - provisioning app: repository/connection/job/historicjob/settings/stats authz
    map; files connector layered checks (dir listing = repositories:read, raw
    file = folder read, resource read = DualReadWriter authorizer).
  - secret app decrypt chain: LocalDecryptClient injects service identity =
    object API group; decryptAuthorizer requires token perm
    `secret.grafana.app/securevalues:decrypt` AND the value's decrypters list to
    contain that group. App-plugin settings GET returns name-only refs, never
    decrypted values (decryption only feeds the plugin backend context).
  - query app: authorizer only checks valid user, but pluginClient.QueryData
    enforces `datasources:query` scoped per UID.
  - org routes (`/orgs/:orgId` CRUD): `AuthorizeInOrgMiddleware` resolves the
    caller's identity IN the target org (falls back to global org when not a
    member) before evaluating — not an IDOR.
  - user routes, org_users, admin_users: RBAC scoped; role-escalation guard on
    add-org-user ("cannot assign a role higher than user's role").
  - annotation app (annotation.grafana.app): app authorizer allows all, but every
    CRUD + custom route (tags/graphite/search) calls canAccessAnnotation(s);
    Update checks both existing and new body to block scope-change escalation.
  - advisor app: standard ResourceAuthorizer + fixed roles (admin-only checks,
    all-roles translations).
  - dashvalidator app: authorizer requires datasources:read+query+dashboards:create;
    handler re-checks per-datasource UID scope before fetching.
  - historian app (alerting): app authorizer allows all, but RemoteLokiBackend.Query
    filters by folder UIDs the caller can read rules in (CanReadAllRules bypass
    for admins, GetUserVisibleNamespaces + HasAccessInFolder otherwise).
  - nav tree + applinks: every section gated by hasAccess; nav tree is not a
    security boundary (app routes enforce).
  - render (reqSignedIn, path appended after fixed host), ds diagnostics
    (reqGrafanaAdmin + feature flag), plugin_checks (middleware), signup,
    password reset, frontend logging, avatar proxy.

## Next candidates (unaudited)

- service app (aggregator-mode only, RoleAuthorizer).
- Enterprise-only surfaces not in OSS repo (RBAC status page, licensing,
  audit logs, reporting).
- Deeper resourcepermission storage-layer authz (authorizer delegates to it).
- Anything added after this snapshot — re-clone and diff first.

## Method notes

- App-platform apps live in `pkg/registry/apis/<app>` (+ `pkg/registry/apps/<app>`
  for installer-registered ones); legacy HTTP in `pkg/api/`.
- The recurring bug shape in this codebase: app-level authorizer allows broadly
  ("storage layer handles it") and the storage layer forgot to filter. Grep each
  new app's GetAuthorizer, then verify the claim in the storage/handler.
- `AuthorizeFromName` (preferences/utils) treats an unparseable resource name as
  UnknownResourceOwner -> Allow; safe only because every consumer's storage
  re-parses and rejects. Check both sides before clearing an app that uses it.

