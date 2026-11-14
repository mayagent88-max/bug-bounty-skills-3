# Bugcrowd Program Selection

Bugcrowd's engagement list is a React app — `curl` on `/engagements` returns an empty
shell (`data-react-class` / `data-api-endpoints` attributes only, no program data).
Use the public JSON endpoints instead; they need no session cookie.

## List all programs
```
curl -s -A "Mozilla/5.0 ... Chrome/120.0 Safari/537.36" \
  "https://bugcrowd.com/engagement_listings.json?category=bug_bounty&page=1&sort_by=promoted&sort_direction=desc"
```
- 24 per page; paginate `page=1..N` until `paginationMeta.totalCount` is covered
  (~296 bug-bounty programs, 13 pages at the time of writing).
- `sort_by` accepts `promoted|rewards|scope|starts|ends`.
- Per program: `name`, `briefUrl` (program code = last path segment),
  `rewardSummary.minReward/maxReward`, `scopeRank`, `industryName`, `isPrivate`,
  `productEngagementType.label`.
- Sleep ~1s between pages; public endpoint, do not hammer it.

## Per-program stats (the competition signal)
```
curl -s -A "$UA" "https://bugcrowd.com/engagements/<code>/statistics"
```
Returns `rewardedVulnerabilities`, `averagePayout`, `validationWithin`
(e.g. `"9 days"`, `"about 1 month"`, or null).

Other public endpoints on the same program code:
- `/hall_of_fames.json` — top researchers + points (who already camps it)
- `/recently_joined_users.json` — new subscribers (rising interest)
- `/scope_ranks` — scope rank number
- `/engagement_known_issues.json` — REQUIRES LOGIN, skip it

Do NOT parse the brief page HTML for scope/targets: its `data-react-props`
carries only a csrfToken. Read the brief in a browser or logged in.

## Ranking formula
Bugcrowd exposes no "reports this month" like YesWeHack, so approximate
competition from `rewardedVulnerabilities` (all-time paid reports):

```
score = 2 * min(avg_payout, 3000)/100          # money per report
      + 1.5 * max(0, 30 - min(rewarded, 30))   # low competition
      + 0.8 * max(0, 30 - min(valid_days, 30)) # fast triage
      + min(max_reward, 10000)/2000            # ceiling
```
Parse `averagePayout` as float (strip `$` and commas) and `validationWithin`
into days (`"about 1 month"` -> 30). Filter to real product programs before
ranking: drop the ~100 Atlassian-marketplace app vendors (scopeRank 1, $100-$1.5k
ceilings, pure noise) and VDPs with no reward.

Good target shape: rewarded <= 60, validation <= 20 days, avg payout >= $400.

## bcstats (github h1pmnh/bcstats)
Downloads the same per-program stats but requires the `_crowdcontrol_session`
cookie and is unmaintained. The public `/statistics` endpoint gives the same
fields without handling a session token — prefer it. Never write a session
token to disk or into a script.

## Output
Save raw + ranked tables under `~/bounty-hunter/bugcrowd/`:
`bc_all_programs.json` (raw list) and `bc_programs_ranked.csv` (scored).
