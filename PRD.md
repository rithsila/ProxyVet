# PRD — ProxyVet

> Proxy IP quality checker. Vets candidate proxy IPs across network-classification,
> anonymizer, and reputation signals to decide whether an IP is safe to front a
> Facebook business identity.

| Field | Value |
|---|---|
| Project | ProxyVet *(working title — see Open Decisions D1)* |
| Document | PRD.md (root-level, descriptive — the "why and what") |
| Version | 0.1 (draft) |
| Status | Draft — pending sign-off on Open Decisions |
| Owner | Sila |
| Last updated | 2026-06-25 |
| Related docs | `DESIGN.md`, `ImplementPlan.md`, `.claude/rules/{workflow,stack,security}.md` |

This PRD intentionally stays at the level of *what* and *why*. Architecture, scoring
weights, data schemas, and tech-stack pinning live in `DESIGN.md`; sequencing lives in
`ImplementPlan.md`. Prescriptive, auto-loaded constraints live in `.claude/rules/`. Do
not collapse those into this file.

---

## 1. Summary

ProxyVet is a single-operator command-line tool that takes one or many proxy IPs and
returns a clear, reasoned verdict — `CLEAN`, `CAUTION`, or `BURNED` — by aggregating
signals from local offline databases and a small set of free reputation APIs. It
replaces a slow, manual, multi-tab workflow (IPHub, IPQS, vpnapi, Scamalytics, etc.)
with one command, caches results, and stores history so IP reputation *drift* can be
tracked over time.

The tool exists to reduce one specific, controllable risk factor in managing legitimate
Facebook business presence: the likelihood that a proxy IP is classified as a
server/VPN/proxy or carries spam/abuse history, which raises the odds of account
restrictions, blocks, reduced reach, or poor audience recommendations.

## 2. Problem statement

Today the proxy-vetting workflow is fully manual: paste an IP into five or six websites,
read each result, and form a gut judgment. This is slow, inconsistent, easy to skip
under time pressure, and impossible to do for a whole pool. Critically, it is also a
*point-in-time* check — an IP that looks clean today can be blacklisted next week because
another tenant on the same subnet was flagged (the "contamination" problem). There is no
record of what was checked, no composite score, and no way to be alerted when a
previously-good IP degrades.

## 3. Goals & success criteria

The tool is successful if it delivers the following, measurably:

- **G1 — One-command verdict.** A single command returns a full, multi-source verdict for
  an IP, with the contributing reasons, in seconds rather than minutes.
- **G2 — Batch vetting.** A pool of N IPs can be checked from a file and returned as a
  ranked `CLEAN / CAUTION / BURNED` report.
- **G3 — Quota discipline.** Offline checks run first as a cheap gate so that scarce paid
  quota (e.g. IPQS at 1,000 lookups/month) is consumed only when offline signals are
  ambiguous or a tiebreak is needed. Target: the large majority of routine checks
  complete without spending any metered API quota.
- **G4 — Drift visibility.** Every check is persisted with a timestamp; re-running an IP
  shows whether its standing has changed since last time.
- **G5 — Self-hosted & secret-safe.** Runs entirely on Sila's own infrastructure
  (Proxmox LXC / VM), commits zero secrets, and passes `/security-check`.

Non-success looks like: a tool that just automates the manual lookups but burns the IPQS
monthly budget on the first batch, leaks API keys, or gives a single opaque number with
no reasoning.

## 4. User & context

Single user (Sila), technical, security-conscious, running on self-hosted infrastructure.
No multi-user accounts, no auth, no SaaS surface in v1. Input is Sila's own proxy pool —
sensitive business infrastructure that should stay local and not be broadcast more widely
than each chosen reputation source inherently requires (see NFR-Privacy).

## 5. The signal model (what we measure and why)

ProxyVet evaluates three independent signal families. They are weighted very differently
because, for the Facebook use case, they do not matter equally. Exact weights and the
normalized schema are specified in `DESIGN.md`; this section fixes the *product* intent.

1. **Network classification — what the IP *is* (dominant signal).** ASN / usage type:
   mobile carrier, residential ISP, business, or datacenter/hosting. Detection systems
   classify the network from the ASN *before* evaluating behavior; datacenter/hosting
   ASNs are flagged for extra scrutiny, residential is the trust baseline, and mobile
   (CGNAT) carries the highest baseline trust. For our purpose, datacenter/hosting
   classification is effectively near-disqualifying regardless of how clean the rest is.

2. **Anonymizer status — proxy / VPN / Tor / relay.** Near-hard-fail signals. A clean
   residential IP that is also a known proxy or VPN exit is still unsafe.

3. **Reputation / abuse history — what it has *done*.** Spam, fraud, brute-force reports,
   and DNS blocklist presence. Used both as a hard gate (when bad enough) and as the
   primary *drift* signal across re-checks.

The verdict logic is **gate-then-score**: any hard-fail gate forces `BURNED`; otherwise a
weighted soft score across the remaining signals produces a 0–100 risk that is banded
into `CLEAN / CAUTION / BURNED`. A single blended average is explicitly rejected, because
some signals (Tor exit, multi-source proxy/VPN, high abuse confidence) must be
disqualifying on their own.

## 6. Scope

### 6.1 In scope — v1 (MVP)

The MVP is on-demand vetting with persistent history. It is a complete, useful unit
without any automation layer on top.

- CLI: check a single IP, and batch-check IPs from a file.
- Offline-first checker pipeline (local signals run before metered APIs).
- Result normalizer mapping every source to a common schema.
- Local cache (SQLite) with **per-source TTL** (short for reputation, longer for
  classification).
- Gate-then-score engine producing a `CLEAN / CAUTION / BURNED` verdict plus a
  human-readable reason list.
- History persistence (per-IP, timestamped) enabling drift comparison.
- Output in both a readable table and machine-readable JSON.
- Config file + environment-based secrets for API keys and per-source enable/disable.

### 6.2 Out of scope / non-goals

- **Not** a guarantee against Facebook restrictions. ProxyVet reduces *one* risk factor.
  Meta combines IP signals with device fingerprint and behavior, none of which this tool
  touches. A `CLEAN` verdict is necessary, not sufficient.
- **Not** an anti-detect browser, account-warming, automation, or account-creation tool.
- **Not** a proxy *acquisition* or rotation service; it judges IPs, it does not buy or
  rotate them. (It may, however, recommend *against* over-rotation — see §9 constraints.)
- **Not** a multi-user product, hosted service, or anything with auth in v1.
- **No** scraping of the manual websites' HTML. Use documented APIs / databases only.

### 6.3 Future (post-MVP, not committed)

- **v1.1 (top priority):** scheduled re-check (cron) over the active pool, with
  Telegram alerting when a previously-`CLEAN` IP degrades. This is the highest-leverage
  follow-up and slots into existing cron + Telegram infrastructure.
- **v2:** optional FastAPI endpoint + small local dashboard; residential-proxy detection
  via a paid tier (the one capability genuinely worth paying for); geo-consistency
  checks against a per-IP "expected location."

## 7. Data sources (v1)

Sources are tiered by cost and by whether they disclose the queried IP to a third party.
Offline/local sources run first; metered APIs run only on the ambiguous remainder.

### 7.1 Local / offline (no per-query limit; minimal or no third-party disclosure)

| Source | Provides | Notes |
|---|---|---|
| MaxMind GeoLite2 ASN (`.mmdb`) | ASN + org → datacenter vs ISP inference | Free; org name is often decisive |
| IP2Proxy LITE (`.bin`) | proxy / VPN / Tor / datacenter flags, offline | Free; official Python lib |
| Datacenter/VPN ASN + range lists | offline DC/VPN/Tor classification | e.g. curated GitHub lists; refreshed on a schedule |
| Tor bulk exit list | authoritative Tor exit detection | Free, refreshes frequently |
| Reverse DNS (PTR) | hosting-pattern hostnames vs ISP/none | Pure DNS; strong DC tell |
| DNSBLs (Spamhaus ZEN, others) | spam/abuse blocklist presence | Free DNS queries; high-value, low-cost |

### 7.2 Free hosted APIs (disclose the IP to the vendor)

| Source | Free tier | Role |
|---|---|---|
| proxycheck.io | 1,000 / **day** | Primary daily driver: risk score, operator attribution, DC vs residential |
| AbuseIPDB | 1,000 / **day** (3,000 if domain-verified) | Abuse-history layer: confidence score, report categories, recency |
| vpnapi.io | 1,000 / **day** | Optional second proxy/VPN/Tor opinion |
| StopForumSpam | free | Spam-registration reputation |

### 7.3 Optional tiebreaker (disabled by default)

| Source | Free tier | Role |
|---|---|---|
| IPQualityScore | 1,000 / **month** | Deepest single fraud score; spent only on ambiguous IPs or as tiebreak |

A solid free v1 stack is **proxycheck.io + AbuseIPDB + DNSBL + the local offline set**,
with vpnapi.io/StopForumSpam as optional corroboration and IPQS reserved as a metered
tiebreaker. Every source must be individually toggleable in config.

## 8. Functional requirements

- **FR-1 — Single check.** Given one IP, run all enabled, applicable checkers and return a
  verdict with per-signal detail.
- **FR-2 — Batch check.** Given a file of IPs, check each (respecting per-source rate
  limits and the cache) and return a consolidated, sortable report.
- **FR-3 — Offline-first ordering.** Local/offline checkers run before metered APIs.
  Metered APIs are skipped when the offline result is already decisive, unless the user
  forces a full check.
- **FR-4 — Normalization.** Each checker emits a common record (e.g. `is_datacenter`,
  `is_proxy`, `is_vpn`, `is_tor`, `asn`, `asn_type`, `country`, `abuse_score`,
  `fraud_score`, `dnsbl_hits`, `source`, `raw`). Schema is defined in `DESIGN.md`.
- **FR-5 — Caching with per-source TTL.** Results are cached in SQLite. Reputation data
  has a short TTL (hours); classification/ASN data may cache for days. A `--no-cache` /
  force-refresh path exists.
- **FR-6 — Gate-then-score verdict.** Apply hard-fail gates; if none fire, compute the
  weighted soft score and band into `CLEAN / CAUTION / BURNED`. Always return the list of
  reasons that drove the verdict.
- **FR-7 — History.** Persist every check (IP, timestamp, verdict, score, key signals).
  Provide a way to view an IP's history and whether its standing changed.
- **FR-8 — Output formats.** Human-readable table for terminal use and JSON for scripting
  / downstream automation.
- **FR-9 — Config & secrets.** API keys, enabled sources, TTLs, and verdict thresholds
  are configurable. Keys come from environment / a secrets file that is never committed.
- **FR-10 — Graceful degradation.** If a source errors, times out, or hits its rate
  limit (e.g. HTTP 429 with `Retry-After`), the tool records that the source was
  unavailable, continues with the rest, and never blocks the whole run on one source.

### 8.1 Verdict & scoring requirements

- **VR-1 — Hard-fail gates (any one ⇒ `BURNED`).** Tor exit node; `is_proxy` or `is_vpn`
  true on ≥2 independent sources; AbuseIPDB confidence ≥ threshold, *or* DNSBL/Spamhaus
  listing, *or* IPQS fraud_score ≥ threshold (when IPQS enabled); confirmed open
  public-proxy port (if port probing is enabled for the user's own endpoints).
- **VR-2 — Soft score inputs.** ASN/usage type (mobile ≫ residential > business ≫
  datacenter), recent-abuse/velocity scaled by recency, per-list DNSBL hits, source
  disagreement, and (v2) geo mismatch. Exact weights and thresholds live in `DESIGN.md`
  and must be tunable via config without code changes.
- **VR-3 — Bands.** `CLEAN` (safe to use), `CAUTION` (usable but monitor / not for a
  high-value identity), `BURNED` (do not use). Band boundaries are configurable.

## 9. Non-functional requirements

- **NFR-Performance.** A cached single check returns in a few seconds; a cold single
  check completes within a small number of seconds even when several APIs are queried.
  Batch runs scale linearly and stay within each source's rate limits.
- **NFR-Reliability.** One failing/slow/rate-limited source never aborts the run
  (see FR-10). Rate limits are respected proactively (token-bucket per source), not just
  reacted to.
- **NFR-Security (security-first).** No secret is committed to the repo or written to
  logs. API keys load from environment / an untracked secrets file. The tool follows the
  project's `.claude/rules/security.md`. Dependencies are minimal; any security-critical
  small dependency is vendored and exact versions are pinned per the project's stack
  rules.
- **NFR-Privacy.** Querying any hosted API necessarily discloses the proxy IP to that
  vendor. The offline-first design minimizes this by resolving as much as possible
  locally first. The proxy list and all results stay on local infrastructure; nothing is
  sent anywhere except the specific reputation source being queried.
- **NFR-Portability.** Runs on a self-hosted Linux LXC/VM with no external service
  dependencies beyond the chosen data sources. Local databases (GeoLite2, IP2Proxy LITE,
  ASN/Tor lists) are refreshable on a schedule.
- **NFR-Cost.** v1 is operable entirely on free tiers. Paid capability (IPQS tiebreaker,
  later residential-proxy detection) is strictly opt-in and off by default.

## 10. Assumptions & constraints

- **A1 — IP is one factor, not the whole picture.** The tool cannot predict Facebook's
  behavior; Meta does not publish its criteria and combines IP with device and behavioral
  signals. Treat verdicts as risk reduction, not a guarantee.
- **A2 — Residential-proxy blind spot.** Static lists and most free APIs miss residential
  proxies (a clean-looking ISP IP that is actually in a proxy pool). A `CLEAN` verdict
  from the free stack does not prove an IP is not a residential proxy. Detecting these
  reliably requires a paid tier (deferred to v2).
- **A3 — Reputation drifts.** Standing is not static; this is the core justification for
  history (v1) and scheduled re-checking (v1.1).
- **A4 — Stability matters for FB.** Beyond cleanliness, suddenly moving an identity to a
  different network triggers trust checks. The tool should encourage keeping one good IP
  per identity rather than aggressive rotation. (Advisory only; not enforced in v1.)
- **A5 — Vendor data disagrees.** Sources legitimately disagree; the scorer treats
  disagreement as its own (mild) signal rather than trusting any single source.

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Burning the IPQS monthly quota on a big batch | Offline-first gate; IPQS off by default, used only as a tiebreak |
| False sense of safety from `CLEAN` | Non-goals + A1/A2 stated plainly; reasons always shown; verdict bands not binary |
| Stale local databases degrade accuracy | Scheduled refresh of GeoLite2 / IP2Proxy LITE / ASN + Tor lists |
| API key leakage | Env/untracked secrets, no key logging, `/security-check` gate |
| Rate-limit lockout mid-batch | Token-bucket per source + honor `Retry-After`; degrade gracefully |
| Proxy list exposure to vendors | Offline-first minimizes disclosure; document which sources see the IP |

## 12. Open decisions (need sign-off before/with implementation)

- **D1 — Name.** Working title is "ProxyVet." Confirm or replace (avoid collision with
  the existing "SafetyScore" EA tooling).
- **D2 — v1 source set.** Confirm the proposed v1 = offline set + proxycheck.io +
  AbuseIPDB + DNSBL (vpnapi.io / StopForumSpam optional, IPQS off by default). Alternative
  considered: ship a *local-only* engine first and layer all hosted APIs in v1.1.
- **D3 — Hard-gate thresholds.** Confirm starting thresholds for AbuseIPDB confidence and
  IPQS fraud_score, and the "≥2 sources" rule for proxy/VPN hard-fail (exact numbers to
  be fixed in `DESIGN.md`).
- **D4 — Port probing.** Include open-proxy-port probing of Sila's own endpoints in v1, or
  defer? (Useful signal, but adds an active-network component.)
- **D5 — Language/stack.** Assumed Python for v1 (fits existing tooling and the official
  IP2Proxy/MaxMind libraries). Confirm before `stack.md` is written.

## 13. Acceptance criteria (definition of done — v1)

v1 is done when:

1. `check <ip>` returns a banded verdict with a reason list, using offline signals plus
   the enabled free APIs, in seconds.
2. A batch file of IPs produces a sortable `CLEAN / CAUTION / BURNED` report without
   exceeding any source's rate limit and without consuming IPQS quota unless explicitly
   enabled.
3. Results are cached with per-source TTL, and re-running an IP shows its history and any
   change in standing.
4. Output is available as both a terminal table and JSON.
5. No secrets are present in the repo; the project passes `/security-check`.
6. A failing or rate-limited source degrades gracefully and never aborts the run.

## 14. Appendix

- **Glossary.** ASN = Autonomous System Number (network owner); usage type =
  residential/business/datacenter/mobile classification; DNSBL = DNS-based blocklist;
  CGNAT = Carrier-Grade NAT (mobile); drift = change in an IP's standing over time;
  hard-fail gate = a single disqualifying signal; soft score = weighted aggregate.
- **Related documents.** `DESIGN.md` (architecture, normalized schema, exact weights,
  stack pinning), `ImplementPlan.md` (sequencing), `.claude/rules/workflow.md`,
  `.claude/rules/stack.md`, `.claude/rules/security.md`.
