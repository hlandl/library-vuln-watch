# Library Vulnerability Watch — Agent Methodology

This document is the authoritative instruction set for the scheduled monitoring agent.
The daily routine prompt intentionally stays thin and points here, so the methodology can
be tuned by editing this file — without touching the routine itself.

## Purpose

We run libraries pinned to versions that are out of upstream support (currently
Apache Camel 4.8.8; more libraries will be added). Upstream no longer ships patch
releases for these versions, so security fixes must be identified and backported
in-house. This agent watches the official upstream sources daily and reports:

1. **New (potential) vulnerabilities** that affect our pinned version.
2. For each relevant finding, the **official upstream fix** (PR / commit) as the
   basis for our own backport.

## Inputs

- `config/libraries.yaml` — the monitored libraries: pinned version, Maven
  coordinates, sources to sweep, and (optionally) the list of components actually
  in use. **An empty `used_components` list means: no component filter — treat
  every component as potentially used.**
- `state/seen.json` — fingerprints of findings already reported on previous runs,
  plus the timestamp of the last successful run.
- Delivery targets (email recipients, Teams webhook) are provided **in the run
  prompt**, never stored in this repository (it is public).

## Procedure (per library, per run)

### 1. Determine the lookback window

- Read `state/seen.json`.
- If `last_run` is `null` → **backfill mode**: sweep without a date filter for
  advisories/CVEs (find *everything* whose affected range still includes our
  pinned version), and use a 180-day lookback for Jira/commit sources.
- Otherwise → **incremental mode**: sweep everything created/modified since
  `last_run` **minus 48 hours** (overlap prevents boundary losses; the dedup
  state absorbs the duplicates).

### 2. Collect candidate findings from all configured sources

Use plain HTTPS (curl / WebFetch) — all sources are public, no credentials needed.
If one source is unreachable, continue with the others and record the outage in the
report's "Source health" section. Typical endpoints:

- **GitHub Security Advisories (GHSA)**:
  `https://api.github.com/advisories?ecosystem=maven&per_page=100` (+ `modified`
  filter in incremental mode), then filter results to the library's
  `maven_group`. Also check `https://api.github.com/repos/<github_repo>/security-advisories`.
- **NVD**:
  `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<nvd_keyword>`
  (+ `lastModStartDate`/`lastModEndDate` in incremental mode).
- **Project security page** (e.g. `https://camel.apache.org/security/`): parse the
  advisory table; this is the authoritative list of officially acknowledged CVEs.
- **Apache Jira** (public REST API, no auth):
  `https://issues.apache.org/jira/rest/api/2/search?jql=<urlencoded JQL>&fields=key,summary,resolutiondate,fixVersions,labels,description`
  using the `jira.jql` from the config with the lookback window substituted.
- **GitHub repository sweep** (`github_repo`, e.g. `apache/camel`):
  - New releases + release notes: `https://api.github.com/repos/<repo>/releases?per_page=20`
  - Merged PRs / commits mentioning security: search API, e.g.
    `https://api.github.com/search/issues?q=repo:<repo>+type:pr+is:merged+CVE`
    and variants with `security`, `vulnerability`, `CWE`.
  - This source exists to catch **silent fixes**: hardening commits that look
    security-relevant but have no CVE (yet). Flag these as `SUSPECTED`.

### 3. Merge and dedupe

- A single issue often appears in several sources. Merge by identifier
  (CVE id ↔ GHSA id ↔ Jira key ↔ PR/commit) into one finding.
- Compute the finding's **fingerprint**: the most authoritative id available, in
  order of preference `CVE-… > GHSA-… > <JIRA-KEY> > <repo>@<commit-sha>`.
- Drop every finding whose fingerprint is already in `state/seen.json` →
  only **new** findings continue to the next step.

### 4. Assess each new finding

Answer, with reasoning and links as evidence:

| Question | Result |
|---|---|
| Is this a vulnerability? | `CONFIRMED` (CVE/GHSA exists) / `SUSPECTED` (security-looking fix, no CVE) / `NOT-SECURITY` (drop) |
| Does the affected version range include our pinned version? | `AFFECTED` / `NOT-AFFECTED` (drop, but record in seen-state) / `UNCLEAR` |
| Is an affected artifact in `used_components`? (skip if list empty) | `USED` / `NOT-USED` / `UNCLEAR` |
| Severity | CVSS score+vector if published, otherwise a reasoned LOW/MEDIUM/HIGH/CRITICAL estimate marked *(estimated)* |

Verdict for the summary: **AFFECTS US** (affected + used/unclear), **NOT RELEVANT**
(not affected, or component provably not used), **NEEDS REVIEW** (anything unclear).

### 5. Locate the official fix (for AFFECTS US and high-severity NEEDS REVIEW)

- Find the upstream fix: PR and/or commit(s) in the project repository. Start from
  the advisory's references, the Jira issue's linked PRs/commits, and the release
  notes of the version that first ships the fix; fall back to commit search.
- Report: fix PR/commit links, the first fixed release, the list of changed files,
  and a short **backport assessment** for our pinned version — does the patch
  apply cleanly to the old code, or has the code drifted (renamed modules,
  refactorings)? Which tests should be ported alongside?
- Do **not** attempt the backport itself; the report is the hand-over to a human.

### 6. Write the report

Create `reports/YYYY-MM-DD.md` (UTC date, one file per day; if it exists, append a
`## Run 2` section):

```markdown
# Vulnerability Watch — YYYY-MM-DD

## Summary
| Library | Finding | Severity | Verdict | Official fix |
|---|---|---|---|---|
(one row per new finding — or the single line "✅ No new findings" if none)

## Findings
### <CVE-…/GHSA-…/JIRA-KEY> — <title>   (one section per finding)
- Verdict / severity / affected range vs. our version / component analysis
- All source links (advisory, Jira, PR, commits)
- Official fix + backport assessment (step 5)

## Source health
(per source: OK / FAILED <reason> — a failed source means findings may be missed today)
```

**Always write a report**, even when there are no findings — an explicit
"all clear" distinguishes *nothing found* from *the agent did not run*.

### 7. Persist state

- Add every processed fingerprint (including NOT RELEVANT ones) to
  `state/seen.json` with date and verdict; set `last_run` to now (UTC, ISO-8601).
- Commit report + state with message `watch: report YYYY-MM-DD (<n> new findings)`
  and push.
- **If the push fails** (missing write access), do not abort: delivery (step 8) is
  the primary channel — include the full report inline and prominently note that
  state could not be persisted (the next run will re-report the same findings).

### 8. Deliver

As instructed in the run prompt (targets live there, not here). General rules:

- **Email**: subject `[VULN-WATCH] ⚠ <n> finding(s) affect <libraries>` or
  `[VULN-WATCH] all clear — YYYY-MM-DD`; body = the report (rendered), plus a link
  to the committed report file.
- **Teams webhook** (if a URL is provided): POST a compact summary card — verdict
  counts per library, the summary table, link to the full report. Skip silently
  if no webhook is configured.
- Never include secrets (webhook URLs etc.) in the report or commits.

## Adding a library

Add one entry to `config/libraries.yaml` (see the Camel entry as template). No
other change needed — this methodology is library-agnostic.
