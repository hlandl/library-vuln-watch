# library-vuln-watch

Daily automated monitoring of upstream security activity for libraries we run in
**out-of-support, pinned versions** (currently Apache Camel 4.8.8), so that fixes
can be backported in-house.

A scheduled Claude Code cloud routine runs every morning, follows the methodology
in [AGENT.md](AGENT.md), and:

1. sweeps GitHub Security Advisories, NVD, the project's security page, Apache
   Jira, and the upstream GitHub repo for **new** security-relevant items,
2. assesses whether each finding affects our pinned version and the components we
   actually use ([config/libraries.yaml](config/libraries.yaml)),
3. locates the **official upstream fix (PR/commit)** and assesses its
   backportability,
4. commits a daily report to [reports/](reports/) and updates the dedup state in
   [state/seen.json](state/seen.json),
5. delivers the result by email / Teams (targets are configured in the routine,
   not in this repo).

## Layout

| Path | Purpose |
|---|---|
| `AGENT.md` | The agent's methodology — edit this to tune behaviour |
| `config/libraries.yaml` | Which libraries/versions/components to watch |
| `state/seen.json` | Findings already reported (dedup across runs) |
| `reports/YYYY-MM-DD.md` | One report per day, committed by the agent |

## Adding a library

Add an entry to `config/libraries.yaml` (a commented Spring Framework template is
included). No other change is required.
