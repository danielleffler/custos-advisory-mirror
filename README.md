# custos-advisory-mirror

The custos-owned purl-side advisory mirror (custos-server ROADMAP
phase 20; DECISIONS 2026-08-04, open question 2). The same discipline as
[espressif/esp-nvd-mirror](https://github.com/espressif/esp-nvd-mirror)
on the CPE side: a scheduled sync commits upstream advisory bytes, and
custos-server's `publish advisories-refresh` extracts a scoped,
deterministic, digest-pinned snapshot from a checkout **at a recorded
commit** — a live API call never happens at evaluation time, and an
auditor re-derives any pin's bytes from (this repo @ commit, the scope
file, the converter version) years later.

## Layout

    repos.txt                  the mirror's breadth (canonical lowercase URLs)
    osv/<ID>.json              OSV GIT-ecosystem export records whose affected
                               ranges name a repo in repos.txt (CVE-converted
                               records with ENUMERATED affected versions)
    ghsa/<owner>__<name>/      GitHub repository-advisory API responses,
      <GHSA-ID>.json           verbatim — the ONLY upstream that carries
                               CVE-less repository advisories
    tags/<owner>__<name>.json  the repo's git tags at sync time — the
                               expansion that lets a version RANGE become an
                               enumerated version SET deterministically (the
                               purl-side analogue of esp-nvd-mirror's
                               cpematch/ expansions)
    syncdate.json              the sync instant + the OSV export's
                               Last-Modified header

## Why two upstream legs

arduino-esp32's GHSAs are repository advisories on a non-registry
project: they are NOT in github/advisory-database, and the CVE-less ones
are NOT in osv.dev either — only the repo-advisories API has all of
them. Conversely esp-idf has no repository advisories: its CVEs surface
in OSV's GIT export with enumerated affected-version lists. Coverage
requires the union (probed 2026-08-04; evidence in custos-server
DECISIONS.md).

## Sync

This repo is **data only** (since 2026-08-10). The sync code lives in
the custos monorepo (`advisory-sync/sync.py`,
https://github.com/danielleffler/custos), scheduled there by
`advisory-mirror-sync.yml`, which pushes here with a write deploy key —
so the workflow that produced a commit is the workflow that pushed it.
Commits land only when bytes moved. Manual run, from a custos checkout:

    python3 advisory-sync/sync.py <path-to-this-checkout>
