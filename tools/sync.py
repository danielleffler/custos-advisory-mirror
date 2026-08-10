#!/usr/bin/env python3
"""Sync the mirror from its two upstream legs (README: why two).

Stdlib only, plus `git` for tag listing. Refusal posture mirrors the
consumer's: an upstream response that cannot be read kills the sync
rather than committing a partial mirror that would read as complete.
File formats are byte-stable (sorted keys, fixed separators, trailing
newline) so an unchanged upstream produces a zero-diff sync.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OSV_EXPORT = "https://osv-vulnerabilities.storage.googleapis.com/GIT/all.zip"
API = "https://api.github.com"


def die(msg):
    print(f"sync: {msg}", file=sys.stderr)
    sys.exit(1)


def guard_shrink(what, existing, removing):
    """The deletion floor. A truncated OSV export or an empty-but-200
    GHSA response must not read as 'everything was withdrawn': deleting
    the mirror's records makes the downstream snapshot look evaluated-
    clean, which is the exact false-clean this mirror exists to prevent.
    Removing every record, or more than half, refuses unless the
    operator states the shrink is real (SYNC_ALLOW_SHRINK=1)."""
    if not existing or not removing:
        return
    if os.environ.get("SYNC_ALLOW_SHRINK") == "1":
        print(f"{what}: SYNC_ALLOW_SHRINK=1 -- allowing removal of "
              f"{len(removing)}/{len(existing)} records")
        return
    if len(removing) == len(existing) or len(removing) * 2 > len(existing):
        die(f"{what}: refusing to remove {len(removing)} of "
            f"{len(existing)} mirrored records in one run -- this looks "
            "like a truncated or empty upstream response, not a "
            "withdrawal wave. If the shrink is real, re-run with "
            "SYNC_ALLOW_SHRINK=1.")


def read_repos():
    repos = []
    for line in (ROOT / "repos.txt").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("https://github.com/") or line != line.lower():
            die(f"repos.txt entry {line!r} is not a canonical lowercase "
                "github.com URL")
        repos.append(line.rstrip("/"))
    if not repos:
        die("repos.txt names no repositories")
    return repos


def canon_repo(url):
    """Case-fold and strip the noise upstreams add: trailing .git, slash."""
    if not isinstance(url, str):
        return None
    return url.strip().rstrip("/").removesuffix(".git").lower() or None


def stable_bytes(doc):
    return (json.dumps(doc, sort_keys=True, indent=1, ensure_ascii=True)
            + "\n").encode("ascii")


def write_if_changed(path, data):
    if path.is_file() and path.read_bytes() == data:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return True


def http_get(url, *, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith(API):
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=300) as resp:
        return resp.read(), dict(resp.headers)


def sync_osv(repos):
    """Filter the GIT-ecosystem export down to records naming a mirrored
    repo in an affected GIT range. The export is the whole ecosystem; the
    mirror's breadth is repos.txt (the server-side scope narrows further
    at extraction)."""
    print(f"osv: downloading {OSV_EXPORT} ...")
    with tempfile.NamedTemporaryFile(suffix=".zip") as tmp:
        data, headers = http_get(OSV_EXPORT)
        tmp.write(data)
        tmp.flush()
        last_modified = headers.get("Last-Modified")
        wanted = set(repos)
        kept, changed = 0, 0
        seen_ids = set()
        with zipfile.ZipFile(tmp.name) as zf:
            for info in sorted(zf.namelist()):
                if not info.endswith(".json"):
                    continue
                try:
                    rec = json.loads(zf.read(info))
                except json.JSONDecodeError as exc:
                    die(f"osv export entry {info} does not parse: {exc}")
                hit = False
                for affected in rec.get("affected") or []:
                    if not isinstance(affected, dict):
                        continue
                    for rng in affected.get("ranges") or []:
                        if isinstance(rng, dict) and rng.get("type") == "GIT" \
                                and canon_repo(rng.get("repo")) in wanted:
                            hit = True
                if not hit:
                    continue
                rec_id = rec.get("id")
                if not isinstance(rec_id, str) or not re.fullmatch(
                        r"[A-Za-z0-9._-]+", rec_id):
                    die(f"osv export entry {info} has unusable id {rec_id!r}")
                kept += 1
                seen_ids.add(rec_id)
                if write_if_changed(ROOT / "osv" / f"{rec_id}.json",
                                    stable_bytes(rec)):
                    changed += 1
        # Records that left the export (withdrawn upstream) leave the
        # mirror too -- the git history is the archive. Behind the
        # deletion floor: mass removal refuses (guard_shrink).
        osv_dir = ROOT / "osv"
        existing = sorted(osv_dir.glob("*.json")) if osv_dir.is_dir() else []
        removing = [p for p in existing if p.stem not in seen_ids]
        guard_shrink("osv", existing, removing)
        for path in removing:
            path.unlink()
        print(f"osv: {kept} in-breadth records ({changed} changed, "
              f"{len(removing)} removed)")
        return last_modified, changed + len(removing)


def sync_ghsa(repos):
    """The repository-advisories API, verbatim, per mirrored repo."""
    total = 0
    moved = 0
    for repo in repos:
        owner_name = repo.removeprefix("https://github.com/")
        slug = owner_name.replace("/", "__")
        page, advisories = 1, []
        while True:
            url = (f"{API}/repos/{owner_name}/security-advisories"
                   f"?per_page=100&page={page}&state=published")
            data, _ = http_get(url, headers={
                "Accept": "application/vnd.github+json"})
            try:
                batch = json.loads(data)
            except json.JSONDecodeError as exc:
                die(f"ghsa {owner_name} page {page} does not parse: {exc}")
            if not isinstance(batch, list):
                die(f"ghsa {owner_name} page {page}: unexpected shape "
                    f"{type(batch).__name__}")
            advisories.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        seen = set()
        for adv in advisories:
            ghsa_id = adv.get("ghsa_id")
            if not isinstance(ghsa_id, str) or not ghsa_id.startswith("GHSA-"):
                die(f"ghsa {owner_name}: advisory with unusable ghsa_id")
            seen.add(ghsa_id)
            if write_if_changed(ROOT / "ghsa" / slug / f"{ghsa_id}.json",
                                stable_bytes(adv)):
                moved += 1
        # Same deletion floor as the OSV leg, per repo: a `200 []` from
        # the API (rate limiting, permission change, rename, deprecation)
        # must not silently unlist every advisory for that repo.
        ghsa_dir = ROOT / "ghsa" / slug
        existing = sorted(ghsa_dir.glob("*.json")) if ghsa_dir.is_dir() else []
        removing = [p for p in existing if p.stem not in seen]
        guard_shrink(f"ghsa {owner_name}", existing, removing)
        for path in removing:
            path.unlink()
        moved += len(removing)
        print(f"ghsa: {owner_name}: {len(advisories)} published advisories")
        total += len(advisories)
    return moved


def sync_tags(repos):
    """`git ls-remote --tags`, names only, peeled refs dropped. The tag
    list is what lets a GHSA version RANGE become an enumerated version
    SET deterministically at conversion time."""
    moved = 0
    for repo in repos:
        slug = repo.removeprefix("https://github.com/").replace("/", "__")
        proc = subprocess.run(
            ["git", "ls-remote", "--tags", repo],
            capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            die(f"tags: git ls-remote {repo} failed: {proc.stderr.strip()}")
        tags = set()
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) != 2 or not parts[1].startswith("refs/tags/"):
                continue
            name = parts[1].removeprefix("refs/tags/")
            if name.endswith("^{}"):
                name = name[:-3]
            if name:
                tags.add(name)
        if not tags:
            die(f"tags: {repo} lists no tags -- a repo with no tags cannot "
                "anchor range enumeration; investigate before mirroring")
        if write_if_changed(ROOT / "tags" / f"{slug}.json",
                            stable_bytes({"repo": repo, "tags": sorted(tags)})):
            moved += 1
        print(f"tags: {slug}: {len(tags)}")
    return moved


def main():
    repos = read_repos()
    last_modified, osv_moved = sync_osv(repos)
    ghsa_moved = sync_ghsa(repos)
    tags_moved = sync_tags(repos)
    moved = osv_moved + ghsa_moved + tags_moved
    # syncdate.json moves only when mirrored bytes moved (or on first
    # sync), so "commits only when bytes moved" is actually true and
    # `synced_at` means "when the mirrored content last changed" -- the
    # data instant, not the run instant. Writing it unconditionally made
    # every daily run a commit and every no-op day look like movement.
    if moved or not (ROOT / "syncdate.json").is_file():
        (ROOT / "syncdate.json").write_bytes(stable_bytes({
            "synced_at": datetime.now(timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ"),
            "osv_export_last_modified": last_modified,
        }))
    print(f"sync: done ({moved} records moved)")


if __name__ == "__main__":
    main()
