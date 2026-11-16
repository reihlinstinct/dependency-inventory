"""Org-wide collector: dependency inventory across all repos of an owner.

Reads repos via the GitHub API with a token. ``--public-only`` drops private
repos entirely so the result is safe to commit to a public repository.
"""

from __future__ import annotations

import base64
import datetime
import json
import time
import urllib.error
import urllib.request

from .manifests import WORKFLOW_RE, parse_workflow, parser_for

API = "https://api.github.com"


class GitHub:
    def __init__(self, token: str):
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "dependency-inventory/1.0",
        }

    def get(self, path: str):
        req = urllib.request.Request(API + path, headers=self.headers)
        for attempt in range(4):
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    return json.loads(r.read())
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return None
                if e.code in (403, 429, 502, 503) and attempt < 3:
                    time.sleep(5 * (attempt + 1))
                    continue
                raise


def collect(gh: GitHub, owner: str, public_only: bool,
            log=lambda m: None) -> list[dict]:
    repos = gh.get("/user/repos?per_page=100&visibility=all&affiliation=owner") or []
    repos = [r for r in repos if r["owner"]["login"] == owner]
    inventory: list[dict] = []
    for repo in sorted(repos, key=lambda r: r["name"]):
        name, private = repo["name"], repo["private"]
        if repo.get("archived") or (public_only and private):
            continue
        tree = gh.get(f"/repos/{owner}/{name}/git/trees/HEAD?recursive=1") or {}
        direct: set[tuple[str, str]] = set()
        lock_rows = []
        for item in tree.get("tree", []):
            if item.get("type") != "blob":
                continue
            path = item["path"]
            is_wf = WORKFLOW_RE.match(path)
            parser = None if is_wf else parser_for(path)
            if not is_wf and not parser:
                continue
            blob = gh.get(f"/repos/{owner}/{name}/git/blobs/{item['sha']}")
            if not blob:
                continue
            text = base64.b64decode(blob["content"]).decode("utf-8", "replace")
            if is_wf:
                for eco, pkg, ver, ref in parse_workflow(text):
                    inventory.append(_row(eco, pkg, ver, ref, name, path, True, private))
                continue
            for eco, pkg, ver, spec in parser(text):
                if path.endswith("package-lock.json"):
                    lock_rows.append((eco, pkg, ver, spec, path))
                else:
                    direct.add((eco, pkg.lower()))
                    inventory.append(_row(eco, pkg, ver, spec, name, path, True, private))
        for eco, pkg, ver, spec, path in lock_rows:
            inventory.append(_row(eco, pkg, ver, spec, name, path,
                                  (eco, pkg.lower()) in direct, private))
        log(f"[collect] {name}: {len(inventory)} records so far")
    return inventory


def _row(eco, pkg, ver, spec, repo, path, is_direct, private):
    return {"ecosystem": eco, "package": pkg, "version": ver, "spec": spec,
            "repo": repo, "file": path, "direct": bool(is_direct),
            "private": bool(private)}


def main(argv=None):
    import argparse
    import os
    import sys

    ap = argparse.ArgumentParser(description="Collect org-wide dependency inventory")
    ap.add_argument("--owner", default="reihlinstinct")
    ap.add_argument("--token-env", default="REPO_READ_TOKEN")
    ap.add_argument("--out", default="data/inventory.json")
    ap.add_argument("--public-only", action="store_true")
    args = ap.parse_args(argv)

    token = os.environ.get(args.token_env, "")
    if not token:
        sys.exit(f"missing token in env {args.token_env}")
    gh = GitHub(token)
    inventory = collect(gh, args.owner, args.public_only,
                        log=lambda m: print(m, file=sys.stderr))
    payload = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "public_only": args.public_only,
        "packages": inventory,
    }
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=1)
        f.write("\n")
    print(f"[depinv] {args.out}: {len(inventory)} records")
    return 0
