"""Walk a checked-out repository and build deps-inventory.json."""

from __future__ import annotations

import datetime
import json
import os

from .manifests import WORKFLOW_RE, parse_workflow, parser_for


def generate(repo_dir: str, repo_name: str) -> dict:
    packages = []
    direct = set()
    lock_rows = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__")]
        for fname in files:
            path = os.path.relpath(os.path.join(root, fname), repo_dir)
            try:
                with open(os.path.join(root, fname), encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            if WORKFLOW_RE.match(path):
                for eco, pkg, ver, ref in parse_workflow(text):
                    packages.append(_row(eco, pkg, ver, ref, repo_name, path, True))
                continue
            parser = parser_for(path)
            if not parser:
                continue
            for eco, pkg, ver, spec in parser(text):
                if path.endswith("package-lock.json"):
                    lock_rows.append((eco, pkg, ver, spec, path))
                else:
                    direct.add((eco, pkg.lower()))
                    packages.append(_row(eco, pkg, ver, spec, repo_name, path, True))
    for eco, pkg, ver, spec, path in lock_rows:
        packages.append(_row(eco, pkg, ver, spec, repo_name, path,
                             (eco, pkg.lower()) in direct))
    packages.sort(key=lambda r: (r["ecosystem"], r["package"].lower(), r["file"]))
    return {
        "repo": repo_name,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "packages": packages,
    }


def _row(eco, pkg, ver, spec, repo, path, is_direct):
    return {"ecosystem": eco, "package": pkg, "version": ver, "spec": spec,
            "repo": repo, "file": path, "direct": bool(is_direct)}


def main(argv=None):
    import argparse

    ap = argparse.ArgumentParser(description="Generate deps-inventory.json for a repo")
    ap.add_argument("--repo", default=".", help="checked-out repository directory")
    ap.add_argument("--name", default=None, help="repo name (default: dir name)")
    ap.add_argument("--out", default="deps-inventory.json")
    args = ap.parse_args(argv)
    data = generate(os.path.abspath(args.repo),
                    args.name or os.path.basename(os.path.abspath(args.repo)))
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
        f.write("\n")
    print(f"[depinv] {args.out}: {len(data['packages'])} dependency records")
    return 0
