#!/usr/bin/env python3
"""Aggregate: collect org inventory, scan public packages, write data/, upsert issue.

Privacy contract: private-repo names and dependencies never reach committed
files, logs, or artifacts. Only aggregate counts are reported for them.
"""
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from depinv.org_collect import GitHub, collect
from depinv.osv import scan
from depinv.report import markdown

MARKER = "<!-- depinv-tracker -->"
OWNER = "reihlinstinct"
CENTRAL = "dependency-inventory"


def upsert_issue(token: str, findings_md: str, findings_count: int) -> None:
    gh = GitHub(token)
    issues = gh.get(f"/repos/{OWNER}/{CENTRAL}/issues?state=open&per_page=100") or []
    body = (f"{MARKER}\nLatest weekly scan results.\n\n{findings_md}")
    headers = {**gh.headers, "Content-Type": "application/json"}
    existing = next((i for i in issues if MARKER in (i.get("body") or "")), None)
    if existing:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{OWNER}/{CENTRAL}/issues/{existing['number']}",
            data=json.dumps({"body": body}).encode(), headers=headers, method="PATCH")
        urllib.request.urlopen(req, timeout=30).read()
        print(f"[aggregate] updated tracking issue #{existing['number']}")
    elif findings_count:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{OWNER}/{CENTRAL}/issues",
            data=json.dumps({"title": "Vulnerability findings (weekly tracking)",
                             "body": body,
                             "labels": ["security"]}).encode(),
            headers=headers, method="POST")
        resp = json.loads(urllib.request.urlopen(req, timeout=30).read())
        print(f"[aggregate] opened tracking issue #{resp['number']}")
    else:
        print("[aggregate] no findings and no existing tracker: nothing to file")


def main():
    read_token = os.environ.get("REPO_READ_TOKEN", "")
    gh_token = os.environ.get("GITHUB_TOKEN", "")
    if not read_token:
        sys.exit("REPO_READ_TOKEN is required")
    inventory = collect(GitHub(read_token), OWNER, public_only=False,
                        log=lambda m: print(m, file=sys.stderr))
    public_rows = [{k: v for k, v in e.items() if k != "private"}
                   for e in inventory if not e["private"]]
    private_rows = [e for e in inventory if e["private"]]
    public_findings = scan(public_rows)
    private_findings = scan(private_rows)

    os.makedirs("data", exist_ok=True)
    with open("data/inventory.json", "w", encoding="utf-8") as f:
        json.dump({"public_only": True, "packages": public_rows}, f, indent=1)
        f.write("\n")
    pinned = len({(e["ecosystem"], e["package"], e["version"])
                  for e in public_rows if e["version"]})
    findings_md = markdown(public_findings, "Weekly vulnerability scan (public repos)",
                           len(public_rows), pinned)
    with open("data/findings.md", "w", encoding="utf-8") as f:
        f.write(findings_md)
    with open("data/findings.json", "w", encoding="utf-8") as f:
        json.dump(public_findings, f, indent=1)
    summary = {
        "private_repos": len({e["repo"] for e in private_rows}),
        "private_records": len(private_rows),
        "private_findings": len(private_findings),
        "note": "Counts only. Private repo names and details are never published.",
    }
    with open("data/private-summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=1)
        f.write("\n")
    print(f"[aggregate] public: {len(public_rows)} records, "
          f"{len(public_findings)} findings; private: {summary}")
    if gh_token:
        upsert_issue(gh_token, findings_md, len(public_findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
