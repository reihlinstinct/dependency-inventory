#!/usr/bin/env python3
"""CLI: scan an inventory file against OSV and write a Markdown report."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def main(argv=None):
    import argparse
    import json

    from depinv.osv import scan
    from depinv.report import markdown

    ap = argparse.ArgumentParser(description="Scan deps-inventory.json against OSV")
    ap.add_argument("--inventory", required=True)
    ap.add_argument("--out", default="vuln-report.md")
    ap.add_argument("--title", default="Vulnerability scan")
    args = ap.parse_args(argv)

    with open(args.inventory, encoding="utf-8") as f:
        data = json.load(f)
    packages = data["packages"] if isinstance(data, dict) else data
    findings = scan(packages)
    pinned = len({(e["ecosystem"], e["package"], e["version"])
                  for e in packages if e.get("version")})
    report = markdown(findings, args.title, len(packages), pinned)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(report)
    print(f"[depinv] {len(findings)} findings across {pinned} pinned packages "
          f"({len(packages)} records)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
