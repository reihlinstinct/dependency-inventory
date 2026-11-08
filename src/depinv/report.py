"""Render findings as Markdown."""

from __future__ import annotations


def markdown(findings: list[dict], title: str, total_records: int,
             pinned_combos: int) -> str:
    lines = [
        f"# {title}",
        "",
        (
            f"Scanned {pinned_combos} pinned packages from {total_records} "
            f"dependency records against OSV (osv.dev, includes the GitHub "
            f"Advisory Database)."
        ),
        "",
    ]
    if not findings:
        lines += ["**No known vulnerabilities in any pinned dependency.**", ""]
        return "\n".join(lines)
    lines += [
        f"**{len(findings)} findings.**", "",
        "| Severity | Package | Version | ID | CVE | Fixed in | Repos |",
        "|---|---|---|---|---|---|---|",
    ]
    for f in findings:
        repos = sorted({loc["repo"] for loc in f["locations"]})
        lines.append(
            f"| {f['severity']} ({f['severity_score'] or '?'}) "
            f"| `{f['package']}` | {f['version']} | {f['id']} "
            f"| {', '.join(f['aliases']) or '-'} "
            f"| {', '.join(f['fixed']) or '-'} | {', '.join(repos)} |"
        )
    lines.append("")
    for f in findings:
        lines += [f"## {f['id']}: {f['package']} {f['version']}", "",
                  f["summary"] or "(no summary)", ""]
        for loc in f["locations"]:
            lines.append(f"- `{loc['repo']}` — {loc['file']}")
        lines.append("")
    return "\n".join(lines)
