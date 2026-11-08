"""OSV (osv.dev) batch querying, severity and fixed-version extraction."""

from __future__ import annotations

import json
import math
import time
import urllib.error
import urllib.request

OSV = "https://api.osv.dev"
UA = {"User-Agent": "dependency-inventory/1.0"}


def _open(req, attempts=4):
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code in (429, 500, 502, 503, 504) and attempt < attempts - 1:
                time.sleep(4 * (attempt + 1))
                continue
            raise


def query_batch(combos: list[tuple[str, str, str]]) -> dict[tuple, list[str]]:
    """Map (ecosystem, package, version) -> OSV vuln ids. Batches of 1000."""
    out: dict[tuple, list[str]] = {}
    for i in range(0, len(combos), 1000):
        batch = combos[i:i + 1000]
        payload = {"queries": [
            {"package": {"name": p, "ecosystem": eco}, "version": v}
            for eco, p, v in batch
        ]}
        req = urllib.request.Request(
            f"{OSV}/v1/querybatch", data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", **UA})
        res = _open(req) or {}
        for combo, r in zip(batch, res.get("results", [])):
            ids = [v["id"] for v in r.get("vulns") or []]
            if ids:
                out[combo] = ids
    return out


def get_vuln(vuln_id: str) -> dict | None:
    return _open(urllib.request.Request(f"{OSV}/v1/vulns/{vuln_id}", headers=UA))


def cvss_score(vector: str) -> float | None:
    """Minimal CVSS 3.x base score from a vector string."""
    if not vector or not vector.startswith("CVSS:3"):
        return None
    m = {kv.split(":")[0]: kv.split(":")[1] for kv in vector.split("/")[1:] if ":" in kv}
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        changed = m["S"] == "C"
        pr = ({"N": 0.85, "L": 0.68, "H": 0.5} if changed
              else {"N": 0.85, "L": 0.62, "H": 0.27})[m["PR"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        isc = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
        impact = (7.52 * (isc - 0.029) - 3.25 * ((isc - 0.02) ** 15)
                  if changed else 6.42 * isc)
        if impact <= 0:
            return 0.0
        exploit = 8.22 * av * ac * pr * ui
        score = min(1.08 * (impact + exploit), 10) if changed else min(impact + exploit, 10)
        return math.ceil(score * 10) / 10
    except (KeyError, ZeroDivisionError):
        return None


def severity_of(vuln: dict) -> tuple[float | None, str]:
    best = None
    for s in vuln.get("severity", []):
        if str(s.get("type", "")).startswith("CVSS"):
            sc = cvss_score(s.get("score", ""))
            if sc is not None and (best is None or sc > best):
                best = sc
    if best is not None:
        label = ("CRITICAL" if best >= 9 else "HIGH" if best >= 7 else
                 "MEDIUM" if best >= 4 else "LOW" if best > 0 else "NONE")
        return best, label
    for aff in vuln.get("affected", []):
        sev = (aff.get("database_specific") or {}).get("severity")
        if sev:
            return None, str(sev).upper()
    return None, "UNKNOWN"


def fixed_versions(vuln: dict, ecosystem: str, package: str) -> list[str]:
    out = set()
    for aff in vuln.get("affected", []):
        p = aff.get("package", {})
        if p.get("name", "").lower() != package.lower() or p.get("ecosystem") != ecosystem:
            continue
        for r in aff.get("ranges", []):
            for ev in r.get("events", []):
                if "fixed" in ev:
                    out.add(ev["fixed"])
    return sorted(out)


def scan(packages: list[dict]) -> list[dict]:
    """Scan inventory rows; return findings sorted by severity."""
    combos: dict[tuple, list[dict]] = {}
    for e in packages:
        if e.get("version"):
            combos.setdefault((e["ecosystem"], e["package"], e["version"]), []).append(e)
    hits = query_batch(sorted(combos))
    findings = []
    for combo, ids in hits.items():
        eco, pkg, ver = combo
        for vid in ids:
            v = get_vuln(vid)
            if not v:
                continue
            score, label = severity_of(v)
            locs = sorted({(e["repo"], e["file"]) for e in combos[combo]})
            findings.append({
                "id": vid,
                "aliases": [a for a in v.get("aliases", []) if a.startswith("CVE-")],
                "summary": v.get("summary", ""),
                "severity_score": score, "severity": label,
                "ecosystem": eco, "package": pkg, "version": ver,
                "fixed": fixed_versions(v, eco, pkg),
                "modified": v.get("modified", ""),
                "locations": [{"repo": r, "file": f} for r, f in locs],
            })
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
    findings.sort(key=lambda f: (order.get(f["severity"], 5),
                                 -(f["severity_score"] or 0), f["package"]))
    return findings
