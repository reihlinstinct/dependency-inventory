"""Parsers turning dependency manifests into inventory records.

Every parser takes manifest text and returns entries of
``(ecosystem, package, version_or_None, spec_or_None)`` where *version* is a
concrete pinned version and *spec* is the raw version requirement when no
exact pin exists.
"""

from __future__ import annotations

import json
import re

try:  # Python 3.11+
    import tomllib as _toml
except ImportError:  # pragma: no cover - exercised only on 3.10
    _toml = None

REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(==|>=|~=|<=|>|<)?\s*([A-Za-z0-9.*!+\-]+)?")
MANIFEST_RE = re.compile(
    r"(^|/)(requirements[\w.-]*\.txt|pyproject\.toml|package\.json|"
    r"package-lock\.json|go\.mod)$"
)
WORKFLOW_RE = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$")
USES_RE = re.compile(r"uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([^\s'\"#]+)")

Entry = tuple  # (ecosystem, package, version, spec)


def _requirement(dep: str) -> Entry | None:
    m = REQ_RE.match(dep.split("#")[0].split(";")[0].strip())
    if not m or not m.group(1):
        return None
    version = m.group(3) if m.group(2) == "==" else None
    spec = ((m.group(2) or "") + (m.group(3) or "")).strip() or None
    return ("PyPI", m.group(1), version, spec)


def parse_requirements(text: str) -> list[Entry]:
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(("#", "-", "git+", "http")):
            continue
        e = _requirement(s)
        if e:
            out.append(e)
    return out


def _pyproject_deps_fallback(text: str) -> list[str]:
    """Extract dependency strings from [project] without tomllib."""
    deps, in_deps = [], False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("dependencies") and s.endswith("["):
            in_deps = True
            continue
        if in_deps and s.startswith("]"):
            in_deps = False
            continue
        if in_deps:
            m = re.match(r'["\']([^"\']+)["\']', s)
            if m:
                deps.append(m.group(1))
    return deps


def parse_pyproject(text: str) -> list[Entry]:
    out = []
    if _toml is not None:
        try:
            data = _toml.loads(text)
        except Exception:
            return out
        proj = data.get("project", {})
        deps = list(proj.get("dependencies", []) or [])
        for group in (proj.get("optional-dependencies", {}) or {}).values():
            deps.extend(group or [])
        deps.extend(
            f"{name} {spec.get('version', '') if isinstance(spec, dict) else spec}"
            for name, spec in (
                data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
            ).items()
            if name.lower() != "python"
        )
    else:
        deps = _pyproject_deps_fallback(text)
    for dep in deps:
        e = _requirement(str(dep))
        if e:
            out.append(e)
    return out


def parse_package_json(text: str) -> list[Entry]:
    out = []
    try:
        data = json.loads(text)
    except Exception:
        return out
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            out.append(("npm", name, None, str(spec)))
    return out


def parse_package_lock(text: str) -> list[Entry]:
    out = []
    try:
        data = json.loads(text)
    except Exception:
        return out
    for path, info in (data.get("packages") or {}).items():
        if not path or not isinstance(info, dict):
            continue
        if info.get("version"):
            out.append(("npm", path.split("node_modules/")[-1], info["version"], None))
    return out


def parse_go_mod(text: str) -> list[Entry]:
    out = []
    in_block = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        if s.startswith("require ") and not in_block:
            s = s[len("require "):]
        elif not in_block:
            continue
        parts = s.split()
        if len(parts) >= 2 and not parts[0].startswith("//"):
            out.append(("Go", parts[0], parts[1].lstrip("v"),
                        "indirect" if "// indirect" in s else None))
    return out


def parse_workflow(text: str) -> list[Entry]:
    out = []
    for m in USES_RE.finditer(text):
        action, ref = m.group(1), m.group(2)
        parts = action.split("/")
        if len(parts) > 2:
            action = "/".join(parts[:2])
        version = ref.lstrip("vV") if ref.startswith(("v", "V")) else None
        out.append(("GitHub Actions", action, version, ref))
    return out


PARSERS = {
    "requirements": parse_requirements,
    "pyproject.toml": parse_pyproject,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "go.mod": parse_go_mod,
}


def parser_for(path: str):
    base = path.rsplit("/", 1)[-1]
    if base.startswith("requirements") and base.endswith(".txt"):
        return parse_requirements
    return PARSERS.get(base)
