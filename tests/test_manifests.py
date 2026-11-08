from depinv.manifests import (
    parse_go_mod,
    parse_package_lock,
    parse_pyproject,
    parse_requirements,
    parse_workflow,
)


def test_requirements_pins_and_specs():
    text = "requests==2.32.3  # pinned\nflask>=3.0\n-r other.txt\n# comment\n"
    rows = parse_requirements(text)
    assert ("PyPI", "requests", "2.32.3", "==2.32.3") in rows
    assert ("PyPI", "flask", None, ">=3.0") in rows
    assert all("other.txt" not in str(r) for r in rows)


def test_requirements_env_marker_stripped():
    rows = parse_requirements('uvicorn>=0.30; python_version >= "3.11"\n')
    assert rows == [("PyPI", "uvicorn", None, ">=0.30")]


def test_pyproject_project_deps():
    text = '[project]\ndependencies = [\n  "pillow>=13",\n  "pyyaml==6.0.3",\n]\n'
    rows = parse_pyproject(text)
    assert ("PyPI", "pillow", None, ">=13") in rows
    assert ("PyPI", "pyyaml", "6.0.3", "==6.0.3") in rows


def test_package_lock_transitive_versions():
    text = '{"packages": {"": {}, "node_modules/a": {"version": "1.2.3"},' \
           ' "node_modules/x/node_modules/b": {"version": "9.9.9"}}}'
    rows = parse_package_lock(text)
    assert ("npm", "a", "1.2.3", None) in rows
    assert ("npm", "b", "9.9.9", None) in rows


def test_go_mod_direct_and_indirect():
    text = "module example\n\nrequire (\n\tgithub.com/a/b v1.2.3\n\tgithub.com/c/d v0.1.0 // indirect\n)\n"
    rows = parse_go_mod(text)
    assert ("Go", "github.com/a/b", "1.2.3", None) in rows
    assert ("Go", "github.com/c/d", "0.1.0", "indirect") in rows


def test_workflow_uses_tags_and_shas():
    text = ("- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
            "- uses: actions/setup-node@v4\n"
            "- uses: octo/tool/.github/workflows/x.yml@v2\n")
    rows = parse_workflow(text)
    assert ("GitHub Actions", "actions/checkout", None,
            "3d3c42e5aac5ba805825da76410c181273ba90b1") in rows
    assert ("GitHub Actions", "actions/setup-node", "4", "v4") in rows
    assert ("GitHub Actions", "octo/tool", "2", "v2") in rows
