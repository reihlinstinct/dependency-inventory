import json

from depinv.generate import generate


def test_generate_walks_repo(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("- uses: actions/checkout@v7\n")
    data = generate(str(tmp_path), "o/r")
    rows = data["packages"]
    assert any(r["package"] == "requests" and r["version"] == "2.32.3"
               and r["direct"] for r in rows)
    assert any(r["ecosystem"] == "GitHub Actions" and r["package"] == "actions/checkout"
               for r in rows)
    json.dumps(data)  # serialisable


def test_lock_rows_marked_transitive(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"a": "^1.0.0"}}')
    (tmp_path / "package-lock.json").write_text(
        '{"packages": {"": {}, "node_modules/a": {"version": "1.0.0"},'
        ' "node_modules/b": {"version": "2.0.0"}}}')
    rows = generate(str(tmp_path), "o/r")["packages"]
    by_name = {r["package"]: r for r in rows}
    assert by_name["a"]["direct"] is True
    assert by_name["b"]["direct"] is False
