import json

import pytest

from core import catalog as catalog_module
from core.catalog import MAX_MANIFEST_BYTES, availability, filter_tools, load_catalog, sync_tools
from core.manifest import ToolManifest

GOOD = """\
id: {id}
name: "{name}"
category: {category}
description: "Test tool."
limitations: "Test only."
official_url: https://example.com/{id}
license: {license}
open_source: {oss}
labels: [{labels}]
target_types: [username]
{extra}launch:
{launch}
review_date: 2026-10-01
"""


def write(directory, id, name="Tool", category="usernames", labels="external, passive", oss="true",
          license='"MIT"', launch="  kind: browser", extra="", file=None):
    text = GOOD.format(id=id, name=name, category=category, labels=labels, oss=oss, license=license,
                       launch=launch, extra=extra)
    (directory / (file or f"{id}.yaml")).write_text(text, encoding="utf-8")


@pytest.fixture
def tools_dir(tmp_path):
    d = tmp_path / "tools"
    d.mkdir()
    write(d, "alpha", "Alpha", "usernames")
    write(d, "beta", "Beta", "domains", labels="local", launch="  kind: python\n  module: json")
    write(d, "gamma", "Gamma", "email", labels="external, active", extra="active_setting: active.gamma\n",
          launch='  kind: subprocess\n  venv: envs/gamma\n  args: ["{username}"]')
    write(d, "delta", "Delta", "ip", oss="false", license="null",
          labels="external, passive, api_key", extra="api_key: required\n", launch="  kind: web_api")
    return d


def test_load_sorts_by_category_then_name(tools_dir):
    catalog = load_catalog(tools_dir)
    assert catalog.errors == []
    assert [t.id for t in catalog.tools] == ["alpha", "gamma", "delta", "beta"]
    assert catalog.get("beta").name == "Beta"
    assert str(catalog.reviewed) == "2026-10-01"


def test_bad_manifests_are_skipped_and_reported(tools_dir):
    (tools_dir / "broken.yaml").write_text("id: [unclosed", encoding="utf-8")
    (tools_dir / "list.yaml").write_text("- just a list", encoding="utf-8")
    write(tools_dir, "alpha", "Alpha copy", file="alpha_copy.yaml")
    write(tools_dir, "epsilon", file="wrong_name.yaml")
    write(tools_dir, "zeta", labels="local, external")
    (tools_dir / "huge.yaml").write_text("#" * (MAX_MANIFEST_BYTES + 1), encoding="utf-8")
    (tools_dir / "notes.txt").write_text("ignored", encoding="utf-8")

    catalog = load_catalog(tools_dir)
    assert len(catalog.tools) == 4
    errors = {e.file: e.message for e in catalog.errors}
    assert set(errors) == {"broken.yaml", "list.yaml", "alpha_copy.yaml", "wrong_name.yaml", "zeta.yaml", "huge.yaml"}
    assert "duplicate id" in errors["alpha_copy.yaml"]
    assert "file name must match" in errors["wrong_name.yaml"]
    assert "labels" in errors["zeta.yaml"]


def test_filters(tools_dir):
    tools = load_catalog(tools_dir).tools
    ids = lambda items: sorted(t.id for t in items)  # noqa: E731
    assert ids(filter_tools(tools)) == ["alpha", "beta", "delta", "gamma"]
    assert ids(filter_tools(tools, category="email")) == ["gamma"]
    assert ids(filter_tools(tools, behavior="local")) == ["beta"]
    assert ids(filter_tools(tools, behavior="external")) == ["alpha", "delta", "gamma"]
    assert ids(filter_tools(tools, behavior="active")) == ["gamma"]
    assert ids(filter_tools(tools, open_source_only=True)) == ["alpha", "beta", "gamma"]
    assert ids(filter_tools(tools, query="ALPHA")) == ["alpha"]
    assert ids(filter_tools(tools, query="domains")) == ["beta"]  # matches category label
    assert ids(filter_tools(tools, query="example.com/delta")) == ["delta"]
    assert filter_tools(tools, query="nothing here") == []


def test_availability(tools_dir, tmp_path, db):
    catalog = load_catalog(tools_dir)
    assert availability(catalog.get("alpha"), db).status == "Opens browser"
    assert availability(catalog.get("beta"), db).status == "Built in"  # json is importable
    assert availability(catalog.get("delta"), db).status == "Needs key"

    gamma = catalog.get("gamma")
    assert availability(gamma, db).status == "Disabled"  # active tools start off
    db.set_setting("active.gamma", True)
    assert availability(gamma, db, root=tmp_path).status == "Not installed"
    python = tmp_path / "envs" / "gamma" / "Scripts" / "python.exe"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"")
    assert availability(gamma, db, root=tmp_path).status == "Installed"


EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_installed_program_with_no_module_is_not_integrated(tools_dir, tmp_path):
    write(tools_dir, "beta", "Beta", "domains", labels="local",
          launch=f"  kind: subprocess\n  executable: bin/beta.exe\n  sha256: {EMPTY_SHA256}")
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "beta.exe").write_bytes(b"")
    status = availability(load_catalog(tools_dir).get("beta"), root=tmp_path)
    assert (status.status, status.ready) == ("Not integrated", False)


def test_tampered_pinned_tool_is_not_ready(tools_dir, tmp_path):
    from core.runner import tree_sha256

    (tmp_path / "bin" / "beta_files").mkdir(parents=True)
    (tmp_path / "bin" / "beta.exe").write_bytes(b"")
    (tmp_path / "bin" / "beta_files" / "beta.pl").write_text("print 1", encoding="utf-8")
    pinned = tree_sha256(tmp_path / "bin" / "beta_files")
    write(tools_dir, "beta", "Beta", "domains", labels="local",
          launch=f"  kind: subprocess\n  executable: bin/beta.exe\n  sha256: {EMPTY_SHA256}\n"
                 f"  tree: bin/beta_files\n  tree_sha256: {pinned}\n  args: [\"{{username}}\"]")
    beta = load_catalog(tools_dir).get("beta")
    assert availability(beta, root=tmp_path).status == "Installed"

    (tmp_path / "bin" / "beta_files" / "beta.pl").write_text("print 2", encoding="utf-8")  # changed script
    catalog_module._integrity.clear()  # as at the next start
    status = availability(beta, root=tmp_path)
    assert (status.status, status.ready) == ("Integrity check failed", False)
    assert "bin/beta_files" in status.detail


def test_missing_python_module(tools_dir):
    write(tools_dir, "beta", "Beta", "domains", labels="local",
          launch="  kind: python\n  module: definitely_not_installed_xyz")
    beta = load_catalog(tools_dir).get("beta")
    assert availability(beta).status == "Not installed"


def test_sync_tools_upserts_and_removes(tools_dir, db):
    tools = load_catalog(tools_dir).tools
    sync_tools(db, tools)
    rows = {r["id"]: r for r in db.execute("SELECT * FROM tools")}
    assert set(rows) == {"alpha", "beta", "gamma", "delta"}
    assert json.loads(rows["gamma"]["labels"]) == ["external", "active"]
    assert rows["delta"]["api_requirements"] == "API key required"
    assert rows["beta"]["launch_method"] == "python"

    renamed = [t.model_copy(update={"name": "Alpha 2"}) if t.id == "alpha" else t for t in tools]
    sync_tools(db, [t for t in renamed if t.id != "delta"])
    rows = {r["id"]: r for r in db.execute("SELECT * FROM tools")}
    assert set(rows) == {"alpha", "beta", "gamma"}
    assert rows["alpha"]["name"] == "Alpha 2"


def test_sync_with_empty_catalog(db, tools_dir):
    sync_tools(db, load_catalog(tools_dir).tools)
    sync_tools(db, [])
    assert db.execute("SELECT COUNT(*) FROM tools").fetchone()[0] == 0


def test_manifest_type_is_frozen(tools_dir):
    tool = load_catalog(tools_dir).get("alpha")
    assert isinstance(tool, ToolManifest)
    with pytest.raises(Exception):
        tool.name = "changed"
