"""Case Map core: board storage, graph building, shared-value rules, filters and layout. Fake data only."""

from __future__ import annotations

import math
import sqlite3
import time
from pathlib import Path

import pytest

from core import casemap as cm
from core.casemap import Edge, MapFilter, Node
from core.db import MIGRATIONS, SCHEMA, Database, _split_statements
from core.dbcrypto import DbCrypto
from core.evidence import EvidenceStore
from core.findings import Finding, FindingStore, ResultKind
from core.retention import delete_case
from core.runs import RunStore

PASSWORD = "example-master-passphrase"


@pytest.fixture
def case(manager, new_case):
    return manager.create_case(new_case())  # target t:1 = username example_user


def add(db, case_id, *findings, target_id=None, run_id=None):
    made = [Finding(module=f.get("module", "UserRecon"), title=f.get("title", "Profile"),
                    source=f.get("source", "Sherlock"), value=f.get("value"), url=f.get("url"),
                    confidence=f.get("confidence", "medium"), result=f.get("result", "found")) for f in findings]
    return FindingStore(db).add(case_id, made, run_id=run_id, target_id=target_id)


def shared(g):
    return [e for e in g.edges if e.kind == "shared"]


def linked(g, a, b):
    return [e for e in shared(g) if {e.src, e.dst} == {a, b}]


# ------------------------------------------------------------------ storage


def test_migrates_a_version_2_database(tmp_path):
    path = tmp_path / "v2.db"
    conn = sqlite3.connect(path)
    for statement in _split_statements(SCHEMA) + _split_statements(MIGRATIONS[2]):
        conn.execute(statement)
    conn.execute("PRAGMA user_version = 2")
    conn.execute("INSERT INTO cases (name, purpose, authorized_scope, created_at, updated_at) "
                 "VALUES ('Old case', 'p', 's', 'x', 'x')")
    conn.commit()
    conn.close()
    with Database(path) as db:
        assert db.schema_version == 4 and "board_items" in db.table_names()
        note = cm.add_note(db, 1, 10, 20, "Check example.com")
        assert cm.load_board(db, 1).notes == [note]


def test_board_is_deleted_with_the_case(db, case, tmp_path):
    note = cm.add_note(db, case.id, 0, 0, "note")
    cm.add_link(db, case.id, note.key, "t:1", "same handle")
    cm.save_positions(db, case.id, {"t:1": (5, 5)}, set())
    assert db.execute("SELECT COUNT(*) FROM board_items").fetchone()[0] == 3
    delete_case(db, case.id, tmp_path)
    assert db.execute("SELECT COUNT(*) FROM board_items").fetchone()[0] == 0


def test_encrypted_round_trip(tmp_path, new_case):
    from core.cases import CaseManager

    enc = tmp_path / "nightglass.db.enc"
    db = Database(enc, crypto=DbCrypto.create(enc, PASSWORD))
    case = CaseManager(db).create_case(new_case())
    cm.add_note(db, case.id, 1.25, 2, "board secret about example_user")
    cm.save_positions(db, case.id, {"t:1": (40, 50)}, {"t:1"})
    db.close()
    assert b"board secret" not in enc.read_bytes()
    crypto, data = DbCrypto.unlock(enc, PASSWORD)
    with Database(enc, crypto=crypto, data=data) as again:
        board = cm.load_board(again, case.id)
        assert [n.text for n in board.notes] == ["board secret about example_user"]
        assert (board.notes[0].x, board.notes[0].y) == (round(1.25, 1), 2.0)  # stored to 1 dp
        assert board.positions["t:1"] == (40.0, 50.0) and board.pinned == {"t:1"}


def test_note_and_link_validation(db, case, manager):
    note = cm.add_note(db, case.id, 0, 0, "line one\r\nline\x00 two‮")
    assert note.key == f"n:{note.id}" and note.text == "line one\nline two"
    with pytest.raises(ValueError, match="2000"):
        cm.add_note(db, case.id, 0, 0, "x" * 2001)
    cm.update_note(db, case.id, note.key, text="edited", x=7, y=8)
    [edited] = cm.load_board(db, case.id).notes
    assert (edited.text, edited.x, edited.y) == ("edited", 7.0, 8.0)
    with pytest.raises(KeyError):
        cm.update_note(db, case.id, "n:999", text="gone")

    link = cm.add_link(db, case.id, "t:1", note.key, "same\nhandle\x07")
    assert link.key == f"l:{link.id}" and link.label == "same handle"
    for a, b, label, message in [("t:1", "t:1", "", "different"), ("t:1", "f:99", "", "on the map"),
                                 (note.key, "t:1", "", "already"), ("t:1", "case", "x" * 81, "80")]:
        with pytest.raises(ValueError, match=message):
            cm.add_link(db, case.id, a, b, label)
    cm.add_link(db, case.id, "case", "t:1", "", valid_keys={"case", "t:1"})

    manager.close_case(case.id)
    for call in (lambda: cm.add_note(db, case.id, 0, 0, "x"),
                 lambda: cm.update_note(db, case.id, note.key, text="y"),
                 lambda: cm.add_link(db, case.id, "case", note.key, ""),
                 lambda: cm.delete_item(db, case.id, "link", link.key)):
        with pytest.raises(ValueError, match="The case is closed. Reopen it"):
            call()
    cm.update_note(db, case.id, note.key, x=1, y=2)  # moving is still allowed
    cm.save_positions(db, case.id, {"t:1": (3, 4)}, {"t:1"}, keep=set())  # closed: saved, never pruned
    board = cm.load_board(db, case.id)
    assert board.positions[note.key] == (1.0, 2.0) and board.positions["t:1"] == (3.0, 4.0)

    manager.reopen_case(case.id)
    cm.delete_item(db, case.id, "note", note.key)
    board = cm.load_board(db, case.id)
    assert not board.notes and [lk.a_key for lk in board.links] == ["case"]  # the note's string went with it


def test_positions_upsert_prune_and_pins(db, case):
    note = cm.add_note(db, case.id, 0, 0, "n")
    cm.save_positions(db, case.id, {"case": (0, 0), "t:1": (1.26, 2), "f:9": (3, 3), note.key: (9, 9)},
                      {"t:1", note.key})
    cm.save_positions(db, case.id, {"t:1": (5, 6), "s:Sherlock": (float("nan"), 0)}, set(),
                      keep={"case", "t:1", note.key})
    board = cm.load_board(db, case.id)
    assert board.positions == {"case": (0, 0), "t:1": (5, 6), note.key: (9, 9)}  # f:9 pruned, nan skipped
    assert board.pinned == {note.key}
    assert db.execute("SELECT COUNT(*) FROM board_items WHERE kind = 'pos'").fetchone()[0] == 2


# ------------------------------------------------------------------ graph


def test_graph_counts_labels_and_active_flag(db, case):
    run = RunStore(db).create(case.id, "PortScanner", active=True)
    ids = add(db, case.id, dict(title="GitHub profile", url="https://github.com/example_user", confidence="high"),
              dict(title="Blocked site", result="uncertain"), dict(title="File type", result="info"),
              target_id=1)
    [scan] = add(db, case.id, dict(module="PortScanner", title="Open port", value="203.0.113.5:443",
                                   source="nmap"), run_id=run.id)
    FindingStore(db).set_status(ids[0], "verified")
    EvidenceStore(db).record(case.id, Path("shot.png"), "a" * 64, "Profile screenshot", finding_id=ids[0])
    EvidenceStore(db).record(case.id, Path("loose.png"), "b" * 64)
    g = cm.build_graph(db, case.id)

    s = g.stats
    assert (s["case"], s["target"], s["finding"], s["source"], s["evidence"]) == (1, 1, 4, 2, 2)
    assert s["nodes"] == len(g.nodes) and s["edges"] == len(g.edges) and s["omitted_buckets"] == 0
    assert g.nodes["case"].detail == "CASE-001" and g.nodes["t:1"].subtype == "username"
    assert [g.nodes[f"f:{i}"].status for i in (*ids, scan)] == ["verified", "uncertain", "info", "lead"]
    assert g.nodes[f"f:{scan}"].active and not g.nodes[f"f:{ids[0]}"].active
    assert g.nodes["e:1"].value == "a" * 64 and g.nodes["e:1"].detail == "shot.png"
    labels = {(e.src, e.dst): (e.kind, e.label, e.confidence) for e in g.edges}
    assert labels[("case", "t:1")] == ("has_target", "", "high")
    assert labels[("t:1", f"f:{ids[0]}")] == ("found_by", "found by UserRecon", "high")
    assert labels[(f"f:{ids[0]}", "s:Sherlock")] == ("via", "via Sherlock", "high")
    assert labels[(f"f:{ids[0]}", "e:1")][0] == "evidence"
    assert labels[("case", f"f:{scan}")][1] == "found by PortScanner"  # orphan finding hangs off the case
    assert labels[("case", "e:2")][0] == "evidence"
    assert all(g.nodes[k] for e in g.edges for k in (e.src, e.dst))
    assert g.adj["t:1"] >= {"case", f"f:{ids[0]}"}


def test_shared_value_rules(db, case):
    ids = add(db, case.id,
              dict(url="https://WWW.Example.com/Page/"), dict(url="http://example.com/page?utm_source=x#top"),
              dict(url="https://github.com/example_person"), dict(url="https://github.com/example_other"),
              dict(url="https://gitlab.com/@example_person/project"),
              dict(value="owner@Example.com"), dict(value="contact: OWNER@example.com"),
              dict(value="203.0.113.5"), dict(value="seen at 203.0.113.5"),
              dict(value="10.0.0.1"), dict(value="host 10.0.0.1"),
              dict(value="md5 " + "A" * 32), dict(value="a" * 32))
    f = [f"f:{i}" for i in ids]
    g = cm.build_graph(db, case.id)
    assert [e.label for e in linked(g, f[0], f[1])] == ["same url: example.com/page"]  # www/case/utm/slash
    assert not linked(g, f[2], f[3])  # two GitHub users: a hub domain proves nothing
    assert [e.label for e in linked(g, f[2], f[4])] == ["same username: example_person"]  # two sites, one user
    assert [e.label for e in linked(g, f[5], f[6])] == ["same email: owner@example.com"]
    assert [e.label for e in linked(g, f[7], f[8])] == ["same ip: 203.0.113.5"]
    assert not linked(g, f[9], f[10])  # private LAN address
    [h] = linked(g, f[11], f[12])
    assert h.label.startswith("same hash: aaaaaaaaaaaa") and h.confidence == "high"
    assert all(not e.directed for e in shared(g))
    assert len({frozenset((e.src, e.dst)) for e in shared(g)}) == len(shared(g))  # one string per pair


def test_file_names_and_numeric_ids_are_not_usernames(db, case):
    ids = add(db, case.id, *[dict(url=u) for u in (
        "https://example.com/index.html", "https://example.org/index.html", "https://example.net/robots.txt",
        "https://example.edu/robots.txt", "https://example.com/12345", "https://example.org/12345/some-slug",
        "https://example.net/@example_person", "https://example.edu/example_person/")])
    g = cm.build_graph(db, case.id)
    assert not [e for e in shared(g) if e.label.startswith("same username") and "example_person" not in e.label]
    assert [e.label for e in linked(g, f"f:{ids[6]}", f"f:{ids[7]}")] == ["same username: example_person"]


def test_dotted_names_from_username_targets_are_not_domains(db, case):
    a, b = add(db, case.id, dict(value="john.smith"), dict(value="John.Smith"), target_id=1)
    c, d = add(db, case.id, dict(value="sub.example.co.uk"), dict(value="SUB.example.co.uk."))
    e, f = add(db, case.id, dict(value="release.v2"), dict(value="release.v2"))
    g = cm.build_graph(db, case.id)
    assert not linked(g, f"f:{a}", f"f:{b}")
    assert [x.label for x in linked(g, f"f:{c}", f"f:{d}")] == ["same domain: sub.example.co.uk"]
    assert not linked(g, f"f:{e}", f"f:{f}")  # "v2" is no top-level domain


def test_bridge_edges_relink_a_star_whose_centre_is_hidden(db, case):
    ids = add(db, case.id, *[dict(value="owner@example.com")] * 4)
    FindingStore(db).set_status(ids[0], "rejected")
    g = cm.build_graph(db, case.id)
    assert {e.src for e in shared(g)} == {f"f:{ids[0]}"} and all(e.group == "email:owner@example.com"
                                                                   for e in shared(g))
    assert cm.bridge_edges(g, cm.apply_filter(g, MapFilter())[0]) == []
    visible, _ = cm.apply_filter(g, MapFilter(hide_rejected=True))
    bridges = cm.bridge_edges(g, visible)
    assert {(e.src, e.dst) for e in bridges} == {(f"f:{ids[1]}", f"f:{i}") for i in ids[2:]}
    assert {(e.label, e.confidence, e.directed) for e in bridges} == {("same email: owner@example.com", "medium", False)}


def test_target_joins_index_without_duplicating_found_by(db, case, manager):
    domain = manager.add_target(case.id, "domain", "example.com")
    [own] = add(db, case.id, dict(value="example.com"), target_id=domain.id)
    [other] = add(db, case.id, dict(url="https://example.com/contact"))
    [user] = add(db, case.id, dict(url="https://example.org/example_user"))
    g = cm.build_graph(db, case.id)
    assert not linked(g, f"t:{domain.id}", f"f:{own}")  # found_by already joins them
    assert [e.label for e in linked(g, f"t:{domain.id}", f"f:{other}")] == ["same domain: example.com"]
    assert [e.label for e in linked(g, "t:1", f"f:{user}")] == ["same username: example_user"]


def test_image_hashes_link_their_findings(db, case):
    a, b, c, d = add(db, case.id, dict(title="Photo A"), dict(title="Photo B"),
                     dict(value="dhash:00ff00ff00ff00ff"), dict(value="dHash:00FF00FF00FF00FF size 640x480"))
    store = EvidenceStore(db)
    store.record(case.id, Path("one.png"), "c" * 64, finding_id=a)
    store.record(case.id, Path("two.png"), "c" * 64, finding_id=b)
    g = cm.build_graph(db, case.id)
    [same] = linked(g, f"f:{a}", f"f:{b}")
    assert same.label == "same image hash" and same.confidence == "high"
    assert linked(g, f"f:{c}", f"f:{d}")[0].label.startswith("same image")


def test_hub_cap(db, case):
    add(db, case.id, *[dict(value="owner@example.com", source=f"S{i}") for i in range(50)])
    g = cm.build_graph(db, case.id)
    values = [k for k, n in g.nodes.items() if n.kind == "value"]
    assert values == ["v:email:owner@example.com"] and len(shared(g)) == 50
    assert g.nodes[values[0]].detail == "50 linked" and g.stats["collapsed"] == 1


def test_hub_cap_drops_groups_over_forty(db, case):
    add(db, case.id, *[dict(value=f"user{b}@example.com") for b in range(42) for _ in range(7)])
    g = cm.build_graph(db, case.id)
    assert g.stats["value"] == 40 and g.stats["omitted_buckets"] == 2 and len(shared(g)) == 280


def test_small_group_is_a_star(db, case):
    ids = add(db, case.id, *[dict(value="owner@example.com")] * 6)
    g = cm.build_graph(db, case.id)
    assert {(e.src, e.dst) for e in shared(g)} == {(f"f:{ids[0]}", f"f:{i}") for i in ids[1:]}


def test_edge_tone_table():
    nodes = {"case": Node("case", "case", "c"), "t:1": Node("t:1", "target", "t"),
             "s:x": Node("s:x", "source", "x"), "e:1": Node("e:1", "evidence", "e"),
             **{f"f:{s}": Node(f"f:{s}", "finding", s, status=s) for s in ("lead", "verified", "rejected", "info")}}
    table = [
        (Edge("f:verified", "f:verified", "analyst"), "lead"),
        (Edge("f:rejected", "f:verified", "analyst"), "lead"),
        (Edge("f:rejected", "s:x", "via"), "rejected"),
        (Edge("t:1", "f:rejected", "found_by"), "rejected"),
        (Edge("case", "t:1", "has_target"), "neutral"),
        (Edge("f:verified", "s:x", "via"), "neutral"),
        (Edge("case", "e:1", "evidence"), "neutral"),
        (Edge("f:verified", "e:1", "evidence"), "verified"),
        (Edge("t:1", "f:verified", "found_by"), "verified"),
        (Edge("f:verified", "f:verified", "shared"), "verified"),
        (Edge("f:verified", "f:lead", "shared"), "lead"),
        (Edge("f:info", "t:1", "shared"), "lead"),
        (Edge("t:1", "e:1", "shared"), "lead"),
    ]
    for edge, tone in table:
        assert cm.edge_tone(edge, nodes) == tone, edge
    assert cm.EDGE_STYLE == {"high": "solid", "medium": "dash", "low": "dot"}


def test_filters_and_neighborhood(db, case):
    lead, verified, rejected = add(db, case.id, dict(title="Lead profile", value="owner@example.com"),
                                   dict(title="Kept", module="EmailFootprint", source="Blackbird",
                                        confidence="high", value="owner@example.com"),
                                   dict(title="Wrong person", source="Maigret"), target_id=1)
    FindingStore(db).set_status(verified, "verified")
    FindingStore(db).set_status(rejected, "rejected")
    note = cm.add_note(db, case.id, 0, 0, "ask about Example")
    cm.add_link(db, case.id, note.key, f"f:{lead}", "check")
    g = cm.build_graph(db, case.id)
    every = set(g.nodes)

    assert cm.apply_filter(g, MapFilter()) == (every, set())
    visible, _ = cm.apply_filter(g, MapFilter(hide_rejected=True))
    assert f"f:{rejected}" not in visible and "s:Maigret" not in visible and "s:Sherlock" in visible
    visible, _ = cm.apply_filter(g, MapFilter(statuses={"verified"}))
    assert visible == {"case", "t:1", f"f:{verified}", "s:Blackbird", note.key}
    visible, _ = cm.apply_filter(g, MapFilter(modules={"EmailFootprint"}, confidences={"high"}))
    assert {k for k in visible if k.startswith("f:")} == {f"f:{verified}"}
    visible, _ = cm.apply_filter(g, MapFilter(kinds={"target", "finding"}))
    assert note.key not in visible and "s:Sherlock" not in visible and "case" in visible
    visible, matched = cm.apply_filter(g, MapFilter(query="  EXAMPLE  "))
    assert visible == every and {f"f:{lead}", f"f:{verified}", note.key, "t:1"} <= matched

    assert cm.neighborhood(g, "missing") == set()
    assert cm.neighborhood(g, note.key, 0) == {note.key}
    assert cm.neighborhood(g, note.key) == {note.key, f"f:{lead}"}
    assert cm.neighborhood(g, note.key, 2) >= {"t:1", "s:Sherlock", f"f:{verified}"}


# ------------------------------------------------------------------ layout


def _graph(n_targets, per_target):
    nodes = {"case": Node("case", "case", "c")}
    edges = []
    for t in range(n_targets):
        nodes[f"t:{t}"] = Node(f"t:{t}", "target", "t")
        edges.append(Edge("case", f"t:{t}", "has_target"))
        for i in range(per_target):
            key = f"f:{t * 1000 + i}"
            nodes[key] = Node(key, "finding", "f")
            edges.append(Edge(f"t:{t}", key, "found_by"))
    nodes["n:1"] = Node("n:1", "note", "loose note")
    adj = {k: set() for k in nodes}
    for e in edges:
        adj[e.src].add(e.dst)
        adj[e.dst].add(e.src)
    return cm.Graph(nodes, edges, adj, {})


def test_layout_is_deterministic_and_respects_saved_positions():
    g = _graph(3, 8)
    first = cm.layout(g)
    assert first == cm.layout(g) and first["case"] == (0.0, 0.0)
    assert all(round(x, 1) == x and round(y, 1) == y for x, y in first.values())
    spots = list(first.values())
    gap = min(math.dist(a, b) for i, a in enumerate(spots) for b in spots[i + 1:])
    assert gap > 100, gap  # cards (190 wide) don't pile up

    saved = {"t:0": (900.0, -400.0), "f:1": (1234.5, 66.6)}
    again = cm.layout(g, saved, pinned={"t:0"})
    assert again["t:0"] == (900.0, -400.0) and again["f:1"] == (1234.5, 66.6) and again["case"] == (0.0, 0.0)
    near = math.dist(again["f:2"], again["t:0"])
    assert near < 3 * cm.K, near  # a new card settles near its placed neighbour
    assert cm.layout(cm.Graph({}, [], {}, {})) == {}


def test_layout_600_nodes_is_fast_and_finite():
    g = _graph(20, 29)
    assert len(g.nodes) > 600
    start = time.perf_counter()
    spots = cm.layout(g)
    took = time.perf_counter() - start
    assert took < 3, took
    assert len(spots) == len(g.nodes) and all(math.isfinite(v) for p in spots.values() for v in p)
