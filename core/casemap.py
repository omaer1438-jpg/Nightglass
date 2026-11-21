"""Case Map: the investigation board's graph model, layout and board storage (docs/CASEMAP_SPEC.md A+B).

Pure Python, no Qt. The graph is rebuilt from the database on demand (cases, targets, findings,
evidence, runs) plus the analyst's own board: card positions, sticky notes and manual strings.
Every connection is a lead until the analyst verifies the findings it joins.
"""

from __future__ import annotations

import ipaddress
import math
import random
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from urllib.parse import unquote, urlsplit

from core.cases import case_ref
from core.db import Database

NODE_KINDS = ("case", "target", "finding", "source", "evidence", "note", "value")
EDGE_STYLE = {"high": "solid", "medium": "dash", "low": "dot"}
MAX_BUCKET = 6        # more cards than this sharing one value -> one synthetic "v:" card
MAX_SYNTHETIC = 40    # at most this many synthetic cards; smaller groups beyond are dropped
MAX_NOTE = 2000
MAX_LABEL = 80
K = 230.0             # ideal edge length (cards are 190x96, the case card 240x120)

#: Shared by unrelated people: a common host is no evidence of a connection.
HUB_DOMAINS = frozenset({
    "github.com", "gitlab.com", "twitter.com", "x.com", "facebook.com", "instagram.com", "reddit.com",
    "linkedin.com", "google.com", "youtube.com", "youtu.be", "tiktok.com", "medium.com", "pinterest.com",
    "t.me", "telegram.org", "discord.com", "twitch.tv", "gravatar.com", "keybase.io", "wikipedia.org",
    "archive.org", "bing.com", "duckduckgo.com", "microsoft.com", "apple.com", "amazon.com",
    "steamcommunity.com", "soundcloud.com", "spotify.com", "vk.com", "tumblr.com", "flickr.com", "imgur.com",
    "wordpress.com", "blogspot.com", "quora.com", "stackoverflow.com", "threads.net", "mastodon.social",
    "bsky.app", "about.me", "linktr.ee", "patreon.com", "paypal.com", "snapchat.com", "pastebin.com",
    "crt.sh", "shodan.io", "virustotal.com", "cloudflare.com",
})
#: Path segments that are never the username in a profile URL.
_NOT_USERNAMES = frozenset({
    "user", "users", "u", "profile", "profiles", "people", "person", "in", "pub", "channel", "c", "account",
    "accounts", "member", "members", "author", "authors", "home", "en", "about", "blog", "news", "search",
    "wiki", "tag", "tags", "category", "index", "posts", "status", "photos", "videos", "groups", "pages",
    "company", "login", "signup", "share", "watch", "explore", "hashtag", "results", "docs",
})
_FILE_EXTS = frozenset({"jpg", "jpeg", "png", "gif", "bmp", "webp", "heic", "tif", "tiff", "pdf", "txt", "doc",
                        "docx", "xls", "xlsx", "csv", "json", "xml", "html", "htm", "log", "zip", "exe", "py", "js"})
# RFC 1918 / CGNAT / ULA: everyone's home network uses them, so they link nothing. Documentation
# ranges (192.0.2.0/24, 2001:db8::/32) are kept on purpose.
_LAN = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                                 "100.64.0.0/10", "fc00::/7"))
# Merge order: when two cards share several things, the first kind here labels their string.
_PRIORITY = {k: i for i, k in enumerate(("url", "email", "hash", "image", "ip", "domain", "username"))}
_MEMBER_RANK = {"t": 0, "f": 1, "e": 2}

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URL = re.compile(r"https?://[^\s<>\"']+", re.I)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_HASH = re.compile(r"\b(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b")
_DHASH = re.compile(r"dhash:([0-9a-fA-F]{16})\b", re.I)
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9-]{1,63}\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{1,59})$")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")
_CLOSED = "The case is closed. Reopen it to change notes and links."


@dataclass(frozen=True)
class Node:
    key: str
    kind: str              # case target finding source evidence note value
    label: str
    ref_id: int | None = None
    status: str = ""       # findings: lead verified uncertain info rejected
    module: str = ""
    confidence: str = ""
    active: bool = False   # found by an active module run
    subtype: str = ""      # target type, shared-value kind, case status
    value: str = ""        # raw value: finding value/url, target value, evidence sha256, note text
    detail: str = ""       # secondary line: case ref, evidence file name, module


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    kind: str              # has_target found_by via evidence shared analyst
    label: str = ""
    confidence: str = "high"
    directed: bool = True
    group: str = ""        # small shared groups (star strings): "<kind>:<value>", for bridge_edges


@dataclass
class Graph:
    nodes: dict[str, Node]
    edges: list[Edge]
    adj: dict[str, set[str]]
    stats: dict


@dataclass(frozen=True)
class Note:
    id: int
    key: str
    x: float
    y: float
    text: str
    pinned: bool


@dataclass(frozen=True)
class Link:
    id: int
    key: str
    a_key: str
    b_key: str
    label: str


@dataclass
class Board:
    positions: dict[str, tuple[float, float]] = field(default_factory=dict)
    pinned: set[str] = field(default_factory=set)
    notes: list[Note] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)


@dataclass
class MapFilter:
    kinds: set[str] | None = None
    statuses: set[str] | None = None
    modules: set[str] | None = None
    confidences: set[str] | None = None
    hide_rejected: bool = False
    query: str = ""


# ------------------------------------------------------------------ value keys


def _host(host: str) -> str:
    host = host.lower().rstrip(".")
    host = host[4:] if host.startswith("www.") else host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _is_hub(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in HUB_DOMAINS)


def _domain_key(host: str) -> tuple[str, str] | None:
    if _DOMAIN.match(host) and not _is_hub(host) and host.rsplit(".", 1)[1] not in _FILE_EXTS:
        return "domain", host
    return None


def _ip_key(text: str) -> tuple[str, str] | None:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local or any(ip in n for n in _LAN):
        return None
    return "ip", ip.compressed


def _url_keys(raw: str) -> set[tuple[str, str]]:
    try:
        parts = urlsplit(raw)
        host = _host(parts.hostname or "")
    except ValueError:
        return set()
    if not host:
        return set()
    path = unquote(parts.path).rstrip("/").lower()
    query = "&".join(p for p in parts.query.split("&") if p and not p.lower().startswith("utm_")).lower()
    keys = {("url", host + path + (f"?{query}" if query else ""))}
    try:
        ipaddress.ip_address(host)
        keys.add(_ip_key(host))
    except ValueError:
        keys.add(_domain_key(host))
    for segment in path.split("/"):
        segment = segment.lstrip("@")
        if not segment or segment in _NOT_USERNAMES:
            continue
        # The first real segment is the profile name; a host alone never is. File names
        # (index.html, robots.txt) and numeric ids (articles, posts) are not names: no username.
        if len(segment) >= 3 and "." not in segment and not segment.isdigit():
            keys.add(("username", segment))
        break
    keys.discard(None)
    return keys


def _value_keys(value: str | None, url: str | None, bare_domain: bool = True) -> set[tuple[str, str]]:
    """Shareable keys in a finding's value and url (or a target's value). `bare_domain=False` for
    username data: "first.last" looks like a domain but is a name."""
    text = " ".join(filter(None, (value, url)))
    keys = {("email", m.lower()) for m in _EMAIL.findall(text)}
    keys.update(_ip_key(m) for m in _IPV4.findall(text))
    keys.update(_ip_key(t.strip("[]()")) for t in re.split(r"[\s,;]+", text) if t.count(":") >= 2)
    for m in _URL.findall(text):
        keys |= _url_keys(m.rstrip(".,;:)]}"))
    if value and bare_domain:
        keys.add(_domain_key(_host(value.strip())))
    if value:
        keys.update(("hash", h.lower()) for h in _HASH.findall(value))
        keys.update(("image", h.lower()) for h in _DHASH.findall(value))
    keys.discard(None)
    return keys


def _target_keys(kind: str, value: str) -> set[tuple[str, str]]:
    keys = _value_keys(value, None, bare_domain=kind != "username")
    name = value.lstrip("@").lower()
    if kind == "username" and len(name) >= 3:
        keys.add(("username", name))
    return keys


# ------------------------------------------------------------------ graph


def build_graph(db: Database, case_id: int, board: Board | None = None) -> Graph:
    case = db.execute("SELECT id, name, status FROM cases WHERE id = ?", (case_id,)).fetchone()
    if case is None:
        raise KeyError(case_id)
    if board is None:
        board = load_board(db, case_id)
    ref = case_ref(case_id)
    nodes = {"case": Node("case", "case", case["name"], case_id, subtype=case["status"], value=ref, detail=ref)}
    edges: list[Edge] = []
    index: dict[tuple[str, str], dict[str, None]] = defaultdict(dict)  # key -> members, in order

    for t in db.execute("SELECT id, type, value FROM targets WHERE case_id = ? ORDER BY id", (case_id,)):
        key = f"t:{t['id']}"
        shown = PureWindowsPath(t["value"]).name if t["type"] == "file" else t["value"]  # no local path / user name
        nodes[key] = Node(key, "target", shown, t["id"], subtype=t["type"], value=shown, detail=t["type"])
        edges.append(Edge("case", key, "has_target", "", "high"))
        for k in sorted(_target_keys(t["type"], t["value"])):
            index[k][key] = None

    rows = db.execute(
        "SELECT f.id, f.target_id, f.module, f.title, f.value, f.source, f.url, f.confidence, f.status, f.result, "
        "COALESCE(r.active, 0) AS active FROM findings f LEFT JOIN runs r ON r.id = f.run_id "
        "WHERE f.case_id = ? ORDER BY f.id", (case_id,))
    for f in rows:
        key, conf = f"f:{f['id']}", f["confidence"]
        # Same as StoredFinding.display_status: an uncertain or info lead shows as that.
        status = f["status"] if f["status"] != "lead" or f["result"] == "found" else f["result"]
        nodes[key] = Node(key, "finding", f["title"], f["id"], status=status, module=f["module"], confidence=conf,
                          active=bool(f["active"]), subtype=f["result"], value=f["value"] or f["url"] or "",
                          detail=f["module"])
        parent = f"t:{f['target_id']}"
        edges.append(Edge(parent if parent in nodes else "case", key, "found_by", f"found by {f['module']}", conf))
        source = f"s:{f['source']}"
        nodes.setdefault(source, Node(source, "source", f["source"], value=f["source"]))
        edges.append(Edge(key, source, "via", f"via {f['source']}", conf))
        from_username = parent in nodes and nodes[parent].subtype == "username"
        for k in sorted(_value_keys(f["value"], f["url"], bare_domain=not from_username)):
            index[k][key] = None

    evidence_hashes = set()
    for e in db.execute("SELECT id, finding_id, path, sha256, description FROM evidence WHERE case_id = ? "
                        "ORDER BY id", (case_id,)):
        key, name, owner = f"e:{e['id']}", Path(e["path"]).name, f"f:{e['finding_id']}"
        nodes[key] = Node(key, "evidence", e["description"] or name, e["id"], value=e["sha256"], detail=name)
        if owner in nodes:
            edges.append(Edge(owner, key, "evidence", "evidence", nodes[owner].confidence))
        else:
            owner = key
            edges.append(Edge("case", key, "evidence", "evidence", "high"))
        sha = e["sha256"].lower()
        evidence_hashes.add(sha)
        index[("hash", sha)][owner] = None

    collapsed, omitted = _shared_edges(nodes, edges, index, evidence_hashes)

    for note in board.notes:
        first = note.text.strip().split("\n", 1)[0]
        nodes[note.key] = Node(note.key, "note", first[:MAX_LABEL] or "Note", note.id, value=note.text)
    for link in board.links:
        if link.a_key in nodes and link.b_key in nodes:
            label = f"analyst: {link.label}" if link.label else "analyst"
            edges.append(Edge(link.a_key, link.b_key, "analyst", label, "low", directed=False))

    adj: dict[str, set[str]] = {k: set() for k in nodes}
    for e in edges:
        adj[e.src].add(e.dst)
        adj[e.dst].add(e.src)
    stats = {kind: 0 for kind in NODE_KINDS}
    for n in nodes.values():
        stats[n.kind] += 1
    stats.update(nodes=len(nodes), edges=len(edges), collapsed=collapsed, omitted_buckets=omitted)
    return Graph(nodes, edges, adj, stats)


def _shared_edges(nodes, edges, index, evidence_hashes) -> tuple[int, int]:
    """Undirected "same <kind>" strings. Small groups: a star around the first card. Large groups:
    one synthetic v: card. Returns (synthetic cards made, groups dropped over the cap)."""
    linked = {frozenset((e.src, e.dst)) for e in edges}
    rank = lambda m: (_MEMBER_RANK[m[0]], int(m[2:]))  # noqa: E731
    buckets = sorted(((k, sorted(m, key=rank)) for k, m in index.items() if len(m) > 1),
                     key=lambda b: (_PRIORITY[b[0][0]], b[0][1]))
    big = sorted((b for b in buckets if len(b[1]) > MAX_BUCKET), key=lambda b: (-len(b[1]), b[0]))
    keep = {b[0] for b in big[:MAX_SYNTHETIC]}
    conf = lambda kind, *ends: _shared_conf(nodes, kind, ends)  # noqa: E731

    for (kind, value), members in buckets:
        if kind == "image":
            label = f"same image (dHash {value})"
        elif kind == "hash":
            label = "same image hash" if value in evidence_hashes else f"same hash: {value[:12]}…"
        else:
            label = f"same {kind}: {value}"
        if len(members) > MAX_BUCKET:
            if (kind, value) not in keep:
                continue
            vkey = f"v:{kind}:{value}"
            nodes[vkey] = Node(vkey, "value", value, subtype=kind, value=value, detail=f"{len(members)} linked")
            edges.extend(Edge(m, vkey, "shared", label, conf(kind, m), False) for m in members)
            continue
        hub = members[0]
        for m in members[1:]:
            pair = frozenset((hub, m))
            if pair not in linked:  # never repeat a found_by string or a stronger shared one
                linked.add(pair)
                edges.append(Edge(hub, m, "shared", label, conf(kind, hub, m), False, f"{kind}:{value}"))
    return len(keep), len(big) - len(keep)


def _shared_conf(nodes, kind, ends) -> str:
    return "low" if any(nodes[k].confidence == "low" for k in ends) else ("high" if kind == "hash" else "medium")


def edge_tone(edge: Edge, nodes: dict[str, Node]) -> str:
    """lead | verified | rejected | neutral. Never red: red is reserved for active modules."""
    if edge.kind == "analyst":
        return "lead"
    ends = [nodes[k] for k in (edge.src, edge.dst) if k in nodes]
    if any(n.status == "rejected" for n in ends):
        return "rejected"
    if edge.kind in ("has_target", "via") or (edge.kind == "evidence" and edge.src == "case"):
        return "neutral"
    findings = [n for n in ends if n.kind == "finding"]
    if findings and all(n.status == "verified" for n in findings):
        return "verified"
    return "lead"


def apply_filter(g: Graph, f: MapFilter) -> tuple[set[str], set[str]]:
    """(visible, matched). Filters act on findings; sources, evidence and shared-value cards stay only
    while they still touch something visible; notes only hide with the Notes chip; the query only highlights."""
    def on(kind):
        return f.kinds is None or kind in f.kinds

    visible = set()
    for k, n in g.nodes.items():
        if n.kind == "case" or (n.kind in ("target", "note") and on(n.kind)):
            visible.add(k)
        elif n.kind == "finding" and on("finding") and not (f.hide_rejected and n.status == "rejected") and (
                f.statuses is None or n.status in f.statuses) and (
                f.modules is None or n.module in f.modules) and (
                f.confidences is None or n.confidence in f.confidences):
            visible.add(k)
    for k, n in g.nodes.items():  # evidence is built before value cards, so a v: card sees it
        if n.kind in ("source", "evidence") and on(n.kind) and g.adj[k] & visible:
            visible.add(k)
        elif n.kind == "value" and len(g.adj[k] & visible) >= 2:
            visible.add(k)
    words = f.query.lower().split()
    matched = set()
    if words:
        for k in visible:
            n = g.nodes[k]
            hay = " ".join((n.label, n.value, n.detail, n.module, n.subtype)).lower()
            if all(w in hay for w in words):
                matched.add(k)
    return visible, matched


def bridge_edges(g: Graph, visible: set[str]) -> list[Edge]:
    """Stand-in strings for small shared groups whose star centre is hidden by a filter.

    A group of 3-6 cards sharing a value is drawn as a star around its first card; if that card is
    filtered out, the visible members would lose their link. This returns a star around the first
    visible member instead (same label and group). Draw them alongside g.edges while `visible` applies;
    they are not part of the graph. Empty when nothing is hidden.
    """
    linked = {frozenset((e.src, e.dst)) for e in g.edges}
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    labels = {}
    for e in g.edges:
        if e.group and e.src not in visible and e.dst in visible:
            groups[(e.src, e.group)].append(e.dst)
            labels[e.group] = e.label
    out = []
    for (_, group), members in groups.items():
        hub = members[0]
        for m in members[1:]:
            if frozenset((hub, m)) not in linked:
                out.append(Edge(hub, m, "shared", labels[group],
                                _shared_conf(g.nodes, group.split(":", 1)[0], (hub, m)), False, group))
    return out


def neighborhood(g: Graph, key: str, hops: int = 1) -> set[str]:
    if key not in g.nodes:
        return set()
    seen, frontier = {key}, {key}
    for _ in range(hops):
        frontier = {n for k in frontier for n in g.adj[k]} - seen
        seen |= frontier
    return seen


# ------------------------------------------------------------------ layout


def layout(g: Graph, saved: dict[str, tuple[float, float]] | None = None, pinned: set[str] = frozenset(),
           iterations: int = 150, seed: int = 7) -> dict[str, tuple[float, float]]:
    """Deterministic Fruchterman-Reingold with grid repulsion.

    Every saved position stays put (the board doesn't reshuffle when findings arrive); to re-layout,
    pass only the pinned cards' positions as `saved`. A pinned key needs a saved position to stay put.
    The case card sits at (0, 0) unless saved elsewhere. New cards start near a placed neighbour.
    """
    nodes = g.nodes
    order = {k: i for i, k in enumerate(nodes)}
    pos = {k: [float(x), float(y)] for k, (x, y) in (saved or {}).items()
           if k in nodes and math.isfinite(x) and math.isfinite(y)}
    if "case" in nodes:
        pos.setdefault("case", [0.0, 0.0])
    fixed = set(pos)  # saved positions, pinned ones among them, and the case card
    rng = random.Random(seed)
    golden = math.pi * (3 - math.sqrt(5))
    children: dict[str, int] = defaultdict(int)

    def place(start):
        queue = deque(start)
        while queue:
            u = queue.popleft()
            for v in sorted(g.adj[u], key=order.__getitem__):
                if v not in pos:
                    i = children[u] = children[u] + 1
                    r, a = K * (0.8 + 0.5 * math.sqrt(i)), i * golden + rng.random() * 0.2
                    pos[v] = [pos[u][0] + r * math.cos(a), pos[u][1] + r * math.sin(a)]
                    queue.append(v)

    place(sorted(pos, key=order.__getitem__))
    loose, spread = 0, max((math.hypot(*p) for p in pos.values()), default=0.0)
    for k in nodes:  # notes and anything not connected to a placed card: an outer spiral, then grow
        if k not in pos:
            loose += 1
            r, a = spread + K * (1 + 0.5 * math.sqrt(loose)), loose * golden
            pos[k] = [r * math.cos(a), r * math.sin(a)]
            place([k])

    free = [k for k in nodes if k not in fixed]
    if free:
        pairs = {(e.src, e.dst) if order[e.src] < order[e.dst] else (e.dst, e.src)
                 for e in g.edges if e.src != e.dst}
        pairs = sorted(pairs, key=lambda p: (order[p[0]], order[p[1]]))
        cell, k2 = 2 * K, K * K
        steps = min(iterations, 60) if len(nodes) > 400 else iterations
        temp = K
        for step in range(steps):
            grid: dict[tuple[int, int], list[str]] = defaultdict(list)
            for k in nodes:
                grid[(int(pos[k][0] // cell), int(pos[k][1] // cell))].append(k)
            disp = {k: [0.0, 0.0] for k in free}
            for k in free:
                px, py = pos[k]
                cx, cy = int(px // cell), int(py // cell)
                sx = sy = 0.0
                for gx in (cx - 1, cx, cx + 1):
                    for gy in (cy - 1, cy, cy + 1):
                        for o in grid.get((gx, gy), ()):
                            if o == k:
                                continue
                            dx, dy = px - pos[o][0], py - pos[o][1]
                            d2 = dx * dx + dy * dy
                            if d2 < 0.01:
                                dx, dy, d2 = rng.uniform(-1, 1), rng.uniform(-1, 1), 1.0
                            if d2 < cell * cell:
                                sx += dx * k2 / d2
                                sy += dy * k2 / d2
                disp[k][0] += sx
                disp[k][1] += sy
            for a, b in pairs:
                dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
                d = math.hypot(dx, dy)
                fx, fy = dx * d / K, dy * d / K
                if a in disp:
                    disp[a][0] -= fx
                    disp[a][1] -= fy
                if b in disp:
                    disp[b][0] += fx
                    disp[b][1] += fy
            moved = 0.0
            for k in free:
                dx, dy = disp[k]
                d = math.hypot(dx, dy)
                if d > 0:
                    s = min(d, temp) / d
                    pos[k][0] += dx * s
                    pos[k][1] += dy * s
                    moved = max(moved, d * s)
            if moved < 0.5:
                break
            temp = max(K * (1 - (step + 1) / steps), 1.0)
    return {k: (round(pos[k][0], 1), round(pos[k][1], 1)) for k in nodes}


# ------------------------------------------------------------------ board storage


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _case_status(db: Database, case_id: int) -> str:
    row = db.execute("SELECT status FROM cases WHERE id = ?", (case_id,)).fetchone()
    if row is None:
        raise ValueError("That case doesn't exist.")
    return row["status"]


def _require_open(db: Database, case_id: int) -> None:
    if _case_status(db, case_id) != "open":
        raise ValueError(_CLOSED)


def _clean_note(text: str) -> str:
    text = _CONTROL.sub("", str(text).replace("\r\n", "\n").replace("\r", "\n")).strip()
    if len(text) > MAX_NOTE:
        raise ValueError(f"Keep notes under {MAX_NOTE} characters.")
    return text


def _coord(value: float) -> float:
    value = float(value)
    if not math.isfinite(value):
        raise ValueError("That position isn't on the board.")
    return round(value, 1)


def _insert(conn, case_id: int, kind: str, prefix: str, **cols) -> tuple[int, str]:
    """Insert a note or link and give it its key (n:<id> / l:<id>) in the same transaction."""
    names = ", ".join(cols)
    cur = conn.execute(f"INSERT INTO board_items (case_id, kind, key, created_at, {names}) "
                       f"VALUES (?, ?, ?, ?, {', '.join('?' * len(cols))})",
                       (case_id, kind, f"{prefix}:new", _now(), *cols.values()))
    key = f"{prefix}:{cur.lastrowid}"
    conn.execute("UPDATE board_items SET key = ? WHERE id = ?", (key, cur.lastrowid))
    conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (_now(), case_id))
    return cur.lastrowid, key


def load_board(db: Database, case_id: int) -> Board:
    board = Board()
    for r in db.execute("SELECT * FROM board_items WHERE case_id = ? ORDER BY id", (case_id,)):
        if r["kind"] == "link":
            board.links.append(Link(r["id"], r["key"], r["a_key"], r["b_key"], r["text"]))
            continue
        board.positions[r["key"]] = (r["x"], r["y"])
        if r["pinned"]:
            board.pinned.add(r["key"])
        if r["kind"] == "note":
            board.notes.append(Note(r["id"], r["key"], r["x"], r["y"], r["text"], bool(r["pinned"])))
    return board


def save_positions(db: Database, case_id: int, positions: dict[str, tuple[float, float]], pinned: set[str],
                   keep: set[str] | None = None) -> None:
    """Upsert card positions and pins (allowed on closed cases too). Notes keep theirs on the note row.
    With `keep` (the current graph's keys), positions of cards no longer on the map are pruned (open cases only)."""
    is_open = _case_status(db, case_id) == "open"
    rows = [(k, round(float(x), 1), round(float(y), 1), int(k in pinned)) for k, (x, y) in positions.items()
            if math.isfinite(x) and math.isfinite(y)]
    with db.transaction() as conn:
        conn.executemany("UPDATE board_items SET x = ?, y = ?, pinned = ? WHERE case_id = ? AND kind = 'note' "
                         "AND key = ?", [(x, y, p, case_id, k) for k, x, y, p in rows if k.startswith("n:")])
        conn.executemany(
            "INSERT INTO board_items (case_id, kind, key, x, y, pinned, created_at) VALUES (?, 'pos', ?, ?, ?, ?, ?) "
            "ON CONFLICT (case_id, kind, key) DO UPDATE SET x = excluded.x, y = excluded.y, pinned = excluded.pinned",
            [(case_id, k, x, y, p, _now()) for k, x, y, p in rows if not k.startswith("n:")])
        if keep is not None and is_open:
            stale = [(case_id, r["key"]) for r in conn.execute(
                "SELECT key FROM board_items WHERE case_id = ? AND kind = 'pos'", (case_id,)) if r["key"] not in keep]
            conn.executemany("DELETE FROM board_items WHERE case_id = ? AND kind = 'pos' AND key = ?", stale)


def add_note(db: Database, case_id: int, x: float, y: float, text: str) -> Note:
    _require_open(db, case_id)
    text, x, y = _clean_note(text), _coord(x), _coord(y)
    with db.transaction() as conn:
        note_id, key = _insert(conn, case_id, "note", "n", x=x, y=y, text=text)
    return Note(note_id, key, x, y, text, False)


def update_note(db: Database, case_id: int, key: str, *, text: str | None = None, x: float | None = None,
                y: float | None = None) -> None:
    """Edit a note's text (open cases only) or move it (always allowed, like any card)."""
    row = db.execute("SELECT id FROM board_items WHERE case_id = ? AND kind = 'note' AND key = ?",
                     (case_id, key)).fetchone()
    if row is None:
        raise KeyError(key)
    updates = {}
    if text is not None:
        _require_open(db, case_id)
        updates["text"] = _clean_note(text)
    if x is not None:
        updates["x"] = _coord(x)
    if y is not None:
        updates["y"] = _coord(y)
    if not updates:
        return
    with db.transaction() as conn:
        conn.execute(f"UPDATE board_items SET {', '.join(f'{c} = ?' for c in updates)} WHERE id = ?",
                     (*updates.values(), row["id"]))
        if text is not None:
            conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (_now(), case_id))


def add_link(db: Database, case_id: int, a_key: str, b_key: str, label: str,
             valid_keys: set[str] | None = None) -> Link:
    """An analyst's own string between two cards. `valid_keys` = the current graph's keys (built if omitted)."""
    _require_open(db, case_id)
    label = " ".join(_CONTROL.sub(" ", str(label)).split())
    if len(label) > MAX_LABEL:
        raise ValueError(f"Keep the label under {MAX_LABEL} characters.")
    if a_key == b_key:
        raise ValueError("Connect two different cards.")
    if valid_keys is None:
        valid_keys = set(build_graph(db, case_id).nodes)
    if a_key not in valid_keys or b_key not in valid_keys:
        raise ValueError("Both cards must be on the map.")
    if db.execute("SELECT 1 FROM board_items WHERE case_id = ? AND kind = 'link' AND "
                  "((a_key = ? AND b_key = ?) OR (a_key = ? AND b_key = ?))",
                  (case_id, a_key, b_key, b_key, a_key)).fetchone():
        raise ValueError("These cards are already connected.")
    with db.transaction() as conn:
        link_id, key = _insert(conn, case_id, "link", "l", a_key=a_key, b_key=b_key, text=label)
    return Link(link_id, key, a_key, b_key, label)


def delete_item(db: Database, case_id: int, kind: str, key: str) -> None:
    """Delete a note (and the strings attached to it) or a link. Unknown keys are ignored."""
    if kind not in ("note", "link"):
        raise ValueError("Only notes and connections can be deleted from the map.")
    _require_open(db, case_id)
    with db.transaction() as conn:
        conn.execute("DELETE FROM board_items WHERE case_id = ? AND kind = ? AND key = ?", (case_id, kind, key))
        if kind == "note":
            conn.execute("DELETE FROM board_items WHERE case_id = ? AND kind = 'link' AND (a_key = ? OR b_key = ?)",
                         (case_id, key, key))
        conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (_now(), case_id))
