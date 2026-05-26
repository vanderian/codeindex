"""
Topology gate — deterministic, no-LLM evaluation of a commit's graph delta
against a repo's machine-readable arch-rules.

The gate answers the closed question "is this change architecturally legal?"
with one true answer every run. It reads arch-rules (layer ranks + forbidden
edges + hotspot threshold) from a repo doc, builds/reads the dependency graph,
and evaluates the touched files of a commit (the delta) against these checks:

  1. layer-containment : BLOCK — no delta edge points UP the layer-rank stack
  2. forbidden-edge     : BLOCK — no delta edge matches a §-backed forbidden rule
  3. hotspot            : WARN (never blocks) when a delta file is a
                          heavily-depended-on, MANY-export, churning module
                          (fan_in × exports × churn) — a low-cohesion junk drawer.
                          Raw blast does NOT gate: high fan-in to a thin stable
                          seam (few exports) is healthy (Martin's stable-dependency
                          rule). Export-count beats LOC: it's the cohesion signal
                          and can't be cosmetically gamed (a re-export shim just
                          moves the high count to the barrel).
  4. core→delta         : WARN — the trunk gained a NEW dependency on the delta
                          files (baseline graph vs post-commit graph — the only
                          place two snapshots are compared; opt-in via --baseline)

Only layer-containment + forbidden-edge BLOCK (exit 1). hotspot + core→delta are
advisory WARNs — the human ratifies; the gate never auto-relaxes itself. Cycle
detection is intentionally NOT here — dep-cruiser/madge solve it deterministically
without the graph; duplicating it would be a worse implementation of a solved
problem.

GAMING CAVEAT (load-bearing — read before changing hotspot's role):
layer-containment + forbidden-edge are BINARY TOPOLOGICAL FACTS — an import edge
either exists or it doesn't. To make the violation go away you must actually
remove the illegal dependency; gaming == fixing. Safe to hard-gate.

hotspot is a CONTINUOUS PROXY (fan_in × loc × churn) for an unmeasurable thing
("is this module over-coupled?"). A proxy can be satisfied WITHOUT satisfying
what it proxies: an optimizer can split a file cosmetically (a re-export shim
that lowers per-file LOC while leaving transitive coupling identical) and the
score drops while the architecture gets WORSE. Against an autonomous agent that
treats the metric as a target, hard-gating hotspot is worse than no gate — it
manufactures green-but-wrong (Goodhart). So:
  - hotspot is WARN-only, and surfaced MONITOR→HUMAN only — never handed to the
    impl/AFK agent as a gate to clear. The agent gets `impact` (read-only blast
    thermometer), not a hotspot pass/fail. It can't optimize against a signal it
    never sees. The goal of hotspot is IDENTIFICATION (name the god-object — an
    easy refactor once named), not clearance.
  - the metric IDENTIFIES; the human RATIFIES the fix. Never let the gate certify
    that a hotspot was "addressed" — certification is the step an optimizer games.
  - future hardening (principled, not yet built): a real split SEVERS transitive
    edges (consumers' reach drops); a cosmetic shim leaves transitive coupling
    FLAT. Comparing LOC-drop vs transitive-coupling-delta separates the two — but
    a clever per-domain-barrel shim blurs even that, so it informs the human, it
    doesn't auto-certify. Measure to find; let the human judge the fix.

Cycle detection (the brief's 4th invariant) is intentionally NOT here — it is
solved deterministically by dep-cruiser/madge without the graph; duplicating it
would add a worse implementation of a solved problem.

Arch-rules live in the CONSUMING repo, never in this tool — the gate is a
generic evaluator; the repo owns its topology.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

INTERNAL_PREFIXES = ("apps/", "packages/", "tools/")


# ── arch-rules parsing ────────────────────────────────────────────────────────
# arch-rules are a fenced ```yaml block inside a repo doc (e.g. audit-arch.md).
# We extract that block and parse it. PyYAML if available, else a tiny stdlib
# parser for the exact shape we emit (keeps the tool's zero-required-deps).

_YAML_BLOCK_RE = re.compile(r"```yaml\n(.*?)\n```", re.DOTALL)


def _extract_yaml_block(doc_text: str) -> "str | None":
    """Return the FIRST fenced yaml block that contains a 'layers:' key."""
    for m in _YAML_BLOCK_RE.finditer(doc_text):
        block = m.group(1)
        if "layers:" in block:
            return block
    return None


def _parse_arch_rules(block: str) -> dict:
    try:
        import yaml  # optional
        return yaml.safe_load(block)
    except ImportError:
        return _parse_arch_rules_stdlib(block)


def _split_list(val: str) -> list:
    """Parse an inline [a, b, c] list (possibly across the cleaned single line)."""
    val = val.strip()
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1]
        return [x.strip() for x in inner.split(",") if x.strip()]
    return [val] if val else []


def _parse_arch_rules_stdlib(block: str) -> dict:
    """
    Minimal parser for the arch-rules shape we author. Handles:
      layers: list of {rank: int, modules: [..]}  (modules may span lines)
      forbidden: list of {from: str, to: [..], why: str}
      blast_budget: {warn: int, block: int}
    Strips '#' comments. Not a general YAML parser — just our schema.
    """
    # join continued [ ... ] lists onto one logical line, strip comments
    lines = []
    for raw in block.splitlines():
        # drop trailing comments that aren't inside quotes (our values don't use #)
        line = re.sub(r"\s+#.*$", "", raw.rstrip())
        if line.strip():
            lines.append(line)
    text = "\n".join(lines)
    # join a bare "key:" with a bracketed block on the following line(s):
    #   modules:            modules: [packages/schema, ...]
    #     [          →
    #       packages/schema,
    #     ]
    text = re.sub(r"(:)\s*\n\s*\[", r"\1 [", text)
    # collapse multi-line [ ... ] to single line
    text = re.sub(r"\[\s*\n\s*", "[", text)
    text = re.sub(r",\s*\n\s*", ", ", text)
    text = re.sub(r",?\s*\n\s*\]", "]", text)

    out: dict = {"layers": [], "forbidden": [], "hotspot": {}}
    section = None
    cur: dict = {}

    def flush():
        nonlocal cur
        if cur:
            if "rank" in cur:
                out["layers"].append(cur)
            elif "from" in cur:
                out["forbidden"].append(cur)
        cur = {}

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("layers:"):
            flush(); section = "layers"; continue
        if stripped.startswith("forbidden:"):
            flush(); section = "forbidden"; continue
        if stripped.startswith("hotspot:"):
            flush(); section = "hotspot"; continue
        if section == "layers":
            if stripped.startswith("- rank:"):
                flush()
                cur = {"rank": int(stripped.split(":")[1].strip())}
            elif stripped.startswith("modules:"):
                cur["modules"] = _split_list(stripped.split("modules:", 1)[1])
        elif section == "forbidden":
            if stripped.startswith("- from:"):
                flush()
                cur = {"from": stripped.split("from:", 1)[1].strip()}
            elif stripped.startswith("to:"):
                cur["to"] = _split_list(stripped.split("to:", 1)[1])
            elif stripped.startswith("why:"):
                cur["why"] = stripped.split("why:", 1)[1].strip().strip("'\"")
        elif section == "hotspot":
            if stripped.startswith("warn:"):
                out["hotspot"]["warn"] = int(stripped.split(":")[1].strip())
    flush()
    return out


# ── layer model ───────────────────────────────────────────────────────────────
@dataclass
class ArchRules:
    rank_of_module: dict = field(default_factory=dict)   # "packages/db" -> 1
    rank_prefixes: list = field(default_factory=list)    # [("tools/", 5)]
    forbidden: list = field(default_factory=list)        # [{"from":..,"to":[..],"why":..}]
    hotspot_warn: int = 150000                           # hotspot WARN threshold

    @classmethod
    def from_doc(cls, doc_path: Path) -> "ArchRules":
        block = _extract_yaml_block(doc_path.read_text(errors="replace"))
        if block is None:
            raise ValueError(f"No ```yaml arch-rules block (with 'layers:') in {doc_path}")
        data = _parse_arch_rules(block)
        rank_of = {}
        prefixes = []
        for layer in data.get("layers", []):
            r = layer["rank"]
            for mod in layer.get("modules", []):
                if mod.endswith("/"):
                    prefixes.append((mod, r))
                else:
                    rank_of[mod] = r
        return cls(
            rank_of_module=rank_of,
            rank_prefixes=sorted(prefixes, key=lambda kv: len(kv[0]), reverse=True),
            forbidden=data.get("forbidden", []),
            hotspot_warn=int(data.get("hotspot", {}).get("warn", 150000)),
        )

    def rank(self, path: str) -> "int | None":
        mod = _top2(path)
        if mod in self.rank_of_module:
            return self.rank_of_module[mod]
        for pre, r in self.rank_prefixes:
            if path.startswith(pre) or mod.startswith(pre):
                return r
        return None  # unranked — gate reports as a coverage gap, not a pass

    def forbidden_hit(self, src: str, tgt: str) -> "str | None":
        for rule in self.forbidden:
            if src.startswith(rule["from"]):
                for t in rule.get("to", []):
                    if tgt.startswith(t):
                        return rule.get("why", f"{rule['from']} → {t}")
        return None


def _top2(p: str) -> str:
    parts = p.split("/")
    return "/".join(parts[:2]) if len(parts) > 1 else p


# ── graph helpers ─────────────────────────────────────────────────────────────
def _load_graph(graph_path: Path):
    d = json.loads(graph_path.read_text())
    edges = [(l["source"], l["target"]) for l in d.get("links", []) if isinstance(l, dict)]
    nodes = {n["id"]: n for n in d.get("nodes", [])}
    return edges, nodes


def _commit_files(repo: Path, sha: str) -> list:
    out = subprocess.check_output(
        ["git", "-C", str(repo), "show", "--stat", "--format=", sha]).decode()
    files = []
    for line in out.split("\n"):
        if "|" in line:
            f = line.split("|")[0].strip()
            if f.endswith((".ts", ".tsx", ".js", ".jsx", ".css", ".sql")):
                files.append(f)
    return files


def load_export_counts(graph_path: Path) -> dict:
    """
    Export-count per file from the sibling symbolindex.json (built by
    `codeindex symbols`). Returns {file: n_exported_symbols}. Empty dict if the
    symbol index is absent — callers fall back to a 1× multiplier so the score
    degrades to fan_in × churn rather than crashing.
    """
    sym_path = graph_path.parent / "symbolindex.json"
    if not sym_path.exists():
        return {}
    try:
        data = json.loads(sym_path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    out = {}
    for f, syms in data.get("file_symbols", {}).items():
        out[f] = sum(1 for s in syms if s.get("exported"))
    return out


def hotspot_score(repo: Path, path: str, nodes: dict, exports: dict,
                  min_fan_in: int = 20):
    """
    Hotspot score for a file = fan_in × exports × (churn_90d + 1).

    Export-count (not LOC) is the surface signal: a cohesive seam has FEW exports
    however many importers (cn.ts = 1 export / 108 importers — healthy); a junk
    drawer has MANY exports bundled in one file (import.ts = 33 exports across 6
    CSV domains — the smell). Export-count is also gaming-resistant: you cannot
    lower it with a cosmetic re-export shim (the shim's barrel then carries the
    high count), unlike LOC which a shim trivially reduces.

    Returns (score, fan_in, exports, churn). score is None when fan_in < min_fan_in
    (only heavily-depended-on files can be a hotspot). Shared by the gate (INV3)
    and the standalone `codeindex hotspots` command.
    """
    n = nodes.get(path, {})
    fan_in = n.get("direct_dependents", 0) + n.get("transitive_dependents", 0)
    n_exports = exports.get(path, 1) or 1  # fallback 1× when no symbol index
    if fan_in < min_fan_in:
        return None, fan_in, n_exports, 0
    churn = _churn_90d(repo, path)
    return fan_in * n_exports * (churn + 1), fan_in, n_exports, churn


def _churn_90d(repo: Path, path: str) -> int:
    """Commit count touching a file in the last 90 days (the churn signal)."""
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo), "log", "--oneline", "--since=90.days", "--", path],
            stderr=subprocess.DEVNULL).decode()
        return out.count("\n")
    except subprocess.CalledProcessError:
        return 0


def _baseline_graph(repo: Path, sha: str, analyze_fn) -> "list | None":
    """
    Build the graph as it was at sha^ (the commit's parent) for the core→delta
    diff. Uses a temp worktree so the working tree is untouched. Returns the
    edge list, or None if a baseline can't be built (e.g. root commit).
    """
    import tempfile
    try:
        parent = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", f"{sha}^"],
            stderr=subprocess.DEVNULL).decode().strip()
    except subprocess.CalledProcessError:
        return None
    with tempfile.TemporaryDirectory() as td:
        wt = Path(td) / "wt"
        try:
            subprocess.check_output(
                ["git", "-C", str(repo), "worktree", "add", "--detach", str(wt), parent],
                stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            return None
        try:
            edges = analyze_fn(wt)
        finally:
            subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(wt)],
                           stderr=subprocess.DEVNULL)
    return edges


# ── the gate ──────────────────────────────────────────────────────────────────
@dataclass
class Finding:
    invariant: str
    severity: str   # block | warn | info
    detail: str


def evaluate(repo: Path, sha: str, graph_path: Path, rules: ArchRules,
             analyze_fn=None) -> list:
    """Evaluate a commit's delta. Returns a list of Findings (empty = clean)."""
    edges, nodes = _load_graph(graph_path)
    edges_by_src: dict = {}
    for s, t in edges:
        edges_by_src.setdefault(s, []).append(t)
    node_ids = set(nodes)

    files = _commit_files(repo, sha)
    delta = [f for f in files if f in node_ids]
    findings: list = []

    # delta cross-module edges
    delta_edges = []
    for f in delta:
        fm = _top2(f)
        for t in edges_by_src.get(f, []):
            if t.startswith(INTERNAL_PREFIXES) and _top2(t) != fm:
                delta_edges.append((f, t))

    # INV1 + INV2 (forbidden) — per edge
    for s, t in delta_edges:
        why = rules.forbidden_hit(s, t)
        if why:
            findings.append(Finding("forbidden-edge", "block",
                                     f"{s} → {t}  [{why}]"))
            continue
        rs, rt = rules.rank(s), rules.rank(t)
        if rs is None:
            findings.append(Finding("coverage", "warn",
                                     f"{s} has no arch-rule rank (unranked module)"))
        elif rt is not None and rt > rs:
            findings.append(Finding("layer-containment", "block",
                                     f"{s} → {t}  (rank {rs}→{rt}, edge points UP the stack)"))

    # INV3 — hotspot (WARN only; raw blast does NOT gate — high fan-in to a
    # thin stable seam is healthy). Score = fan_in × exports × (churn_90d + 1).
    exports = load_export_counts(graph_path)
    for f in delta:
        score, fan_in, n_exp, churn = hotspot_score(repo, f, nodes, exports)
        if score is not None and score >= rules.hotspot_warn:
            findings.append(Finding(
                "hotspot", "warn",
                f"{f}  (fan-in {fan_in} × {n_exp} exports × churn {churn} = {score}) "
                f"— heavily-depended-on, many exports, churning; low cohesion, consider splitting"))

    # INV4 — core→delta (baseline vs post-commit; only if analyze_fn given)
    if analyze_fn is not None:
        base = _baseline_graph(repo, sha, analyze_fn)
        if base is not None:
            delta_set = set(delta)
            base_set = set(base)
            # NEW edges into delta files that didn't exist at the parent
            new_into_delta = [(s, t) for (s, t) in edges
                              if t in delta_set and s not in delta_set
                              and s.startswith(INTERNAL_PREFIXES)
                              and (s, t) not in base_set]
            for s, t in new_into_delta:
                findings.append(Finding("core→delta", "warn",
                                        f"{s} NEWLY depends on {t} — trunk gained a dependency on the delta"))

    return findings
