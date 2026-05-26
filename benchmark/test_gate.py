#!/usr/bin/env python3
"""
Unit tests for the topology gate (arch-rules parsing + invariant evaluation).

Usage:
  python benchmark/test_gate.py

Tests the gate's two parsers and three findings paths against a synthetic
arch-rules doc + graph — no git repo needed for the parse/layer/forbidden/
hotspot checks (the core→delta baseline diff is exercised separately, it
needs a real repo + worktree).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from codeindex import gate as G  # noqa: E402

PASS = "\033[32m✓\033[0m"
FAIL = "\033[31m✗\033[0m"


class Results:
    def __init__(self):
        self.passed = self.failed = 0

    def check(self, label, cond, detail=""):
        if cond:
            self.passed += 1; print(f"  {PASS} {label}")
        else:
            self.failed += 1; print(f"  {FAIL} {label}" + (f"\n      {detail}" if detail else ""))

    def summary(self):
        print(f"\n{self.passed}/{self.passed + self.failed} passed")
        return 0 if self.failed == 0 else 1


# A synthetic arch-rules block in the exact shape we author (multi-line lists,
# comments, the prettier-reflowed `key:\n  [` form — all the parser edge cases).
ARCH_DOC = """# arch
## Arch-rules
```yaml
layers:
  # rank 0 — base leaves
  - rank: 0
    modules:
      [
        packages/schema,
        packages/contract,
      ]
  - rank: 1
    modules: [packages/db]
  - rank: 2
    modules: [packages/authz]
  - rank: 3
    modules: [apps/web, apps/spa]
  - rank: 5
    modules: [tools/]
forbidden:
  - from: apps/spa
    to: [packages/db]
    why: 'client must not reach the db layer'
hotspot:
  warn: 100000
```
"""


def make_rules(tmp: Path) -> G.ArchRules:
    doc = tmp / "audit-arch.md"
    doc.write_text(ARCH_DOC)
    return G.ArchRules.from_doc(doc)


def main():
    r = Results()
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        rules = make_rules(Path(td))

    print("Arch-rules parsing (incl. prettier-reflowed multi-line lists):")
    r.check("rank 0 leaves parsed (schema, contract)",
            rules.rank("packages/schema/src/x.ts") == 0 and rules.rank("packages/contract/src/x.ts") == 0,
            f"schema={rules.rank('packages/schema/src/x.ts')}")
    r.check("rank 2 authz above rank 1 db (the 6e5680f-shape ordering)",
            rules.rank("packages/authz/src/x.ts") == 2 and rules.rank("packages/db/src/x.ts") == 1)
    r.check("prefix rank (tools/) resolves",
            rules.rank("tools/scripts/x.ts") == 5)
    r.check("forbidden rule parsed (1 entry, not leaked from layers)",
            len(rules.forbidden) == 1 and rules.forbidden[0]["from"] == "apps/spa")
    r.check("hotspot warn parsed",
            rules.hotspot_warn == 100000)

    print("\nLayer-containment (upward edge = block):")
    r.check("db → schema is legal (1→0, down)",
            rules.rank("packages/db/x.ts") >= rules.rank("packages/schema/x.ts"))
    r.check("authz → db is legal (2→1, down)",
            rules.rank("packages/authz/x.ts") >= rules.rank("packages/db/x.ts"))
    r.check("schema → authz would be illegal (0→2, UP)",
            rules.rank("packages/schema/x.ts") < rules.rank("packages/authz/x.ts"))

    print("\nForbidden edge (overrides rank):")
    r.check("spa → db is forbidden even though rank 3→1 is 'down'",
            rules.forbidden_hit("apps/spa/src/x.tsx", "packages/db/src/index.ts") is not None,
            "the §18/§32 trust boundary: rank says down-legal, forbidden says no")
    r.check("spa → contract is NOT forbidden",
            rules.forbidden_hit("apps/spa/src/x.tsx", "packages/contract/src/index.ts") is None)

    print("\nHotspot scoring — fan_in × exports × churn (the metric, not a gate-run):")
    # healthy seam: huge fan-in, FEW exports, no churn → LOW score
    seam = 108 * 1 * (1 + 1)             # cn.ts-shaped: 108 importers, 1 export
    god  = 209 * 33 * (15 + 1)           # import.ts-shaped: 33 exports, churning
    r.check("thin seam (108 fan-in × 1 export) scores below warn",
            seam < rules.hotspot_warn, f"seam={seam}")
    r.check("junk drawer (209 fan-in × 33 exports × churn) scores above warn",
            god >= rules.hotspot_warn, f"god={god}")
    # export-count is the gaming-resistance property: a cosmetic split that keeps
    # the same exports (re-export barrel) does NOT lower the count → score holds.

    sys.exit(r.summary())


if __name__ == "__main__":
    main()
