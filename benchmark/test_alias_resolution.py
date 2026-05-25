#!/usr/bin/env python3
"""
Unit tests for workspace-alias resolution in the JS/TS analyzer.

Usage:
  python benchmark/test_alias_resolution.py

Builds a synthetic monorepo in a temp dir (tsconfig `paths` + a vite
`resolve.alias` + two internal packages), runs the analyzer, and asserts that
aliased imports like `@scope/pkg` and `@app/foo` resolve to internal repo files
rather than collapsing to opaque external package nodes.

Why this matters: monorepos remap bare specifiers (TS path aliases, vite/webpack
aliases) to in-repo source. Without alias resolution every cross-package import
becomes an external node and cross-package edges — the ones a layer-boundary
check needs — are invisible.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# Import the analyzer from the repo (benchmark/ sits next to codeindex/)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from codeindex.analyzers import js_analyzer  # noqa: E402

PASS = "\033[32m✓\033[0m"
FAIL = "\033[31m✗\033[0m"


class Results:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def check(self, label: str, condition: bool, detail: str = "") -> None:
        if condition:
            self.passed += 1
            print(f"  {PASS} {label}")
        else:
            self.failed += 1
            print(f"  {FAIL} {label}" + (f"\n      {detail}" if detail else ""))

    def summary(self) -> int:
        total = self.passed + self.failed
        print(f"\n{self.passed}/{total} checks passed")
        return 0 if self.failed == 0 else 1


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def build_fixture(root: Path) -> None:
    """A minimal monorepo exercising both alias shapes."""
    # Root tsconfig with exact + subpath path aliases (the @clubschedule shape)
    write(root / "tsconfig.json", """{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@scope/contract": ["./packages/contract/src/index.ts"],
      "@scope/db": ["./packages/db/src/index.ts"],
      "@scope/db/sub": ["./packages/db/src/sub.ts"]
    }
  }
}
""")
    # App vite config with a prefix alias (the @app -> ../app/src shape)
    write(root / "apps/web/vite.config.ts", """import { defineConfig } from 'vite'
import { fileURLToPath } from 'node:url'
export default defineConfig({
  resolve: {
    alias: {
      '@app': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
})
""")
    # Internal packages (alias targets)
    write(root / "packages/contract/src/index.ts", "export type Club = { id: string }\n")
    write(root / "packages/db/src/index.ts", "export function withTx() {}\n")
    write(root / "packages/db/src/sub.ts", "export const SUB = 1\n")

    # Consumer files using the aliases
    write(root / "apps/web/src/route.ts", """import { Club } from '@scope/contract'
import { withTx } from '@scope/db'
import { SUB } from '@scope/db/sub'
import { helper } from '@app/util'
export const r = (c: Club) => withTx()
""")
    write(root / "apps/web/src/util.ts", "export function helper() {}\n")
    # A genuinely external import — must STAY external, not be mis-resolved
    write(root / "apps/web/src/ext.ts", "import React from 'react'\nexport default React\n")


def edges_from(links_map: dict, source_suffix: str):
    """Return target ids for edges whose source ends with source_suffix."""
    return {t for (s, t), _ in links_map.items() if s.endswith(source_suffix)}


def main() -> None:
    r = Results()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        build_fixture(root)

        nodes, external, links_map, meta = js_analyzer.analyze(root, {})
        route_targets = edges_from(links_map, "apps/web/src/route.ts")
        ext_targets = edges_from(links_map, "apps/web/src/ext.ts")
        ext_ids = {e["id"] for e in external}

        print("Alias resolution:")
        r.check(
            "tsconfig exact alias @scope/contract → packages/contract/src/index.ts",
            "packages/contract/src/index.ts" in route_targets,
            f"route edges: {sorted(route_targets)}",
        )
        r.check(
            "tsconfig exact alias @scope/db → packages/db/src/index.ts",
            "packages/db/src/index.ts" in route_targets,
            f"route edges: {sorted(route_targets)}",
        )
        r.check(
            "tsconfig subpath alias @scope/db/sub → packages/db/src/sub.ts (longest-prefix wins)",
            "packages/db/src/sub.ts" in route_targets,
            f"route edges: {sorted(route_targets)}",
        )
        r.check(
            "vite prefix alias @app/util → apps/web/src/util.ts",
            "apps/web/src/util.ts" in route_targets,
            f"route edges: {sorted(route_targets)}",
        )

        print("\nNegative cases (must NOT over-resolve):")
        r.check(
            "external import 'react' stays external (not mis-resolved internally)",
            "react" in ext_ids and "react" in ext_targets,
            f"external ids: {sorted(ext_ids)}; ext.ts edges: {sorted(ext_targets)}",
        )
        r.check(
            "no alias target leaked into external node set",
            not (ext_ids & {"@scope/contract", "@scope/db", "@app"}),
            f"external ids: {sorted(ext_ids)}",
        )

    sys.exit(r.summary())


if __name__ == "__main__":
    main()
