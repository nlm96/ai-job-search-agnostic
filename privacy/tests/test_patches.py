"""The upstream-spec patch and the agent rules it points to.

The patch adds one pointer line to CLAUDE.md and three command specs. Oracles:
it applies to the current upstream files; with it applied, upstream's own
CI checks (lint_skills, security_guards, the unittest suite) still pass;
and the rules name every token the identity store knows.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from privacy import identity as ident

ROOT = Path(__file__).resolve().parent.parent.parent
PATCHES = sorted((ROOT / "privacy" / "patches").glob("*.patch"))
RULES = ROOT / "privacy" / "AGENT-RULES.md"
PATCHED = ("CLAUDE.md", ".claude/commands/apply.md",
           ".claude/commands/setup.md", ".claude/commands/reset.md")
POINTER = "first read and follow `privacy/AGENT-RULES.md`"
IN_GATES = os.environ.get("JOBSEARCH_GATES") == "1"


def git(*args, cwd=ROOT, check=True):
    return subprocess.run(["git", "-c", "core.fsmonitor=", *args], cwd=cwd,
                          capture_output=True, text=True, check=check)


class Rules(unittest.TestCase):
    def test_every_token_documented(self):
        text = RULES.read_text()
        for token in ident.TOKENS.values():
            self.assertIn(f"`{token}`", text)

    def test_finalize_and_identity_commands_named(self):
        text = RULES.read_text()
        self.assertIn("privacy/bin/finalize <company>_<role>", text)
        self.assertIn("privacy/bin/identity init", text)
        self.assertIn("private/final/", text)


class ForkOwnedPointers(unittest.TestCase):
    # AGENTS.md is guarded by upstream's framework_version check, so the
    # instructions for Codex (AGENTS.override.md replaces AGENTS.md) and for
    # Gemini-family agents (GEMINI.md) live in fork-owned files.
    OWNED = ("AGENTS.override.md", "GEMINI.md")

    def test_owned_files_point_to_rules_and_agents_md(self):
        for name in self.OWNED:
            text = (ROOT / name).read_text()
            self.assertIn(POINTER, text, name)
            self.assertIn("`AGENTS.md`", text, name)

    def test_inline_token_list_matches_identity_store(self):
        for name in self.OWNED:
            text = (ROOT / name).read_text()
            for token in ident.TOKENS.values():
                self.assertIn(f"`{token}`", text, f"{name}: {token}")

    def test_agents_md_untouched(self):
        self.assertEqual(git("diff", "--quiet", "HEAD", "--", "AGENTS.md",
                             check=False).returncode, 0)


class Patch(unittest.TestCase):
    def test_patches_touch_only_the_pointer(self):
        text = "".join(p.read_text() for p in PATCHES)
        added = [l for l in text.splitlines() if l.startswith("+") and not l.startswith("+++")]
        self.assertEqual(len([l for l in added if POINTER in l]), len(PATCHED))
        self.assertTrue(all(POINTER in l or l == "+" for l in added), added)
        removed = [l for l in text.splitlines() if l.startswith("-") and not l.startswith("---")]
        self.assertEqual(removed, [])

    def test_applies_to_current_tree_or_is_applied(self):
        for patch in PATCHES:
            r = git("apply", "--check", str(patch), check=False)
            if r.returncode:
                already = git("apply", "--check", "--reverse", str(patch), check=False)
                self.assertEqual(already.returncode, 0, f"{patch.name}: {r.stderr}")


@unittest.skipUnless(IN_GATES, "runs upstream CI on a patched clone inside jobsearch-gates")
class PatchedUpstreamStillPasses(unittest.TestCase):
    def test_upstream_checks(self):
        base = Path(tempfile.mkdtemp())
        try:
            clone = base / "repo"
            git("clone", "-q", "--no-hardlinks", str(ROOT), str(clone))
            for patch in PATCHES:
                if git("apply", "--check", str(patch), cwd=clone, check=False).returncode == 0:
                    git("apply", str(patch), cwd=clone)
            for rel in PATCHED:
                self.assertIn(POINTER, (clone / rel).read_text(), rel)
            for cmd in (["tools/lint_skills.py"], ["tools/security_guards.py"],
                        ["tools/check_framework_version.py"],
                        ["-m", "unittest", "discover", "-s", "tests", "-t", "."]):
                r = subprocess.run([sys.executable, *cmd], cwd=clone,
                                   capture_output=True, text=True, timeout=600)
                self.assertEqual(r.returncode, 0, f"{cmd}:\n{r.stdout[-2000:]}{r.stderr[-2000:]}")
        finally:
            shutil.rmtree(base)


if __name__ == "__main__":
    unittest.main()
