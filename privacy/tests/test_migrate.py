"""Tests for privacy/migrate.py.

The fixture is a workspace in the state an upstream /setup leaves it: the
stock templates with the user's real values (here: the synthetic CANARY)
written into the profile files, CLAUDE.md, main_example.tex and a draft.
Oracle: after --apply no value is left in any target, the output never
contains a value, documents/ is untouched, a second run changes nothing,
and (inside the gate) the migrated draft finalizes back to the real values.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from privacy import finalize as fz
from privacy import identity as ident
from privacy import migrate as mg
from privacy import texsubst
from privacy.tests.fixtures import CANARY, TEST_PASSPHRASE, TRICKY
from privacy.tests.repo_fixture import CO_ROLE, make_app_repo

IN_GATES = os.environ.get("JOBSEARCH_GATES") == "1"
CANARY_N = ident.normalise(CANARY)
TRICKY_N = ident.normalise(TRICKY)
SKILL = ".claude/skills/job-application-assistant"


def realise(repo: Path, identity: dict) -> None:
    """Turn the token fixture into an upstream-style workspace with real values."""
    for p in [repo / "cv" / f"main_{CO_ROLE}.tex",
              repo / "cover_letters" / f"cover_{CO_ROLE}.tex"]:
        p.write_text(texsubst.substitute(p.read_text(), identity)[0])
    (repo / SKILL).mkdir(parents=True)
    (repo / SKILL / "01-candidate-profile.md").write_text(
        f"# Profile\n- **Name:** {identity['full_name']}\n"
        f"- **Contact:** {identity['email']}, tel. {identity['phone']}\n"
        f"- LinkedIn: {identity['linkedin'].replace('https://', '')}\n")
    (repo / SKILL / "05-cv-templates.md").write_text(
        "```latex\n"
        f"\\name{{{texsubst.escape(identity['first_name'])}}}"
        f"{{{texsubst.escape(identity['last_name'])}}}\n"
        f"\\phone[mobile]{{{identity['phone']}}}\n"
        f"\\email{{{texsubst.escape(identity['email'])}}}\n```\n")
    (repo / "CLAUDE.md").write_text(
        f"# Job Application Assistant for {identity['full_name']}\n"
        f"Phone without spaces: {''.join(c for c in identity['phone'] if c.isdigit())}\n"
        f"Email in caps: {identity['email'].upper()}\n"
        f"Ask {identity['first_name']} before sending.\n")
    (repo / "documents" / "cv").mkdir(parents=True)
    (repo / "documents" / "cv" / "my_cv.md").write_text(identity["full_name"] + "\n")


def run_migrate(repo: Path, *extra: str) -> tuple[int, str]:
    buf = io.StringIO()
    with mock.patch("sys.stdin", io.StringIO(TEST_PASSPHRASE + "\n")), redirect_stdout(buf):
        rc = mg.main(["--repo", str(repo), "--passphrase-stdin", *extra])
    return rc, buf.getvalue()


def values_in(text: str, identity: dict) -> list[str]:
    """Value forms (raw, lowercase, TeX-escaped, digits-only phone) found in
    text. First or last name alone is excluded: migrate leaves those on
    purpose and reports them."""
    low = text.lower()
    alone = {ident.TOKENS["first_name"], ident.TOKENS["last_name"]}
    found = [form for form, token in fz.redaction_pairs(identity)
             if token not in alone and form.lower() in low]
    digits = "".join(c for c in identity["phone"] if c.isdigit())
    if digits[-8:] in "".join(c for c in text if c.isdigit()):
        found.append("phone digits")
    return found


class PhonePattern(unittest.TestCase):
    def test_spellings(self):
        import re
        pat = re.compile(mg.phone_pattern("+45 99 88 77 66"))
        for s in ("+45 99 88 77 66", "+4599887766", "99887766", "99 88 77 66",
                  "+45 9988 7766", "(+45) 99-88-77-66"):
            self.assertTrue(pat.search(f"tel {s}."), s)

    def test_no_partial_match(self):
        import re
        pat = re.compile(mg.phone_pattern("+45 99 88 77 66"))
        self.assertIsNone(pat.search("id 1998877661"))
        self.assertIsNone(pat.search("9988776"))


class Migrate(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.base)

    def workspace(self, identity=CANARY, normalised=CANARY_N) -> Path:
        repo = make_app_repo(self.base, identity, TEST_PASSPHRASE)
        realise(repo, normalised)
        return repo

    def targets_text(self, repo: Path) -> str:
        return "\n".join(p.read_text() for p in mg.target_files(repo))

    def test_dry_run_changes_nothing(self):
        repo = self.workspace()
        before = self.targets_text(repo)
        rc, out = run_migrate(repo)
        self.assertEqual(rc, 0)
        self.assertIn("would replace", out)
        self.assertIn("dry run", out)
        self.assertEqual(self.targets_text(repo), before)

    def test_apply_removes_every_value(self):
        for identity, norm in ((CANARY, CANARY_N), (TRICKY, TRICKY_N)):
            with self.subTest(identity=norm["first_name"]):
                shutil.rmtree(self.base)
                self.base.mkdir()
                repo = self.workspace(identity, norm)
                self.assertTrue(values_in(self.targets_text(repo), norm))
                rc, out = run_migrate(repo, "--apply")
                self.assertEqual(rc, 0, out)
                self.assertEqual(values_in(self.targets_text(repo), norm), [], out)
                self.assertIn("ZZNAMEZZ", (repo / "CLAUDE.md").read_text())
                self.assertIn("\\name{ZZFIRSTNAMEZZ}{ZZLASTNAMEZZ}",
                              (repo / SKILL / "05-cv-templates.md").read_text())

    def test_output_never_contains_values(self):
        repo = self.workspace()
        for extra in ((), ("--apply",)):
            _, out = run_migrate(repo, *extra)
            self.assertEqual(fz.redact(out, CANARY_N), out)
            self.assertEqual(values_in(out, CANARY_N), [])

    def test_standalone_first_name_reported_not_replaced(self):
        repo = self.workspace()
        _, out = run_migrate(repo, "--apply")
        self.assertIn("standalone first/last name(s) left in CLAUDE.md", out)
        self.assertIn(f"Ask {CANARY_N['first_name']} before", (repo / "CLAUDE.md").read_text())

    def test_documents_untouched(self):
        repo = self.workspace()
        run_migrate(repo, "--apply")
        self.assertEqual((repo / "documents/cv/my_cv.md").read_text(),
                         CANARY_N["full_name"] + "\n")

    def test_idempotent(self):
        repo = self.workspace()
        run_migrate(repo, "--apply")
        after = self.targets_text(repo)
        _, out = run_migrate(repo, "--apply")
        self.assertIn("nothing to replace", out)
        self.assertEqual(self.targets_text(repo), after)

    def test_symlinked_target_skipped(self):
        repo = self.workspace()
        outside = self.base / "outside.md"
        outside.write_text(CANARY_N["email"])
        (repo / "AGENTS.md").symlink_to(outside)
        run_migrate(repo, "--apply")
        self.assertEqual(outside.read_text(), CANARY_N["email"])

    def test_git_history_warning(self):
        repo = self.workspace()
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
        for cmd in (["init", "-q"], ["add", "CLAUDE.md"], ["commit", "-qm", "x"]):
            subprocess.run(["git", "-C", str(repo), *cmd], check=True, env=env,
                           capture_output=True)
        _, out = run_migrate(repo, "--apply")
        self.assertIn("occur in 1 git commit", out)

    def test_refuses_inside_launcher(self):
        repo = self.workspace()
        with mock.patch.dict(os.environ, {fz.JAIL_MARKER: "1"}):
            rc, _ = run_migrate(repo, "--apply")
        self.assertEqual(rc, 2)


@unittest.skipUnless(IN_GATES, "compiles in a bwrap jail: runs inside jobsearch-gates")
class MigrateThenFinalize(unittest.TestCase):
    def test_round_trip(self):
        base = Path(tempfile.mkdtemp())
        try:
            repo = make_app_repo(base, CANARY, TEST_PASSPHRASE)
            realise(repo, CANARY_N)
            self.assertEqual(run_migrate(repo, "--apply")[0], 0)
            buf = io.StringIO()
            with mock.patch("sys.stdin", io.StringIO(TEST_PASSPHRASE + "\n")), \
                 redirect_stdout(buf):
                rc = fz.main([CO_ROLE, "--repo", str(repo), "--passphrase-stdin"])
            self.assertEqual(rc, 0, buf.getvalue())
            _, text, _, uris = fz.pdf_facts(repo / "private/final" / CO_ROLE / "cv.pdf")
            self.assertIn(fz.fold(CANARY_N["email"]), fz.fold(text))
            self.assertIn(CANARY_N["linkedin"], uris)
        finally:
            shutil.rmtree(base)


if __name__ == "__main__":
    unittest.main()
