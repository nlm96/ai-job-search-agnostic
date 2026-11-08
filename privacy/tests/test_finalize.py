"""Tests for privacy/finalize.py.

Unit tests run anywhere. The build tests compile real PDFs in finalize's
bubblewrap jail, so they run only inside jobsearch-gates. Their oracles:
the real values must be in the PDF (text layer, links), no token may be
left, nothing finalize prints may contain an identity value, and a hostile
draft must not get real values or outside files anywhere else.
"""

from __future__ import annotations

import io
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from privacy import finalize as fz
from privacy import identity as ident
from privacy.tests.fixtures import CANARY, TEST_PASSPHRASE, TRICKY
from privacy.tests.repo_fixture import CO_ROLE, make_app_repo

IN_GATES = os.environ.get("JOBSEARCH_GATES") == "1"
CANARY_N = ident.normalise(CANARY)
TRICKY_N = ident.normalise(TRICKY)


def run_finalize(repo: Path, *extra: str, passphrase: str = TEST_PASSPHRASE,
                 co_role: str = CO_ROLE) -> tuple[int, str]:
    buf = io.StringIO()
    with mock.patch("sys.stdin", io.StringIO(passphrase + "\n")), redirect_stdout(buf):
        rc = fz.main([co_role, "--repo", str(repo), "--passphrase-stdin", *extra])
    return rc, buf.getvalue()


def leaked(text: str, identity: dict) -> list[str]:
    """Identity values (in any form redact() knows) found in text."""
    low = text.lower()
    return [form for form, _ in fz.redaction_pairs(identity) if form.lower() in low]


class Redact(unittest.TestCase):
    def test_values_and_forms(self):
        text = ("Dear Qvistrup Ørnbjerg-Ældremøller, QX7CANARY@EXAMPLE.INVALID "
                "tel 4599887766 at Canaryvej 7, 9999 Testby, Denmark")
        out = fz.redact(text, CANARY_N)
        self.assertEqual(leaked(out, CANARY_N), [])
        self.assertIn("ZZNAMEZZ", out)
        self.assertIn("ZZPHONEZZ", out)

    def test_escaped_forms(self):
        out = fz.redact(r"\name{Åse-Marie}{O'Brien \& Søn} aase\_marie+jobs@example.invalid",
                        TRICKY_N)
        self.assertEqual(leaked(out, TRICKY_N), [])


class Guards(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.repo = make_app_repo(self.base, CANARY, TEST_PASSPHRASE)

    def tearDown(self):
        shutil.rmtree(self.base)

    def test_refuses_inside_launcher(self):
        with mock.patch.dict(os.environ, {fz.JAIL_MARKER: "1"}):
            rc, out = run_finalize(self.repo)
        self.assertEqual(rc, 2)
        self.assertIn("outside the agent session", out)

    def test_rejects_path_like_co_role(self):
        for bad in ("../acme", "a/b", ".hidden", ""):
            rc, _ = run_finalize(self.repo, co_role=bad)
            self.assertEqual(rc, 2, bad)

    def test_wrong_passphrase(self):
        rc, out = run_finalize(self.repo, passphrase="nope")
        self.assertEqual(rc, 2)
        self.assertIn("wrong passphrase", out)
        self.assertFalse((self.repo / "private" / "final").exists())

    def test_missing_identity(self):
        (self.repo / "private" / "identity.enc").unlink()
        rc, out = run_finalize(self.repo)
        self.assertEqual(rc, 2)
        self.assertIn("identity init", out)

    def test_custom_template_refused(self):
        guide = self.repo / fz.TEMPLATE_GUIDES[0]
        guide.parent.mkdir(parents=True)
        guide.write_text("<!-- BEGIN ACTIVE-TEMPLATE x -->")
        rc, out = run_finalize(self.repo)
        self.assertEqual(rc, 2)
        self.assertIn("custom", out)

    def test_symlinked_private_refused(self):
        shutil.move(self.repo / "private", self.base / "elsewhere")
        (self.repo / "private").symlink_to(self.base / "elsewhere")
        rc, _ = run_finalize(self.repo)
        self.assertEqual(rc, 2)

    def test_safe_mkdirs_refuses_symlink(self):
        (self.repo / "private" / "final").symlink_to(self.repo / "cv")
        with self.assertRaises(fz.FinalizeError):
            fz.safe_mkdirs(self.repo, Path("private/final/acme_dev"))


@unittest.skipUnless(IN_GATES, "compiles in a bwrap jail: runs inside jobsearch-gates")
class Build(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.base)

    def repo(self, identity=CANARY, **kw) -> Path:
        return make_app_repo(self.base, identity, TEST_PASSPHRASE, **kw)

    def assert_pass(self, repo: Path, identity: dict) -> str:
        rc, out = run_finalize(repo)
        self.assertEqual(rc, 0, out)
        self.assertEqual(leaked(out, identity), [], out)
        final = repo / "private" / "final" / CO_ROLE
        for key, pages in (("cv", 2), ("cover_letter", 1)):
            n, text, meta, uris = fz.pdf_facts(final / f"{key}.pdf")
            self.assertEqual(n, pages)
            self.assertEqual(ident.TOKEN_RE.findall(text + meta + " ".join(uris)), [])
            self.assertIn(fz.fold(identity["email"]), fz.fold(text))
            self.assertIn(fz.fold(identity["full_name"]), fz.fold(text))
            self.assertIn(f"mailto:{identity['email']}", uris)
            self.assertIn(identity["linkedin"], uris)
        _, cv_text, meta, uris = fz.pdf_facts(final / "cv.pdf")
        self.assertIn(fz.fold(identity["phone"]), fz.fold(cv_text))
        self.assertIn(identity["github"], uris)
        self.assertIn(identity["full_name"], meta)
        self.assertEqual(list((repo / "private" / ".work").iterdir()), [])
        return out

    def test_pass_canary(self):
        repo = self.repo()
        out = self.assert_pass(repo, CANARY_N)
        link = repo / "documents" / "applications" / CO_ROLE / "final"
        self.assertTrue(link.is_symlink())
        self.assertEqual(link.resolve(), (repo / "private/final" / CO_ROLE).resolve())
        self.assertIn("PASS", out)

    def test_pass_tricky_characters(self):
        self.assert_pass(self.repo(TRICKY), TRICKY_N)

    def test_drafts_untouched_and_no_real_value_outside_private(self):
        repo = self.repo()
        before = {p: p.read_bytes() for p in (repo / "cv").iterdir()}
        self.assertEqual(run_finalize(repo)[0], 0)
        self.assertEqual({p: p.read_bytes() for p in (repo / "cv").iterdir()}, before)
        for p in repo.rglob("*"):
            if p.is_file() and "private" not in p.relative_to(repo).parts:
                data = p.read_bytes().decode("utf-8", "replace")
                self.assertEqual(leaked(data, CANARY_N), [], str(p))

    def test_too_long_cv_fails_and_writes_nothing(self):
        repo = self.repo(filler=90)
        rc, out = run_finalize(repo)
        self.assertEqual(rc, 1)
        self.assertRegex(out, r"cv: [3-9] pages, expected 2")
        self.assertEqual(leaked(out, CANARY_N), [], out)
        self.assertFalse((repo / "private" / "final").exists())

    def test_unknown_token_fails(self):
        repo = self.repo()
        p = repo / "cv" / f"main_{CO_ROLE}.tex"
        p.write_text(p.read_text().replace("\\section{More}", "\\section{ZZBOGUSZZ}"))
        rc, out = run_finalize(repo)
        self.assertEqual(rc, 1)
        self.assertIn("ZZBOGUSZZ", out)

    def test_compile_error_is_redacted(self):
        repo = self.repo()
        p = repo / "cv" / f"main_{CO_ROLE}.tex"
        p.write_text(p.read_text().replace(
            "\\section{More}", "\\section{More}\\undefinedmacro{ZZEMAILZZ ZZNAMEZZ}"))
        rc, out = run_finalize(repo)
        self.assertEqual(rc, 1)
        self.assertIn("lualatex failed", out)
        self.assertEqual(leaked(out, CANARY_N), [], out)

    def test_hostile_draft_cannot_read_or_write_outside(self):
        repo = self.repo()
        secret = self.base / "outside_secret.txt"
        secret.write_text("OUTSIDESECRET42\n")
        hostile = (
            "\\section{More}\n"
            f"\\IfFileExists{{{secret}}}{{\\input{{{secret}}}}}{{}}\n"
            "\\newwrite\\leak\\immediate\\openout\\leak="
            f"{repo}/cv/leak_tex.txt\n"
            "\\immediate\\write\\leak{ZZEMAILZZ}\\immediate\\closeout\\leak\n"
            "\\directlua{pcall(function() local f = io.open('"
            f"{repo}/cv/leak_lua.txt', 'w') f:write('x') f:close() end)}}\n")
        p = repo / "cv" / f"main_{CO_ROLE}.tex"
        p.write_text(p.read_text().replace("\\section{More}", hostile))
        rc, out = run_finalize(repo)
        self.assertFalse((repo / "cv" / "leak_tex.txt").exists())
        self.assertFalse((repo / "cv" / "leak_lua.txt").exists())
        self.assertNotIn("OUTSIDESECRET42", out)
        cv = repo / "private" / "final" / CO_ROLE / "cv.pdf"
        if cv.exists():
            self.assertNotIn("OUTSIDESECRET42", fz.pdf_facts(cv)[1])

    def test_planted_link_is_not_followed(self):
        repo = self.repo()
        app_final = repo / "documents" / "applications" / CO_ROLE / "final"
        app_final.symlink_to(repo / "cv")
        rc, out = run_finalize(repo)
        self.assertEqual(rc, 0, out)
        self.assertIn("left untouched", out)
        self.assertFalse((repo / "cv" / "cv.pdf").exists())
        self.assertTrue((repo / "private/final" / CO_ROLE / "cv.pdf").is_file())


if __name__ == "__main__":
    unittest.main()
