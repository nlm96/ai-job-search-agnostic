"""finalize: build the real, sendable PDFs for one application.

    privacy/bin/finalize CO_ROLE

Run this yourself, outside any agent session. It

1. reads the agent's token drafts ``cv/main_CO_ROLE.tex`` and
   ``cover_letters/cover_CO_ROLE.tex``;
2. asks for your passphrase and decrypts ``private/identity.enc`` in memory;
3. replaces the tokens (``ZZNAMEZZ``, ``ZZEMAILZZ``, ...) with your escaped
   real values in a copy under ``private/.work/`` (which agents cannot see);
4. compiles the copy in a bubblewrap jail with no network, no home
   directory and only the work directory writable, so a hostile draft can
   neither read your files into the PDF nor write real values anywhere an
   agent can see;
5. checks the real PDFs: page counts, layout, contact details as literal
   text, no token left in text, metadata or link targets;
6. on PASS writes ``private/final/CO_ROLE/cv.pdf`` and ``cover_letter.pdf``,
   and links ``documents/applications/CO_ROLE/final`` to that folder.

Everything it prints passes through ``redact()``, so the output can be
pasted to an agent: it never contains an identity value.
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import secrets
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    # Appended, not prepended: stdlib and the venv win over anything an
    # agent might have planted in the repo root.
    sys.path.append(str(REPO))

from privacy import identity as ident  # noqa: E402
from privacy import texsubst  # noqa: E402

CO_ROLE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_\-]{0,99}")
JAIL_MARKER = "JOBSEARCH_JAIL"


@dataclass(frozen=True)
class Doc:
    key: str            # "cv" or "cover_letter"
    src_dir: str        # directory in the repo
    prefix: str         # source file prefix
    engine: str
    pages: int
    contact_check: bool  # ATS literal email/phone check

    def source(self, co_role: str) -> str:
        return f"{self.prefix}{co_role}.tex"


DOCS = (
    Doc("cv", "cv", "main_", "lualatex", 2, True),
    Doc("cover_letter", "cover_letters", "cover_", "xelatex", 1, False),
)
TEMPLATE_GUIDES = (
    ".claude/skills/job-application-assistant/05-cv-templates.md",
    ".claude/skills/job-application-assistant/06-cover-letter-templates.md",
)


class FinalizeError(Exception):
    pass


@dataclass
class Report:
    identity: dict
    lines: list[str] = field(default_factory=list)
    failed: bool = False

    def say(self, msg: str) -> None:
        self.lines.append(redact(msg, self.identity))

    def fail(self, msg: str) -> None:
        self.failed = True
        self.say("FAIL: " + msg)


# ---------------------------------------------------------------- redaction

def redaction_pairs(identity: dict) -> list[tuple[str, str]]:
    """(text, token) pairs covering each value as written, escaped, and in
    the forms a PDF or TeX log shows it (digits only, lowercase, accents
    on separate glyphs are not attempted)."""
    pairs = []
    for f, value in identity.items():
        token = ident.TOKENS[f]
        forms = {value, value.lower(), texsubst.escape(value),
                 texsubst.escape(value, url=True)}
        if f == "phone":
            forms.add(re.sub(r"\D", "", value))
        for form in forms:
            if len(form) >= 3:
                pairs.append((form, token))
    # Longest first, so "First Last" is replaced before "First".
    return sorted(pairs, key=lambda p: -len(p[0]))


def redact(text: str, identity: dict) -> str:
    for form, token in redaction_pairs(identity):
        text = re.sub(re.escape(form), token, text, flags=re.IGNORECASE)
    return text


# ------------------------------------------------------------ safe file ops

def check_no_symlinks(base: Path, rel: Path) -> Path:
    """Return base/rel after checking no component below base is a symlink."""
    path = base
    for part in rel.parts:
        path = path / part
        if path.is_symlink():
            raise FinalizeError(f"refusing to use {path.relative_to(base)}: it is a symlink")
    return path


def safe_mkdirs(base: Path, rel: Path, mode: int = 0o700) -> Path:
    path = base
    for part in rel.parts:
        path = path / part
        if path.is_symlink():
            raise FinalizeError(f"refusing to use {path.relative_to(base)}: it is a symlink")
        if not path.exists():
            path.mkdir(mode=mode)
        elif not path.is_dir():
            raise FinalizeError(f"{path.relative_to(base)} is not a directory")
    return path


def safe_write(path: Path, data: bytes) -> None:
    if path.is_symlink():
        raise FinalizeError(f"refusing to overwrite symlink {path.name}")
    tmp = path.with_name(f".{path.name}.tmp-{secrets.token_hex(4)}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def copy_tree_plain(src: Path, dst: Path, skip) -> None:
    """Copy regular files and directories only; symlinks are dropped."""
    dst.mkdir(mode=0o700)
    for entry in os.scandir(src):
        if entry.is_symlink() or skip(entry.name):
            continue
        if entry.is_dir(follow_symlinks=False):
            copy_tree_plain(Path(entry.path), dst / entry.name, lambda n: False)
        elif entry.is_file(follow_symlinks=False):
            shutil.copyfile(entry.path, dst / entry.name, follow_symlinks=False)


def read_source(repo: Path, doc: Doc, co_role: str) -> str:
    path = check_no_symlinks(repo, Path(doc.src_dir) / doc.source(co_role))
    if not path.is_file():
        raise FinalizeError(f"{doc.src_dir}/{doc.source(co_role)} not found")
    return path.read_text(encoding="utf-8")


# ------------------------------------------------------------------ the jail

def jail_argv(work: Path, chdir: Path, command: list[str],
              extra_ro: tuple[Path, ...] = (), writable: bool = True) -> list[str]:
    argv = ["bwrap", "--die-with-parent", "--new-session", "--unshare-all",
            "--ro-bind", "/usr", "/usr",
            "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/lib64", "/lib64", "--symlink", "usr/sbin", "/sbin",
            "--ro-bind", "/etc", "/etc"]
    for d in ("/var/lib/texmf", "/var/cache/fontconfig"):
        if os.path.exists(d):
            argv += ["--ro-bind", d, d]
    for p in extra_ro:
        argv += ["--ro-bind", str(p), str(p)]
    argv += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
             "--bind" if writable else "--ro-bind", str(work), str(work),
             "--chdir", str(chdir), "--clearenv",
             "--setenv", "PATH", "/usr/bin:/bin",
             "--setenv", "HOME", str(work / "home"),
             "--setenv", "TEXMFVAR", str(work / "texmf-var"),
             "--setenv", "LANG", "C.UTF-8",
             "--", *command]
    return argv


def run_jailed(argv: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                          stdin=subprocess.DEVNULL, errors="replace")


def first_tex_error(log: str) -> str:
    for line in log.splitlines():
        if line.startswith("!"):
            return line[:200]
    return "no error line found in the log"


# ------------------------------------------------------------------- checks

def pdf_facts(pdf: Path):
    import pypdf
    reader = pypdf.PdfReader(str(pdf))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    meta = " ".join(str(v) for v in (reader.metadata or {}).values())
    uris = []
    for page in reader.pages:
        for annot in page.get("/Annots") or []:
            action = annot.get_object().get("/A") or {}
            if "/URI" in action:
                uris.append(str(action["/URI"]))
    return len(reader.pages), text, meta, uris


def fold(s: str) -> str:
    s = s.replace("’", "'").replace(" ", " ")
    s = re.sub(r"-\s+", "-", s)          # a line break after a hyphen
    return re.sub(r"\s+", " ", s).strip().lower()


def compact(s: str) -> str:
    """fold() without any whitespace: moderncv sets first and last name in
    separate boxes, and pypdf sometimes extracts them with no space."""
    return re.sub(r"\s+", "", fold(s))


def check_pdf(pdf: Path, doc: Doc, identity: dict, used: set[str], rep: Report) -> None:
    pages, text, meta, uris = pdf_facts(pdf)
    if pages != doc.pages:
        rep.fail(f"{doc.key}: {pages} pages, expected {doc.pages}")
    leftovers = ident.TOKEN_RE.findall(" ".join([text, meta, *uris]))
    if leftovers:
        rep.fail(f"{doc.key}: tokens left in the PDF: {sorted(set(leftovers))}")
    if "(cid:" in text or "�" in text:
        rep.fail(f"{doc.key}: text layer has (cid:) or replacement characters")
    for token in sorted(used):
        f = texsubst.FIELD_OF[token]
        if f in ident.URL_FIELDS:
            if identity[f] not in uris and fold(identity[f]) not in fold(text):
                rep.fail(f"{doc.key}: {f} is neither a link target nor visible text")
        elif f == "email":
            if fold(identity[f]) not in fold(text):
                rep.fail(f"{doc.key}: email is not literal text in the PDF")
            if f"mailto:{identity[f]}" not in uris and doc.contact_check:
                rep.say(f"note: {doc.key}: no mailto link with the email")
        elif f == "phone":
            if fold(identity[f]) not in fold(text):
                rep.fail(f"{doc.key}: phone is not literal text in the PDF")
        elif compact(identity[f]) not in compact(text) + compact(meta):
            rep.fail(f"{doc.key}: {f} appears neither in the text nor in the metadata")
    if doc.contact_check:
        for f in ("email", "phone"):
            if ident.TOKENS[f] not in used:
                rep.fail(f"{doc.key}: the draft has no {ident.TOKENS[f]}; ATS needs the {f}")


# ------------------------------------------------------------------ the run

def custom_template_active(repo: Path) -> bool:
    for rel in TEMPLATE_GUIDES:
        p = repo / rel
        if p.is_file() and "BEGIN ACTIVE-TEMPLATE" in p.read_text(encoding="utf-8"):
            return True
    return False


def build(repo: Path, co_role: str, identity: dict, rep: Report,
          ) -> dict[str, bytes]:
    sources = {}
    for doc in DOCS:
        try:
            sources[doc.key] = read_source(repo, doc, co_role)
        except FinalizeError as e:
            if doc.key == "cv":
                raise
            rep.say(f"note: {e}; building the CV only")
    private = safe_mkdirs(repo, Path("private"))
    work_root = safe_mkdirs(private, Path(".work"))
    work = work_root / secrets.token_hex(8)
    work.mkdir(mode=0o700)
    outputs = {}
    try:
        (work / "home").mkdir()
        (work / "texmf-var").mkdir()
        for doc in DOCS:
            if doc.key not in sources:
                continue
            out_dir = work / doc.src_dir
            copy_tree_plain(repo / doc.src_dir, out_dir,
                            lambda n, d=doc: n == "final" or (
                                n.startswith(d.prefix) and n != d.source(co_role)))
            try:
                real, used = texsubst.substitute(sources[doc.key], identity)
            except texsubst.SubstitutionError as e:
                rep.fail(f"{doc.key}: {e}")
                continue
            (out_dir / doc.source(co_role)).write_text(real, encoding="utf-8")
            argv = jail_argv(work, out_dir, [
                doc.engine, "-interaction=nonstopmode", "-halt-on-error",
                "-no-shell-escape", doc.source(co_role)])
            for _ in range(2):   # second pass settles page references
                r = run_jailed(argv)
                if r.returncode:
                    break
            pdf = out_dir / doc.source(co_role).replace(".tex", ".pdf")
            if r.returncode or not pdf.is_file():
                log = out_dir / doc.source(co_role).replace(".tex", ".log")
                err = first_tex_error(log.read_text(errors="replace")) if log.is_file() else "no log"
                rep.fail(f"{doc.key}: {doc.engine} failed (exit {r.returncode}): {err}")
                continue
            check_pdf(pdf, doc, identity, used, rep)
            layout = run_jailed(jail_argv(
                work, out_dir,
                [str(REPO / ".venv/bin/python"), "-I",
                 str(REPO / "tools/verify_layout.py"), pdf.name],
                extra_ro=(REPO / ".venv", REPO / "tools"), writable=False))
            if layout.returncode == 1:
                detail = "; ".join(l.strip() for l in layout.stdout.splitlines()
                                   if l.strip())[:600]
                rep.fail(f"{doc.key}: layout problem: {detail}")
            elif layout.returncode == 2:
                rep.say(f"note: {doc.key}: layout check skipped (no Poppler)")
            outputs[doc.key] = pdf.read_bytes()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return outputs


def install(repo: Path, co_role: str, outputs: dict[str, bytes], rep: Report,
            link: bool) -> None:
    final = safe_mkdirs(repo, Path("private/final") / co_role)
    for key, data in outputs.items():
        safe_write(final / f"{key}.pdf", data)
        rep.say(f"wrote private/final/{co_role}/{key}.pdf")
    if not link:
        return
    app = repo / "documents" / "applications" / co_role
    if not app.is_dir() or app.is_symlink():
        return
    target = Path("../../../private/final") / co_role
    lnk = app / "final"
    if lnk.is_symlink() and Path(os.readlink(lnk)) == target:
        return
    if lnk.exists() or lnk.is_symlink():
        rep.say(f"note: documents/applications/{co_role}/final exists and is not "
                "the expected link; left untouched")
        return
    lnk.symlink_to(target)
    rep.say(f"linked documents/applications/{co_role}/final -> private/final/{co_role}")


def read_passphrase(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\n")
    return getpass.getpass("Passphrase for private/identity.enc: ")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("co_role", help="the COMPANY_ROLE part of cv/main_COMPANY_ROLE.tex")
    ap.add_argument("--repo", type=Path, default=REPO)
    ap.add_argument("--passphrase-stdin", action="store_true",
                    help="read the passphrase from the first line of stdin")
    ap.add_argument("--no-link", action="store_true",
                    help="do not link documents/applications/CO_ROLE/final")
    args = ap.parse_args(argv)

    if os.environ.get(JAIL_MARKER) == "1":
        print("FAIL: finalize must run outside the agent session "
              "(this shell is inside the jobsearch launcher)")
        return 2
    if not CO_ROLE_RE.fullmatch(args.co_role):
        print("FAIL: COMPANY_ROLE may contain only letters, digits, _ and -")
        return 2
    repo = args.repo.resolve()
    if custom_template_active(repo):
        print("FAIL: a custom /add-template template is active; finalize "
              "supports only the stock templates for now")
        return 2
    if shutil.which("bwrap") is None:
        print("FAIL: bubblewrap (bwrap) is not installed")
        return 2
    try:
        enc = check_no_symlinks(repo, Path("private/identity.enc"))
        blob = ident.read_file(enc)
    except (OSError, FinalizeError):
        print("FAIL: private/identity.enc not found or unreadable; "
              "create it with privacy/bin/identity init")
        return 2
    try:
        identity = ident.normalise(ident.decrypt(blob, read_passphrase(args.passphrase_stdin)))
    except ident.IdentityError as e:
        print(f"FAIL: {e}")
        return 2

    rep = Report(identity)
    try:
        outputs = build(repo, args.co_role, identity, rep)
        if not rep.failed and outputs:
            install(repo, args.co_role, outputs, rep, link=not args.no_link)
    except FinalizeError as e:
        rep.fail(str(e))
    except subprocess.TimeoutExpired:
        rep.fail("a compile or check timed out")
    for line in rep.lines:
        print(line)
    print(f"{'FAIL' if rep.failed else 'PASS'}: finalize {args.co_role}")
    return 1 if rep.failed else 0


if __name__ == "__main__":
    sys.exit(main())
