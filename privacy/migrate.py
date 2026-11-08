"""migrate: replace your real contact details with tokens in workspace files.

    privacy/bin/migrate            dry run: count what would change, per file
    privacy/bin/migrate --apply    rewrite the files

Run it yourself, outside any agent session, after ``privacy/bin/identity
init``. Use it when real values are already in the profile or drafts, for
example after a ``/setup`` that ran before the privacy layer existed.

What is replaced, in the files listed in TARGETS: the full name (also as
"first last"), email, phone (in its common spellings), address and profile
URLs, each also in its TeX-escaped form; first and last name alone only
inside ``\\name{..}{..}``. A first or last name standing alone elsewhere is
counted and reported but left alone, since it may belong to someone else.

``documents/`` is never touched: what you put there is your responsibility.
The output names files and counts only, never a value. It also reports
whether your values are in the git history, which a working-tree rewrite
cannot fix.
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.append(str(REPO))

from privacy import identity as ident  # noqa: E402
from privacy import texsubst  # noqa: E402
from privacy.finalize import JAIL_MARKER, check_no_symlinks, read_passphrase  # noqa: E402

TARGETS = (
    "CLAUDE.md", "AGENTS.md",
    ".claude/skills/job-application-assistant/*.md",
    ".claude/skills/job-scraper/search-queries.md",
    "cv/*.tex", "cover_letters/*.tex",
    "templates/**/*",
    "job_search_tracker.csv",
)


def target_files(repo: Path) -> list[Path]:
    out = []
    for root, dirs, files in os.walk(repo):
        rel_root = Path(root).relative_to(repo)
        dirs[:] = [d for d in dirs if not (rel_root / d).parts[0] in
                   (".git", ".venv", "private", "documents", "node_modules", "privacy")]
        for f in files:
            rel = (rel_root / f).as_posix()
            if any(fnmatch.fnmatch(rel, pat) for pat in TARGETS):
                p = repo / rel
                if p.is_file() and not p.is_symlink():
                    out.append(p)
    return sorted(out)


def phone_pattern(phone: str) -> str:
    """Digits of the number with any separators between them, with or
    without the country code."""
    digits = re.sub(r"\D", "", phone)
    sep = r"[\s\-.()]*"
    variants = {digits}
    if phone.strip().startswith("+") and len(digits) > 8:
        for cc in (1, 2, 3):                 # country codes are 1-3 digits
            if len(digits) - cc >= 8:
                variants.add(digits[cc:])
    alts = []
    for v in sorted(variants, key=len, reverse=True):
        body = sep.join(re.escape(d) for d in v)
        alts.append(rf"(?:\+?{sep})?{body}" if v == digits else body)
    return rf"(?<!\d)(?:{'|'.join(alts)})(?!\d)"


def url_forms(url: str) -> set[str]:
    bare = re.sub(r"^https?://", "", url).rstrip("/")
    forms = {url, bare, "http://" + bare}
    if bare.startswith("www."):
        forms |= {bare[4:], "https://" + bare[4:]}
    else:
        forms |= {"www." + bare, "https://www." + bare}
    return forms


def build_rules(identity: dict) -> list[tuple[re.Pattern, str]]:
    """(pattern, token) pairs, applied in order."""
    literal: dict[str, str] = {}

    def add(value: str, token: str):
        for v in {value, texsubst.escape(value), texsubst.escape(value, url=True)}:
            if len(v) >= 4:
                literal.setdefault(v, token)

    first, last = identity.get("first_name"), identity.get("last_name")
    if identity.get("full_name"):
        add(identity["full_name"], ident.TOKENS["full_name"])
    if first and last:
        add(f"{first} {last}", ident.TOKENS["full_name"])
    for f in ("email", "address"):
        if identity.get(f):
            add(identity[f], ident.TOKENS[f])
    for f in ident.URL_FIELDS:
        if identity.get(f):
            for form in url_forms(identity[f]):
                add(form, ident.TOKENS[f])
    rules = [(re.compile(re.escape(v), re.IGNORECASE), t)
             for v, t in sorted(literal.items(), key=lambda kv: -len(kv[0]))]
    if identity.get("phone") and len(re.sub(r"\D", "", identity["phone"])) >= 6:
        rules.append((re.compile(phone_pattern(identity["phone"])), ident.TOKENS["phone"]))
    if first and last:
        rules.append((re.compile(r"\\name\{" + re.escape(texsubst.escape(first)) + r"\}\{"
                                 + re.escape(texsubst.escape(last)) + r"\}"),
                      r"\\name{ZZFIRSTNAMEZZ}{ZZLASTNAMEZZ}"))
    return rules


def leftover_names(text: str, identity: dict) -> int:
    n = 0
    for f in ("first_name", "last_name"):
        v = identity.get(f)
        if v and len(v) >= 3:
            n += len(re.findall(rf"(?<!\w){re.escape(v)}(?!\w)", text, re.IGNORECASE))
    return n


def migrate_text(text: str, rules) -> tuple[str, int]:
    total = 0
    for pattern, token in rules:
        text, n = pattern.subn(token, text)
        total += n
    return text, total


def git_history_hits(repo: Path, identity: dict) -> int:
    """Number of commits whose diff adds or removes one of the values."""
    if not (repo / ".git").exists():
        return 0
    commits = set()
    for f in ("full_name", "email", "phone", "address"):
        v = identity.get(f)
        if not v:
            continue
        r = subprocess.run(["git", "-C", str(repo), "-c", "core.fsmonitor=",
                            "log", "--all", "--format=%H", "-S", v],
                           capture_output=True, text=True)
        commits |= set(r.stdout.split())
    return len(commits)


def write_atomic(path: Path, text: str) -> None:
    tmp = path.with_name(f".{path.name}.migrate-tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 os.stat(path).st_mode & 0o777)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    os.replace(tmp, path)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Replace real contact details with tokens")
    ap.add_argument("--repo", type=Path, default=REPO)
    ap.add_argument("--apply", action="store_true", help="rewrite the files")
    ap.add_argument("--passphrase-stdin", action="store_true")
    args = ap.parse_args(argv)
    if os.environ.get(JAIL_MARKER) == "1":
        print("migrate must run outside the agent session")
        return 2
    repo = args.repo.resolve()
    try:
        blob = ident.read_file(check_no_symlinks(repo, Path("private/identity.enc")))
        identity = ident.normalise(ident.decrypt(blob, read_passphrase(args.passphrase_stdin)))
    except (OSError, ident.IdentityError) as e:
        msg = str(e) if isinstance(e, ident.IdentityError) else "private/identity.enc not found"
        print(f"FAIL: {msg}")
        return 2

    rules = build_rules(identity)
    changed = names_left = 0
    for path in target_files(repo):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        new, n = migrate_text(text, rules)
        left = leftover_names(new, identity)
        rel = path.relative_to(repo).as_posix()
        if n:
            changed += 1
            print(f"{'replaced' if args.apply else 'would replace'} {n:3d} in {rel}")
            if args.apply:
                write_atomic(path, new)
        if left:
            names_left += left
            print(f"note: {left} standalone first/last name(s) left in {rel}; "
                  "check them by hand")
    hist = git_history_hits(repo, identity)
    if hist:
        print(f"warning: your values occur in {hist} git commit(s). Rewriting files does "
              "not remove them from history; do not push those commits to a public remote.")
    if not changed:
        print("nothing to replace")
    elif not args.apply:
        print("dry run: run again with --apply to rewrite these files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
