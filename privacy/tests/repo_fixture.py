"""Build a throwaway repo with token drafts made from the shipped templates.

The drafts are the stock ``cv/main_example.tex`` and
``cover_letters/cover_example.tex`` with their identity placeholders
replaced by tokens, which is what an agent's draft looks like under the
privacy layer. ``filler`` lines of synthetic content fill page 2 so the
stock CV passes the layout check (its placeholder page 2 is thin by design).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from privacy import identity as ident

ROOT = Path(__file__).resolve().parent.parent.parent
CO_ROLE = "acme_dev"

CV_TOKENS = [
    ("[YOUR_NAME]", "ZZNAMEZZ"),
    ("\\name{[First]}{[Last]}", "\\name{ZZFIRSTNAMEZZ}{ZZLASTNAMEZZ}"),
    ("[Your Address, City, Country]", "ZZADDRESSZZ"),
    ("[+XX XXXXXXXXXX]", "ZZPHONEZZ"),
    ("[your.email@example.com]", "ZZEMAILZZ"),
    ("[https://linkedin.com/in/your-profile]", "ZZLINKEDINZZ"),
    ("[https://github.com/your-username]", "ZZGITHUBZZ"),
]
COVER_TOKENS = [
    ("[YOUR NAME]", "ZZNAMEZZ"),
    ("mailto:your.email@example.com", "mailto:ZZEMAILZZ"),
    ("{your.email@example.com}", "{ZZEMAILZZ}"),
    ("[+XX XXXXXXXXXX]", "ZZPHONEZZ"),
    ("https://www.linkedin.com/in/yourprofile", "ZZLINKEDINZZ"),
]
FILLER_ITEM = ("\\cvitem{Synthetic}{Filler line for the test fixture, long enough "
               "to wrap once in the banking style so it takes real space.}\n")


def tokenise(src: str, pairs) -> str:
    for old, new in pairs:
        if old not in src:
            raise AssertionError(f"template changed upstream: {old!r} not found")
        src = src.replace(old, new)
    return src


def make_app_repo(base: Path, identity: dict | None, passphrase: str = "",
                  filler: int = 30, co_role: str = CO_ROLE) -> Path:
    repo = base / "repo"
    (repo / "cv").mkdir(parents=True)
    shutil.copytree(ROOT / "cover_letters", repo / "cover_letters",
                    ignore=shutil.ignore_patterns("cover_*.tex", "*.pdf", "final"))
    cv = tokenise((ROOT / "cv/main_example.tex").read_text(encoding="utf-8"), CV_TOKENS)
    if filler:
        cv = cv.replace("\\section{References}",
                        "\\section{More}\n" + FILLER_ITEM * filler + "\\section{References}")
    (repo / "cv" / f"main_{co_role}.tex").write_text(cv, encoding="utf-8")
    cover = tokenise((ROOT / "cover_letters/cover_example.tex").read_text(encoding="utf-8"),
                     COVER_TOKENS)
    (repo / "cover_letters" / f"cover_{co_role}.tex").write_text(cover, encoding="utf-8")
    (repo / "documents" / "applications" / co_role).mkdir(parents=True)
    if identity is not None:
        (repo / "private").mkdir(mode=0o700)
        blob = ident.encrypt(identity, passphrase, ident.KdfParams(log2_n=10))
        ident.write_file(repo / "private" / "identity.enc", blob)
    return repo


def write_json(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path
