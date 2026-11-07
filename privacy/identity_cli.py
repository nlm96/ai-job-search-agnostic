"""identity: create and manage private/identity.enc.

    privacy/bin/identity init     ask for your details and a passphrase
    privacy/bin/identity check    decrypt and list which fields are set
    privacy/bin/identity rekey    change the passphrase
    privacy/bin/identity tokens   print the token for each field

Run it yourself, outside any agent session. Values are typed in your
terminal and never printed back.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.append(str(REPO))

from privacy import identity as ident  # noqa: E402
from privacy.finalize import JAIL_MARKER, check_no_symlinks, safe_mkdirs  # noqa: E402

PROMPTS = {
    "first_name": "First name", "last_name": "Last name",
    "full_name": "Full name as printed (Enter = first + last)",
    "email": "Email", "phone": "Phone, e.g. +45 12 34 56 78",
    "address": "Address line (Enter = none)",
    "linkedin": "LinkedIn URL, https://... (Enter = none)",
    "github": "GitHub URL (Enter = none)",
    "website": "Website URL (Enter = none)",
}


def enc_path(repo: Path) -> Path:
    safe_mkdirs(repo, Path("private"))
    return check_no_symlinks(repo, Path("private/identity.enc"))


def ask_passphrase(stdin: bool, confirm: bool, label: str = "Passphrase") -> str:
    if stdin:
        return sys.stdin.readline().rstrip("\n")
    while True:
        p = getpass.getpass(f"{label}: ")
        if len(p) < 12:
            print("Use at least 12 characters.")
            continue
        if not confirm or p == getpass.getpass("Repeat: "):
            return p
        print("The two entries differ; try again.")


def cmd_init(args) -> int:
    path = enc_path(args.repo)
    if path.exists() and not args.force:
        print("private/identity.enc exists; use rekey, or init --force to replace it")
        return 2
    if args.from_json:
        data = json.loads(Path(args.from_json).read_text(encoding="utf-8"))
    else:
        data = {f: input(f"{label}: ") for f, label in PROMPTS.items()}
    data = ident.normalise(data)
    problems = ident.validate(data)
    if problems:
        print("Not saved:\n  " + "\n  ".join(problems))
        return 1
    params = ident.KdfParams(args.log2_n) if args.log2_n else ident.KdfParams()
    ident.write_file(path, ident.encrypt(data, ask_passphrase(args.passphrase_stdin, True), params))
    print(f"Saved private/identity.enc with fields: {', '.join(sorted(data))}")
    return 0


def load(args) -> dict:
    blob = ident.read_file(enc_path(args.repo))
    return ident.decrypt(blob, ask_passphrase(args.passphrase_stdin, False))


def cmd_check(args) -> int:
    data = load(args)
    for f in ident.TOKENS:
        print(f"  {f:11} {'set' if data.get(f) else '-'}")
    problems = ident.validate(ident.normalise(data))
    print("OK" if not problems else "Problems:\n  " + "\n  ".join(problems))
    return 0 if not problems else 1


def cmd_rekey(args) -> int:
    data = load(args)
    new = ask_passphrase(args.passphrase_stdin, True, "New passphrase")
    ident.write_file(enc_path(args.repo), ident.encrypt(data, new))
    print("Passphrase changed.")
    return 0


def cmd_tokens(args) -> int:
    for f, t in ident.TOKENS.items():
        print(f"  {t:15} {f}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Manage private/identity.enc")
    ap.add_argument("--repo", type=Path, default=REPO)
    ap.add_argument("--passphrase-stdin", action="store_true",
                    help="read passphrase(s) from stdin, one per line (for tests)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    p.add_argument("--force", action="store_true")
    p.add_argument("--from-json", help="read the fields from a JSON file (for tests)")
    p.add_argument("--log2-n", type=int, help=argparse.SUPPRESS)
    sub.add_parser("check")
    sub.add_parser("rekey")
    sub.add_parser("tokens")
    args = ap.parse_args(argv)
    if args.cmd != "tokens" and os.environ.get(JAIL_MARKER) == "1":
        print("identity must run outside the agent session")
        return 2
    args.repo = args.repo.resolve()
    try:
        return {"init": cmd_init, "check": cmd_check,
                "rekey": cmd_rekey, "tokens": cmd_tokens}[args.cmd](args)
    except ident.IdentityError as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
