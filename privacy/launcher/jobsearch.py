#!/usr/bin/env python3
"""jobsearch: start an agent CLI with the private parts of the repo masked.

    jobsearch claude [args...]        # or codex, copilot, agy
    jobsearch -- COMMAND [args...]    # any command, e.g. for tests

The agent runs in a bubblewrap namespace where the host filesystem looks
normal except for these changes:

* ``private/``, ``cv/final/`` and ``cover_letters/final/`` in the repo are
  replaced by empty tmpfs mounts (writes there vanish on exit);
* ``/mnt`` (Windows drives) and ``/run/WSL`` (Windows interop sockets) are
  hidden, and the interop variables and ``/mnt/...`` PATH entries removed;
* ``/tmp`` is a fresh tmpfs, so temp files of the finaliser are invisible;
* the agent gets its own PID namespace, so it cannot reach host processes'
  view of the filesystem through ``/proc/<pid>/root``;
* inherited file descriptors above stderr are closed.

Network, the user's home and the rest of the repo stay as they are, because
agent CLIs need their login state and the workspace.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

MASKED_REPO_DIRS = ("private", "cv/final", "cover_letters/final")
HIDDEN_HOST_DIRS = ("/mnt", "/run/WSL")
DROPPED_ENV = ("WSL_INTEROP", "WSLENV")
KNOWN_CLIS = ("claude", "codex", "copilot", "agy")
JAIL_MARKER = "JOBSEARCH_JAIL"


# On WSL /etc/resolv.conf links into /mnt/wsl/, which HIDDEN_HOST_DIRS hides;
# without re-exposing the link target the agent has no DNS.
KEEP_VISIBLE_LINKS = ("/etc/resolv.conf",)


class LauncherError(Exception):
    pass


def default_repo() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def check_masked_dirs(repo: Path) -> list[Path]:
    """Return the masked directories, creating missing ones.

    Refuses symlinks anywhere between the repo and a masked directory:
    bwrap follows them, so the mask would land on the link target and the
    directory the finaliser actually writes to would stay visible.
    """
    out = []
    for rel in MASKED_REPO_DIRS:
        path = repo
        for part in Path(rel).parts:
            path = path / part
            if path.is_symlink():
                raise LauncherError(f"refusing to start: {path} is a symlink")
        path.mkdir(parents=True, exist_ok=True)
        out.append(path)
    return out


def clean_env(env: dict[str, str]) -> dict[str, str]:
    env = {k: v for k, v in env.items() if k not in DROPPED_ENV}
    if "PATH" in env:
        env["PATH"] = ":".join(p for p in env["PATH"].split(":")
                               if p and not p.startswith("/mnt/"))
    env[JAIL_MARKER] = "1"
    return env


def keep_visible(links) -> list[str]:
    """Re-bind, read-only, link targets that fall inside a hidden dir."""
    argv = []
    for link in links:
        target = os.path.realpath(link)
        hidden = any(target == d or target.startswith(d + "/")
                     for d in HIDDEN_HOST_DIRS)
        if hidden and os.path.isfile(target):
            argv += ["--ro-bind", target, target]
    return argv


def build_argv(repo: Path, command: list[str]) -> list[str]:
    argv = ["bwrap", "--die-with-parent",
            "--unshare-pid", "--unshare-ipc", "--unshare-cgroup-try",
            "--bind", "/", "/",
            "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"]
    for d in HIDDEN_HOST_DIRS:
        if os.path.isdir(d):
            argv += ["--tmpfs", d]
    argv += keep_visible(KEEP_VISIBLE_LINKS)
    for d in check_masked_dirs(repo):
        argv += ["--tmpfs", str(d)]
    argv += ["--chdir", os.getcwd(), "--"] + command
    return argv


def parse_args(args: list[str]) -> tuple[Path, list[str]]:
    repo = default_repo()
    if args[:1] == ["--repo"] and len(args) >= 2:
        repo, args = Path(args[1]), args[2:]
    if args[:1] == ["--"]:
        command = args[1:]
    elif args and args[0] in KNOWN_CLIS:
        command = args
    else:
        raise LauncherError("usage: jobsearch [--repo DIR] {"
                            + ",".join(KNOWN_CLIS) + "} [args] | -- COMMAND")
    if not command:
        raise LauncherError("no command given")
    return repo.resolve(strict=True), command


def main(args: list[str]) -> int:
    try:
        repo, command = parse_args(args)
        if shutil.which("bwrap") is None:
            raise LauncherError("bubblewrap (bwrap) is not installed")
        argv = build_argv(repo, command)
    except (LauncherError, FileNotFoundError) as e:
        print(f"jobsearch: {e}", file=sys.stderr)
        return 2
    os.closerange(3, os.sysconf("SC_OPEN_MAX"))
    os.execvpe(argv[0], argv, clean_env(dict(os.environ)))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
