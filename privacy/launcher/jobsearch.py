#!/usr/bin/env python3
"""jobsearch: start an agent CLI with the private parts of the repo masked.

    jobsearch claude [args...]        # or codex, copilot, agy
    jobsearch -- COMMAND [args...]    # any command, e.g. for tests

The agent runs in a bubblewrap namespace where

* ``private/`` (identity file, final PDFs, finalize's work dir) is replaced
  by an empty tmpfs, so nothing in it is readable, and writes there vanish;
* the whole host filesystem is READ-ONLY, except:
  - the repo, so the agent can write drafts, profile files and state; but
    the code and config that run later OUTSIDE the jail stay read-only:
    ``privacy/`` (finalize), ``tools/``, ``.venv/``, ``.git/`` (hooks,
    config), and the Claude permission files and agent definitions;
  - the agent CLIs' own state directories, with their executable config
    (settings, hooks, MCP and plugin definitions) kept read-only;
  - a fresh ``/tmp``;
  so a prompt-injected agent cannot plant code in your shell config,
  ``~/.local/bin``, the venv or finalize that would run with your full
  rights the next time you work outside the jail;
* ``/mnt`` (Windows drives) and ``/run/WSL`` (interop sockets) are hidden,
  and the interop variables and ``/mnt/...`` PATH entries removed;
* the agent gets its own PID namespace, and inherited file descriptors
  above stderr are closed.

Network stays available, because agent CLIs need their model provider.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

MASKED_REPO_DIRS = ("private",)
# Code or config in the repo that runs, or decides what runs, outside the jail.
READONLY_REPO_PATHS = (
    "privacy", "tools", ".venv", ".git",
    ".claude/settings.json", ".claude/settings.local.json",
    ".claude/agents", ".claude/commands", ".claude/hooks",
)
# Agent CLI state that must stay writable for the CLIs to work.
WRITABLE_HOME_PATHS = (
    ".claude", ".claude.json", ".codex", ".copilot", ".gemini",
    ".cache", ".local/state",
)
# Inside those: files that make the CLI run commands or load instructions.
READONLY_HOME_PATHS = (
    # Claude Code
    ".claude/settings.json", ".claude/CLAUDE.md", ".claude/hooks",
    ".claude/skills", ".claude/agents", ".claude/commands",
    ".claude/plugins", ".claude/output-styles",
    # Codex: config (hooks, MCP, notify), exec-policy rules, its own binary
    ".codex/config.toml", ".codex/AGENTS.md", ".codex/rules",
    ".codex/skills", ".codex/plugins", ".codex/packages",
    # Copilot CLI: trusted folders, MCP/LSP servers, hooks, status line
    ".copilot/config.json", ".copilot/settings.json", ".copilot/mcp-config.json",
    ".copilot/lsp-config.json", ".copilot/hooks", ".copilot/skills",
    ".copilot/installed-plugins", ".copilot/copilot-instructions.md",
    ".copilot/statusline.sh",
    # Antigravity CLI (agy): settings, MCP, plugins, skills, its own binary
    ".gemini/settings.json", ".gemini/GEMINI.md", ".gemini/bin", ".gemini/config",
    ".gemini/antigravity-cli/settings.json", ".gemini/antigravity-cli/mcp",
    ".gemini/antigravity-cli/skills", ".gemini/antigravity-cli/statusline.sh",
    ".gemini/antigravity-cli/updater", ".gemini/antigravity-cli/bin",
    ".gemini/antigravity/mcp",
)
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


def existing(base: Path, rels) -> list[Path]:
    """Paths under base that exist; symlinks are skipped (bwrap would follow
    them and bind the target instead)."""
    return [base / r for r in rels
            if (base / r).exists() and not (base / r).is_symlink()]


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


def build_argv(repo: Path, command: list[str], home: Path | None = None) -> list[str]:
    home = home or Path.home()
    masked = check_masked_dirs(repo)
    argv = ["bwrap", "--die-with-parent",
            "--unshare-pid", "--unshare-ipc", "--unshare-cgroup-try",
            "--ro-bind", "/", "/",
            "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"]
    for d in HIDDEN_HOST_DIRS:
        if os.path.isdir(d):
            argv += ["--tmpfs", d]
    argv += keep_visible(KEEP_VISIBLE_LINKS)
    for p in existing(home, WRITABLE_HOME_PATHS):
        argv += ["--bind", str(p), str(p)]
    for p in existing(home, READONLY_HOME_PATHS):
        argv += ["--ro-bind", str(p), str(p)]
    argv += ["--bind", str(repo), str(repo)]
    for p in existing(repo, READONLY_REPO_PATHS):
        argv += ["--ro-bind", str(p), str(p)]
    for d in masked:
        argv += ["--tmpfs", str(d)]
    argv += ["--chdir", os.getcwd(), "--"] + command
    return argv


def parse_args(args: list[str]) -> tuple[Path, Path | None, list[str]]:
    repo, home = default_repo(), None
    while args[:1] in (["--repo"], ["--home"]) and len(args) >= 2:
        if args[0] == "--repo":
            repo = Path(args[1])
        else:
            home = Path(args[1]).resolve(strict=True)   # for tests
        args = args[2:]
    if args[:1] == ["--"]:
        command = args[1:]
    elif args and args[0] in KNOWN_CLIS:
        command = args
    else:
        raise LauncherError("usage: jobsearch [--repo DIR] {"
                            + ",".join(KNOWN_CLIS) + "} [args] | -- COMMAND")
    if not command:
        raise LauncherError("no command given")
    return repo.resolve(strict=True), home, command


def main(args: list[str]) -> int:
    try:
        repo, home, command = parse_args(args)
        if shutil.which("bwrap") is None:
            raise LauncherError("bubblewrap (bwrap) is not installed")
        argv = build_argv(repo, command, home)
    except (LauncherError, FileNotFoundError) as e:
        print(f"jobsearch: {e}", file=sys.stderr)
        return 2
    os.closerange(3, os.sysconf("SC_OPEN_MAX"))
    os.execvpe(argv[0], argv, clean_env(dict(os.environ)))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
