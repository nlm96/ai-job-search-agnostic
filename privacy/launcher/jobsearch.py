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
* the home directory is replaced by an empty tmpfs. Only the toolchains
  the agent needs (read-only), a cache of its own, and the state directory
  of the ONE CLI being started are bound back in. Everything else, such as
  ``~/.ssh``, ``~/.config/gh``, other CLIs' logins, shell history, other
  projects and mounted drives, is invisible;
* ``/mnt`` (Windows drives), ``/run/WSL`` (interop sockets) and
  ``/run/user`` (ssh/gpg agent, D-Bus keyring) are hidden, and environment
  variables that look like secrets are dropped, except the started CLI's
  own login variables;
* the agent gets its own PID namespace, and inherited file descriptors
  above stderr are closed.

Network stays available, because agent CLIs need their model provider.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from pathlib import Path

MASKED_REPO_DIRS = ("private",)
# Code or config in the repo that runs, or decides what runs, outside the jail.
READONLY_REPO_PATHS = (
    "privacy", "tools", ".venv", ".git",
    ".claude/settings.json", ".claude/settings.local.json",
    ".claude/agents", ".claude/commands", ".claude/hooks",
    # fork-owned instruction files that carry the privacy rules
    "AGENTS.override.md", "GEMINI.md",
)
# Per CLI: its state (bound read-write; holds its own login, which it needs)
# and the environment variables that may carry its login.
CLI_STATE = {
    "claude": (".claude", ".claude.json"),
    "codex": (".codex",),
    "copilot": (".copilot",),
    "agy": (".gemini",),
}
CLI_ENV = {
    "claude": ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"),
    "codex": ("OPENAI_API_KEY", "CODEX_API_KEY"),
    "copilot": ("COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"),
    "agy": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
}
# Toolchains under home, bound read-only. Nothing here may hold credentials.
HOME_TOOLCHAIN = (
    ".local/bin", ".local/share/claude", ".local/share/pnpm", ".local/share/uv",
    ".nvm", ".agents", ".config/uv",
)
# The jail's own ~/.cache, one per CLI, so no host cache (which can hold
# tokens, e.g. huggingface) is visible and CLIs cannot poison each other.
JAIL_CACHE = ".cache/jobsearch-jail"
# Inside the CLI state: files that make the CLI run commands or load instructions.
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
    ".gemini/antigravity-cli/updater", ".gemini/antigravity-cli/bin/webm_encoder",
    ".gemini/antigravity/mcp",
)
HIDDEN_HOST_DIRS = ("/mnt", "/run/WSL", "/run/user")
DROPPED_ENV = ("WSL_INTEROP", "WSLENV", "SSH_AUTH_SOCK", "SSH_AGENT_PID",
               "GPG_AGENT_INFO", "DBUS_SESSION_BUS_ADDRESS", "GNOME_KEYRING_CONTROL")
# Names that look like they carry a secret. GIT_CONFIG_* is dropped as a
# group, since its numbered KEY/VALUE pairs must stay consistent.
SECRET_ENV_RE = re.compile(
    r"TOKEN|SECRET|PASSW|API_?KEY|PRIVATE|CREDENTIAL|AUTH|COOKIE|SESSION|_KEY$|^GIT_CONFIG_",
    re.IGNORECASE)
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


def clean_env(env: dict[str, str], cli: str | None = None) -> dict[str, str]:
    keep = CLI_ENV.get(cli, ())
    env = {k: v for k, v in env.items()
           if k not in DROPPED_ENV and (k in keep or not SECRET_ENV_RE.search(k))}
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


# agy rewrites this shim at every start, so it must stay writable. A jailed
# agent could replace it with code that runs when agy is next started
# outside the launcher; the launcher refuses to start if it has changed.
AGY_SHIM = ".gemini/antigravity-cli/bin/agentapi"


def agy_shim_expected(home: Path) -> str:
    return f'#!/bin/sh\nexec "{home}/.local/bin/agy" agentapi "$@"\n'


def check_agy_shim(home: Path) -> None:
    shim = home / AGY_SHIM
    if shim.is_symlink():
        raise LauncherError(f"refusing to start: {shim} is a symlink")
    if shim.exists() and shim.read_text(errors="replace").strip() != \
            agy_shim_expected(home).strip():
        raise LauncherError(
            f"refusing to start: {shim} has unexpected content, possibly planted "
            "by an earlier agent session. Inspect it, delete it (agy recreates it), "
            "and do not run agy outside the launcher until you have.")


def jail_cache(home: Path, cli: str) -> Path | None:
    """The host directory bound as ~/.cache, created if missing."""
    path = home
    for part in Path(JAIL_CACHE, cli).parts:
        path = path / part
        if path.is_symlink():
            return None
    path.mkdir(parents=True, exist_ok=True)
    return path


def inside(path: Path, base: Path) -> bool:
    return path == base or base in path.parents


def build_argv(repo: Path, command: list[str], home: Path | None = None,
               cli: str | None = None) -> list[str]:
    home = home or Path.home()
    masked = check_masked_dirs(repo)
    check_agy_shim(home)
    argv = ["bwrap", "--die-with-parent",
            "--unshare-pid", "--unshare-ipc", "--unshare-cgroup-try",
            "--ro-bind", "/", "/",
            "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"]
    for d in HIDDEN_HOST_DIRS:
        if os.path.isdir(d):
            argv += ["--tmpfs", d]
    argv += keep_visible(KEEP_VISIBLE_LINKS)
    argv += ["--tmpfs", str(home)]
    for p in existing(home, HOME_TOOLCHAIN):
        argv += ["--ro-bind", str(p), str(p)]
    if cli:
        cache = jail_cache(home, cli)
        if cache:
            argv += ["--bind", str(cache), str(home / ".cache")]
        state = CLI_STATE[cli]
        for p in existing(home, state):
            argv += ["--bind", str(p), str(p)]
        own = [r for r in READONLY_HOME_PATHS
               if any(r == s or r.startswith(s + "/") for s in state)]
        for p in existing(home, own):
            argv += ["--ro-bind", str(p), str(p)]
    argv += ["--bind", str(repo), str(repo)]
    for p in existing(repo, READONLY_REPO_PATHS):
        argv += ["--ro-bind", str(p), str(p)]
    for d in masked:
        argv += ["--tmpfs", str(d)]
    # luaotfload's font cache (normally ~/.texlive*/texmf-var, now hidden):
    # in the jail cache, so lualatex works and the host cache, whose Lua
    # files run in every later lualatex, cannot be planted into.
    texmf = (home / ".cache" / "texmf-var") if cli else Path("/tmp/texmf-var")
    argv += ["--setenv", "TEXMFVAR", str(texmf)]
    cwd = Path(os.getcwd())
    if inside(cwd, home) and not inside(cwd, repo):
        cwd = repo          # would not exist inside the jail
    argv += ["--chdir", str(cwd), "--"] + command
    return argv


def parse_args(args: list[str]) -> tuple[Path, Path | None, str | None, list[str]]:
    repo, home, cli = default_repo(), None, None
    while args[:1] in (["--repo"], ["--home"], ["--cli"]) and len(args) >= 2:
        if args[0] == "--repo":
            repo = Path(args[1])
        elif args[0] == "--home":
            home = Path(args[1]).resolve(strict=True)   # for tests
        else:
            cli = args[1]                                # whose state -- gets
        args = args[2:]
    usage = ("usage: jobsearch [--repo DIR] {" + ",".join(KNOWN_CLIS)
             + "} [args] | [--cli NAME] -- COMMAND")
    if args[:1] == ["--"]:
        command = args[1:]
    elif args and args[0] in KNOWN_CLIS:
        command, cli = args, args[0]
    else:
        raise LauncherError(usage)
    if cli is not None and cli not in KNOWN_CLIS:
        raise LauncherError(usage)
    if not command:
        raise LauncherError("no command given")
    return repo.resolve(strict=True), home, cli, command


def main(args: list[str]) -> int:
    try:
        repo, home, cli, command = parse_args(args)
        if shutil.which("bwrap") is None:
            raise LauncherError("bubblewrap (bwrap) is not installed")
        argv = build_argv(repo, command, home, cli)
    except (LauncherError, FileNotFoundError) as e:
        print(f"jobsearch: {e}", file=sys.stderr)
        return 2
    os.closerange(3, os.sysconf("SC_OPEN_MAX"))
    os.execvpe(argv[0], argv, clean_env(dict(os.environ), cli))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
