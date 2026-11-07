"""Tests for privacy/launcher/jobsearch.py.

The unit tests run anywhere. The red-team tests start the real launcher
around an attack script and need user namespaces, so they run only inside
jobsearch-gates. Their oracle is a canary: unique strings planted in every
masked location must never appear in anything the jailed process prints,
while a canary in a visible file must appear (proving the attacks work).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from privacy.launcher import jobsearch

ROOT = Path(__file__).resolve().parent.parent.parent
LAUNCHER = ROOT / "privacy" / "launcher" / "jobsearch.py"
IN_GATES = os.environ.get("JOBSEARCH_GATES") == "1"

SECRET = {
    "private/identity.enc": "CANARY-PRIVATE-7f3a",
    "cv/final/acme_dev.pdf": "CANARY-CVFINAL-91bc",
    "cover_letters/final/acme_dev.pdf": "CANARY-CLFINAL-44de",
}
VISIBLE = {"cv/main_acme_dev.tex": "CANARY-VISIBLE-0a0a"}
SECRET_VALUES = tuple(SECRET.values())


def make_repo(base: Path) -> Path:
    repo = base / "repo"
    for rel, content in {**SECRET, **VISIBLE}.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content + "\n")
    return repo


def scratch_dir() -> Path:
    # Not under /tmp: the launcher replaces /tmp with an empty tmpfs.
    d = ROOT / ".gate-scratch"
    d.mkdir(exist_ok=True)
    return Path(tempfile.mkdtemp(dir=d))


class BuildArgv(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.repo = make_repo(self.base)

    def tearDown(self):
        shutil.rmtree(self.base)

    def test_masks_every_private_dir(self):
        argv = jobsearch.build_argv(self.repo, ["true"])
        for rel in jobsearch.MASKED_REPO_DIRS:
            i = argv.index(str(self.repo / rel))
            self.assertEqual(argv[i - 1], "--tmpfs", rel)

    def test_masked_set_is_pinned(self):
        # Iterating MASKED_REPO_DIRS cannot notice an entry being dropped.
        self.assertEqual(set(jobsearch.MASKED_REPO_DIRS),
                         {"private", "cv/final", "cover_letters/final"})
        self.assertEqual(set(SECRET), {f"{d}/{n}" for d, n in (
            ("private", "identity.enc"), ("cv/final", "acme_dev.pdf"),
            ("cover_letters/final", "acme_dev.pdf"))})

    def test_masks_come_after_root_bind(self):
        argv = jobsearch.build_argv(self.repo, ["true"])
        root_bind = argv.index("--bind")
        for rel in jobsearch.MASKED_REPO_DIRS:
            self.assertGreater(argv.index(str(self.repo / rel)), root_bind)

    def test_own_pid_namespace_and_tmp(self):
        argv = jobsearch.build_argv(self.repo, ["true"])
        self.assertIn("--unshare-pid", argv)
        self.assertEqual(argv[argv.index("/proc") - 1], "--proc")
        self.assertEqual(argv[argv.index("/tmp") - 1], "--tmpfs")

    def test_command_is_last(self):
        argv = jobsearch.build_argv(self.repo, ["claude", "-p", "x"])
        self.assertEqual(argv[-4:], ["--", "claude", "-p", "x"])

    def test_creates_missing_masked_dirs(self):
        shutil.rmtree(self.repo / "cover_letters" / "final")
        jobsearch.build_argv(self.repo, ["true"])
        self.assertTrue((self.repo / "cover_letters" / "final").is_dir())

    def test_refuses_symlinked_masked_dir(self):
        shutil.rmtree(self.repo / "cv" / "final")
        (self.repo / "cv" / "final").symlink_to(self.base)
        with self.assertRaises(jobsearch.LauncherError):
            jobsearch.build_argv(self.repo, ["true"])

    def test_refuses_symlinked_parent(self):
        shutil.move(self.repo / "cv", self.base / "cv_real")
        (self.repo / "cv").symlink_to(self.base / "cv_real")
        with self.assertRaises(jobsearch.LauncherError):
            jobsearch.build_argv(self.repo, ["true"])


class KeepVisible(unittest.TestCase):
    def test_rebinds_target_inside_hidden_dir(self):
        with mock.patch("os.path.realpath", return_value="/mnt/wsl/resolv.conf"), \
             mock.patch("os.path.isfile", return_value=True):
            self.assertEqual(jobsearch.keep_visible(["/etc/resolv.conf"]),
                             ["--ro-bind", "/mnt/wsl/resolv.conf",
                              "/mnt/wsl/resolv.conf"])

    def test_ignores_target_outside_hidden_dirs(self):
        with mock.patch("os.path.realpath", return_value="/run/systemd/resolve/x"), \
             mock.patch("os.path.isfile", return_value=True):
            self.assertEqual(jobsearch.keep_visible(["/etc/resolv.conf"]), [])

    def test_prefix_is_not_enough(self):
        with mock.patch("os.path.realpath", return_value="/mntx/resolv.conf"), \
             mock.patch("os.path.isfile", return_value=True):
            self.assertEqual(jobsearch.keep_visible(["/etc/resolv.conf"]), [])

    def test_rebind_comes_after_hiding(self):
        base = Path(tempfile.mkdtemp())
        try:
            repo = make_repo(base)
            with mock.patch.object(jobsearch, "keep_visible",
                                   return_value=["--ro-bind", "/mnt/wsl/r", "/mnt/wsl/r"]), \
                 mock.patch("os.path.isdir", return_value=True):
                argv = jobsearch.build_argv(repo, ["true"])
            self.assertGreater(argv.index("/mnt/wsl/r"), argv.index("/mnt"))
        finally:
            shutil.rmtree(base)


class CleanEnv(unittest.TestCase):
    def test_drops_interop_and_windows_path(self):
        env = jobsearch.clean_env({
            "WSL_INTEROP": "/run/WSL/1_interop", "WSLENV": "X",
            "PATH": "/usr/bin:/mnt/c/Windows:/home/u/.local/bin:/mnt/c/x",
            "HOME": "/home/u"})
        self.assertNotIn("WSL_INTEROP", env)
        self.assertNotIn("WSLENV", env)
        self.assertEqual(env["PATH"], "/usr/bin:/home/u/.local/bin")
        self.assertEqual(env["HOME"], "/home/u")
        self.assertEqual(env[jobsearch.JAIL_MARKER], "1")


class ParseArgs(unittest.TestCase):
    def test_known_cli(self):
        repo, cmd = jobsearch.parse_args(["--repo", str(ROOT), "claude", "-c"])
        self.assertEqual((repo, cmd), (ROOT, ["claude", "-c"]))

    def test_unknown_cli_rejected(self):
        with self.assertRaises(jobsearch.LauncherError):
            jobsearch.parse_args(["bash"])

    def test_missing_repo_rejected(self):
        with self.assertRaises(FileNotFoundError):
            jobsearch.parse_args(["--repo", "/nonexistent/x", "claude"])


# Each attack prints whatever it manages to read. None may print a secret.
ATTACKS = r"""
R="$1"
echo "## plain read";      cat "$R"/private/* "$R"/cv/final/* "$R"/cover_letters/final/* 2>&1
echo "## recursive grep";  grep -r CANARY- "$R" 2>&1
echo "## find";            find "$R" -type f 2>&1
echo "## symlink";         ln -s "$R/private" /tmp/p && cat /tmp/p/* 2>&1
echo "## proc root";       for p in /proc/[0-9]*; do cat "$p/root$R/private/identity.enc" 2>/dev/null; done
echo "## proc pids";       ls -d /proc/[0-9]* 2>&1 | wc -l
echo "## nested unmount";  unshare -rm sh -c "umount '$R/private' 2>&1; umount -l '$R/cv/final' 2>&1; cat '$R'/private/* '$R'/cv/final/* 2>&1" 2>&1
echo "## inherited fds";   for f in /proc/self/fd/*; do n=${f##*/}; [ "$n" -gt 2 ] && timeout 2 cat "$f" 2>/dev/null | head -c 200; done; echo
echo "## windows";         ls /mnt 2>&1; ls /run/WSL 2>&1; echo "WSL_INTEROP=${WSL_INTEROP-unset}"
echo "## write-through";   echo planted > "$R/private/planted" && echo wrote
echo "## jail marker";     echo "JOBSEARCH_JAIL=${JOBSEARCH_JAIL-unset}"
"""


@unittest.skipUnless(IN_GATES, "needs user namespaces: runs inside jobsearch-gates")
class RedTeam(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = scratch_dir()
        cls.repo = make_repo(cls.base)
        # An fd to a secret, inheritable, as a careless parent might leak it.
        fd = os.open(cls.repo / "private" / "identity.enc", os.O_RDONLY)
        os.set_inheritable(fd, True)
        r = subprocess.run(
            [sys.executable, str(LAUNCHER), "--repo", str(cls.repo), "--",
             "bash", "-c", ATTACKS, "attack", str(cls.repo)],
            capture_output=True, text=True, timeout=120, pass_fds=(fd,),
            stdin=subprocess.DEVNULL,
            cwd=cls.repo)
        os.close(fd)
        cls.result = r
        cls.out = r.stdout + r.stderr

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base)

    def test_launcher_ran(self):
        self.assertIn("JOBSEARCH_JAIL=1", self.out, self.out)

    def test_no_secret_leaks(self):
        for value in SECRET_VALUES:
            self.assertNotIn(value, self.out, f"{value} leaked:\n{self.out}")

    def test_visible_canary_found(self):
        # Positive control: the same attacks do read files that are visible.
        self.assertIn(VISIBLE["cv/main_acme_dev.tex"], self.out, self.out)

    def test_only_jail_processes_visible(self):
        section = self.out.split("## proc pids")[1].split("##")[0]
        self.assertLessEqual(int(section.split()[0]), 5, section)

    def test_windows_hidden(self):
        self.assertIn("WSL_INTEROP=unset", self.out)

    def test_writes_to_masked_dir_do_not_reach_host(self):
        self.assertIn("wrote", self.out)
        self.assertFalse((self.repo / "private" / "planted").exists())

    def test_host_files_untouched(self):
        for rel, content in SECRET.items():
            self.assertEqual((self.repo / rel).read_text(), content + "\n")


if __name__ == "__main__":
    unittest.main()
