"""Checks that the gate jail is what jobsearch-gates promises, and the first
spike question: can bubblewrap nest two levels deep there? Two levels are
needed because the privacy launcher is one bwrap and each agent CLI's own
sandbox (Claude Code's, for example) is another one inside it.

These tests only run inside jobsearch-gates (JOBSEARCH_GATES=1).
"""

import os
import shutil
import socket
import subprocess
import unittest

IN_GATES = os.environ.get("JOBSEARCH_GATES") == "1"
BWRAP_MIN = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
             "--unshare-all", "--die-with-parent"]


@unittest.skipUnless(IN_GATES, "runs only inside jobsearch-gates")
class GateJail(unittest.TestCase):
    def test_no_network(self):
        with self.assertRaises(OSError):
            socket.create_connection(("1.1.1.1", 443), timeout=3)

    def test_home_is_empty(self):
        self.assertEqual(os.listdir(os.path.expanduser("~")), [])

    def test_windows_drive_absent(self):
        self.assertFalse(os.path.exists("/mnt/c"))

    def test_agent_credentials_absent(self):
        for p in ("~/.claude", "~/.codex", "~/.copilot", "~/.gemini", "~/.ssh"):
            self.assertFalse(os.path.exists(os.path.expanduser(p)), p)


@unittest.skipUnless(IN_GATES, "runs only inside jobsearch-gates")
class NestedBubblewrap(unittest.TestCase):
    def setUp(self):
        if shutil.which("bwrap") is None:
            self.fail("bwrap not installed")

    def test_one_level(self):
        r = subprocess.run(BWRAP_MIN + ["true"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_two_levels(self):
        r = subprocess.run(BWRAP_MIN + BWRAP_MIN + ["true"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
