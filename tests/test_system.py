"""Runs the real-browser journey (Playwright + Chromium) as part of the Python suite when it is available."""
import os
import shutil
import subprocess
import sys
import unittest

from helpers import ROOT


def browser_available():
    if not shutil.which("node"):
        return False
    try:
        npm_cmd = shutil.which("npm") or "npm"
        npm_root = subprocess.run([npm_cmd, "root", "-g"], capture_output=True, text=True).stdout.strip()
        return bool(npm_root) and os.path.isdir(os.path.join(npm_root, "playwright"))
    except (FileNotFoundError, OSError):
        return False


@unittest.skipUnless(browser_available(), "node + playwright not installed; run `make e2e` where they are available")
class BrowserJourneyTests(unittest.TestCase):
    def test_full_user_journey_in_a_real_browser(self):
        proc = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "run_e2e.py")], capture_output=True, text=True, timeout=300)
        self.assertEqual(proc.returncode, 0, proc.stdout[-3000:] + proc.stderr[-2000:])
        self.assertIn("18/18 browser steps passed", proc.stdout)


if __name__ == "__main__":
    unittest.main()
