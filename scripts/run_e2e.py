"""Start a throwaway server on a free port and run the browser journey against it."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.path.insert(0, ROOT)

from apiclient import RunningServer  # noqa: E402


def main() -> int:
    server = RunningServer()
    try:
        env = dict(os.environ, BG_URL=f"http://127.0.0.1:{server.port}")
        env.setdefault("NODE_PATH", subprocess.run(["npm", "root", "-g"], capture_output=True, text=True).stdout.strip())
        return subprocess.call(["node", os.path.join(ROOT, "tests", "e2e", "journey.cjs")], env=env)
    finally:
        server.close()


if __name__ == "__main__":
    sys.exit(main())
