"""Line coverage of the brandguardian package using only the standard library (`trace`).

Runs the in-process tests (subprocess and browser tests exercise the same code but are not traced). Usage:
    python scripts/coverage_report.py [--min 85]
"""
import argparse
import os
import sys
import threading
import trace
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--min", type=float, default=0.0, help="fail if total coverage is below this percentage")
    parser.add_argument("--detail", action="store_true", help="list uncovered line numbers")
    args = parser.parse_args()

    tracer = trace.Trace(count=True, trace=False, ignoredirs=[sys.prefix, sys.exec_prefix])
    skip = ("test_cli", "test_system")

    def run_all():
        # Discovery happens inside the traced call so that import-time lines (def, class, imports) are counted too.
        suite = unittest.defaultTestLoader.discover(os.path.join(ROOT, "tests"), pattern="test_*.py")
        filtered = unittest.TestSuite()
        for group in suite:
            for case in group:
                if not any(s in type(case).__module__ for s in skip):
                    filtered.addTest(case)
        return unittest.TextTestRunner(verbosity=0, stream=open(os.devnull, "w")).run(filtered)

    threading.settrace(tracer.globaltrace)  # follow the HTTP server threads started by the API tests
    result = tracer.runfunc(run_all)

    counts = tracer.results().counts
    pkg = os.path.join(ROOT, "brandguardian")
    rows, total_exec, total_hit = [], 0, 0
    for dirpath, _, files in os.walk(pkg):
        for name in sorted(files):
            if not name.endswith(".py"):
                continue
            path = os.path.join(dirpath, name)
            executable = set(trace._find_executable_linenos(path))
            hit = {line for (fname, line), n in counts.items() if fname == path and n > 0} & executable
            total_exec += len(executable)
            total_hit += len(hit)
            pct = 100.0 * len(hit) / len(executable) if executable else 100.0
            rows.append((os.path.relpath(path, ROOT), len(executable), len(hit), pct, sorted(executable - hit)))
    print(f"{'file':44} {'lines':>6} {'hit':>6} {'cover':>7}")
    for rel, n, h, pct, missing in sorted(rows, key=lambda r: r[3]):
        print(f"{rel:44} {n:6d} {h:6d} {pct:6.1f}%")
    total = 100.0 * total_hit / total_exec if total_exec else 100.0
    print(f"{'TOTAL':44} {total_exec:6d} {total_hit:6d} {total:6.1f}%")
    print(f"tests run: {result.testsRun}, failures: {len(result.failures)}, errors: {len(result.errors)}")
    if args.detail:
        for rel, _, _, _, missing in rows:
            if missing:
                print(rel, missing)
    return 0 if result.wasSuccessful() and total >= args.min else 1


if __name__ == "__main__":
    sys.exit(main())
