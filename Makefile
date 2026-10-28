PY ?= python3

.PHONY: run test test-js e2e coverage bench check-kb all clean

run:            ## start the web app on http://127.0.0.1:8000
	$(PY) -m brandguardian

test:           ## Python unit, integration, API and system tests (standard library only)
	$(PY) -m unittest discover -s tests

test-js:        ## UI logic tests (Node 18+ built-in runner)
	node --test tests/js/logic.test.mjs

e2e:            ## real-browser journey (needs Node + Playwright + Chromium)
	$(PY) scripts/run_e2e.py

coverage:       ## line coverage using only the standard library
	$(PY) scripts/coverage_report.py --min 90

bench:          ## measure review latency on this machine
	$(PY) scripts/benchmark.py

check-kb:       ## validate the knowledge base file
	$(PY) -m brandguardian check-kb

all: test test-js e2e coverage

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
