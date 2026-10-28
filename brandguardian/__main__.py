"""Command line: serve (default), review a file, validate the knowledge base, create a user."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from typing import List, Optional

from .app import build_app
from .config import load_settings
from .server import serve


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="brandguardian", description="Brand Guardian prototype")
    sub = parser.add_subparsers(dest="cmd")
    p_serve = sub.add_parser("serve", help="run the web app (default)")
    p_serve.add_argument("--port", type=int)
    p_review = sub.add_parser("review", help="review a text file and print flags as JSON")
    p_review.add_argument("path")
    sub.add_parser("check-kb", help="validate the knowledge base file")
    p_user = sub.add_parser("add-user", help="create a user and print a one-time token (production mode)")
    p_user.add_argument("--id", required=True)
    p_user.add_argument("--name", required=True)
    p_user.add_argument("--role", required=True)
    args = parser.parse_args(argv)

    settings = load_settings()
    if args.cmd in (None, "serve"):
        if getattr(args, "port", None) is not None:
            settings = replace(settings, port=args.port)
        serve(settings)
        return 0
    app = build_app(settings)
    if args.cmd == "check-kb":
        print(f"OK: {app.kb.version_label}, {len(app.kb.rules)} rules, {len(app.kb.ledger)} ledger entries, fingerprint {app.kb.fingerprint}")
        return 0
    if args.cmd == "review":
        with open(args.path, "r", encoding="utf-8") as handle:
            text = handle.read()
        print(json.dumps(app.reviews.review(text, use_ai=False), indent=2, ensure_ascii=False))
        return 0
    if args.cmd == "add-user":
        print(app.workflow.provision_user(args.id, args.name, args.role))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
