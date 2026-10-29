"""Vercel / WSGI / standalone entrypoint for Aran."""
import os
import sys

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from brandguardian.server import BGHandler, wsgi_app

# Vercel discovers either `app` (WSGI/ASGI) or `handler` (BaseHTTPRequestHandler)
app = wsgi_app
handler = BGHandler

if __name__ == "__main__":
    from brandguardian.__main__ import main

    main()
