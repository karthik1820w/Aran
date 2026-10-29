"""Vercel Serverless Function entrypoint."""
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from brandguardian.server import BGHandler, wsgi_app

app = wsgi_app
handler = BGHandler

