"""PDF document text extraction with pypdf and regex stream fallback."""
from __future__ import annotations

import io
import re

try:
    import pypdf
    _HAS_PYPDF = True
except ImportError:
    _HAS_PYPDF = False


def extract_pdf(content: bytes) -> str:
    """Extract plain text from a PDF file buffer."""
    if _HAS_PYPDF:
        import logging
        logging.getLogger("pypdf").setLevel(logging.ERROR)
        try:
            reader = pypdf.PdfReader(io.BytesIO(content))
            pages_text = []
            for page in reader.pages:
                t = page.extract_text()
                if t:
                    pages_text.append(t.strip())
            if pages_text:
                return "\n\n".join(pages_text)
        except Exception:
            pass  # Fall through to stream regex fallback

    # Pure standard library fallback: parse text blocks (/BT ... /ET) and literal strings
    text_chunks = []
    # Match strings inside parentheses in PDF text operators like (Hello World) Tj
    matches = re.findall(rb"\(([^\(\)\\]*(?:\\.[^\(\)\\]*)*)\)\s*(?:Tj|'|\")", content)
    for m in matches:
        try:
            decoded = m.decode("latin-1")
            # Unescape basic PDF escapes
            decoded = decoded.replace(r"\n", "\n").replace(r"\r", "\r").replace(r"\t", "\t")
            decoded = decoded.replace(r"\(", "(").replace(r"\)", ")").replace(r"\\", "\\")
            if decoded.strip():
                text_chunks.append(decoded)
        except Exception:
            continue

    if text_chunks:
        return " ".join(text_chunks)

    # If no text operators found, check for plain ASCII/UTF-8 streams
    plain_text = re.findall(rb"[\x20-\x7E\s]{15,}", content)
    readable = [c.decode("latin-1", errors="ignore").strip() for c in plain_text if len(c.strip()) > 20]
    return "\n\n".join(readable) if readable else ""
