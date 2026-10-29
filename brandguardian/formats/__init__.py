"""Multi-format review entry point: DOCX, PDF, HTML, and Images (Accessibility Lens)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .docx import extract_docx
from .html import extract_html
from .lens import evaluate_accessibility_lens, extract_advisory_image_text, palette_distance
from .pdf import extract_pdf


@dataclass
class DocumentExtraction:
    format: str
    text: str
    advisory: bool = False
    note: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    lens: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": self.format,
            "text": self.text,
            "advisory": self.advisory,
            "note": self.note,
            "metadata": self.metadata,
            "lens": self.lens,
        }


def extract_document(filename: str, content: bytes, mime_type: Optional[str] = None) -> DocumentExtraction:
    """Extract text and metadata from any supported document format."""
    ext = os.path.splitext(filename.lower())[1]

    if ext == ".docx":
        text = extract_docx(content)
        return DocumentExtraction(format="docx", text=text, metadata={"filename": filename})

    if ext == ".pdf":
        text = extract_pdf(content)
        return DocumentExtraction(format="pdf", text=text, metadata={"filename": filename})

    if ext in {".html", ".htm"}:
        text, meta = extract_html(content)
        return DocumentExtraction(format="html", text=text, metadata={"filename": filename, **meta})

    if ext in {".png", ".jpg", ".jpeg", ".svg", ".webp"}:
        ocr = extract_advisory_image_text(content, filename)
        lens_eval = None
        if ocr.get("regions"):
            lens_eval = evaluate_accessibility_lens(ocr["regions"])
        return DocumentExtraction(
            format="image",
            text=ocr["text"],
            advisory=True,
            note="OCR advisory: text extracted from graphic; verify against original visual.",
            metadata={"filename": filename},
            lens=lens_eval,
        )

    # Fallback to UTF-8 text decode
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = content.decode("latin-1", errors="ignore")
    return DocumentExtraction(format="text", text=text, metadata={"filename": filename})

