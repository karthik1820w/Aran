"""HTML / Web text extraction using standard library html.parser."""
from __future__ import annotations

from html.parser import HTMLParser
from typing import Any, Dict, List, Tuple


class TextExtractParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.pieces: List[str] = []
        self.images: List[Dict[str, str]] = []
        self.links: List[Dict[str, str]] = []
        self._ignore = False
        self._current_tag = ""

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        self._current_tag = tag.lower()
        if self._current_tag in {"script", "style", "noscript", "svg"}:
            self._ignore = True
            return

        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        if self._current_tag == "img":
            alt = attr_dict.get("alt", "")
            src = attr_dict.get("src", "")
            self.images.append({"alt": alt, "src": src})
            # Insert markdown-style representation so existing alt-text detectors work
            self.pieces.append(f' ![alt="{alt}"]({src}) ')
        elif self._current_tag == "a":
            href = attr_dict.get("href", "")
            self.links.append({"href": href})
        elif self._current_tag in {"p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "li", "br"}:
            self.pieces.append("\n")

    def handle_endtag(self, tag: str):
        if tag.lower() in {"script", "style", "noscript", "svg"}:
            self._ignore = False
        elif tag.lower() in {"p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "li"}:
            self.pieces.append("\n")

    def handle_data(self, data: str):
        if not self._ignore:
            cleaned = data.strip()
            if cleaned:
                self.pieces.append(data)


def extract_html(content: bytes | str) -> Tuple[str, Dict[str, Any]]:
    """Extract visible plain text and accessibility metadata from HTML."""
    if isinstance(content, bytes):
        try:
            html_str = content.decode("utf-8")
        except UnicodeDecodeError:
            html_str = content.decode("latin-1", errors="ignore")
    else:
        html_str = content

    parser = TextExtractParser()
    parser.feed(html_str)
    full_text = "".join(parser.pieces).strip()
    # Normalize multiple line breaks
    import re
    full_text = re.sub(r"\n{3,}", "\n\n", full_text)
    metadata = {
        "images_found": len(parser.images),
        "links_found": len(parser.links),
        "images": parser.images,
    }
    return full_text, metadata

