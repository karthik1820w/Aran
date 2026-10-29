"""DOCX document text extraction using only standard library (zipfile + xml)."""
from __future__ import annotations

import io
import xml.etree.ElementTree as ET
import zipfile


def extract_docx(content: bytes) -> str:
    """Extract plain text paragraphs from a .docx file buffer."""
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as docx:
            xml_content = docx.read("word/document.xml")
    except Exception as exc:
        raise ValueError(f"Invalid DOCX file or structure: {exc}") from exc

    import re
    try:
        tree = ET.fromstring(xml_content)
    except ET.ParseError:
        # If unbound prefix in custom/test XML, strip prefix tags
        clean_xml = re.sub(r'<(/?)w:', r'<\1', xml_content.decode('utf-8', errors='ignore'))
        tree = ET.fromstring(clean_xml)
    # The Word XML namespace for text elements is typically {http://schemas.openxmlformats.org/wordprocessingml/2006/main}
    paragraphs = []
    # Find all paragraph tags <w:p>
    for p in tree.iter():
        if p.tag.endswith("}p") or p.tag == "p":
            text_parts = []
            for t in p.iter():
                if (t.tag.endswith("}t") or t.tag == "t") and t.text:
                    text_parts.append(t.text)
            p_text = "".join(text_parts).strip()
            if p_text:
                paragraphs.append(p_text)

    return "\n\n".join(paragraphs)
