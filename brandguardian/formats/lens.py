"""Accessibility Lens: palette distance, contrast overlay and advisory OCR extraction."""
from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..contrast import evaluate, parse_hex

# Default fallback brand palette if brand config doesn't specify one
DEFAULT_BRAND_PALETTE = ["#1B365D", "#4A777A", "#D96B43", "#F4E8D1", "#FFFFFF", "#111111"]


def rgb_distance(hex_a: str, hex_b: str) -> float:
    """Calculate Euclidean color distance in RGB space (0 to ~441.7)."""
    r1, g1, b1 = parse_hex(hex_a)
    r2, g2, b2 = parse_hex(hex_b)
    return math.sqrt((r1 - r2) ** 2 + (g1 - g2) ** 2 + (b1 - b2) ** 2)


def palette_distance(color_hex: str, brand_palette: Sequence[str]) -> Tuple[float, str]:
    """Find distance to the closest brand palette color and return (distance, nearest_hex)."""
    palette = list(brand_palette) if brand_palette else DEFAULT_BRAND_PALETTE
    best_dist = float("inf")
    best_color = palette[0]
    for c in palette:
        try:
            d = rgb_distance(color_hex, c)
            if d < best_dist:
                best_dist = d
                best_color = c
        except Exception:
            continue
    return round(best_dist, 1), best_color


def evaluate_accessibility_lens(
    regions: Sequence[Dict[str, Any]],
    brand_palette: Optional[Sequence[str]] = None,
    distance_threshold: float = 35.0,
) -> Dict[str, Any]:
    """Examine poster or graphic visual regions for color compliance and WCAG contrast.
    
    Each region dict may contain:
    - id: str
    - label: str (e.g. 'Headline', 'CTA button', 'Footer')
    - fg: str (#hex)
    - bg: str (#hex)
    - large: bool
    - bounds: optional dict {x, y, w, h}
    """
    palette = list(brand_palette) if brand_palette else DEFAULT_BRAND_PALETTE
    results: List[Dict[str, Any]] = []
    palette_flags: List[Dict[str, Any]] = []
    contrast_flags: List[Dict[str, Any]] = []

    for reg in regions:
        fg = reg.get("fg", "#000000")
        bg = reg.get("bg", "#ffffff")
        large = bool(reg.get("large", False))
        label = reg.get("label", "Element")
        reg_id = reg.get("id", f"reg-{len(results) + 1}")
        bounds = reg.get("bounds", {"x": 0, "y": 0, "w": 100, "h": 50})

        # 1. Palette check for foreground and background
        fg_dist, nearest_fg = palette_distance(fg, palette)
        bg_dist, nearest_bg = palette_distance(bg, palette)

        is_fg_off = fg_dist > distance_threshold
        is_bg_off = bg_dist > distance_threshold

        if is_fg_off:
            palette_flags.append({
                "region_id": reg_id,
                "label": label,
                "color": fg,
                "distance": fg_dist,
                "nearest_brand_color": nearest_fg,
                "role": "foreground",
                "message": f"Colour {fg} on '{label}' is off-palette (distance {fg_dist} to nearest approved colour {nearest_fg}).",
            })
        if is_bg_off:
            palette_flags.append({
                "region_id": reg_id,
                "label": label,
                "color": bg,
                "distance": bg_dist,
                "nearest_brand_color": nearest_bg,
                "role": "background",
                "message": f"Background colour {bg} on '{label}' is off-palette (distance {bg_dist} to nearest approved colour {nearest_bg}).",
            })

        # 2. WCAG Contrast check
        try:
            eval_res = evaluate(fg, bg, large=large)
            contrast_ratio = eval_res["ratio"]
            passes_aa = eval_res.get("aa", False)
            suggestion = eval_res.get("suggested_foreground") or fg
        except Exception:
            contrast_ratio = 1.0
            passes_aa = False
            suggestion = "#000000"

        if not passes_aa:
            min_target = "3.0:1" if large else "4.5:1"
            contrast_flags.append({
                "region_id": reg_id,
                "label": label,
                "ratio": contrast_ratio,
                "required": min_target,
                "fg": fg,
                "bg": bg,
                "suggested_fg": suggestion,
                "message": f"Contrast ratio {contrast_ratio}:1 on '{label}' fails WCAG AA minimum of {min_target}. Suggest: {suggestion}.",
                "bounds": bounds,
            })

        results.append({
            "id": reg_id,
            "label": label,
            "fg": fg,
            "bg": bg,
            "large": large,
            "bounds": bounds,
            "contrast_ratio": contrast_ratio,
            "passes_wcag_aa": passes_aa,
            "suggested_passing_fg": suggestion,
            "fg_palette_distance": fg_dist,
            "bg_palette_distance": bg_dist,
            "is_off_palette": is_fg_off or is_bg_off,
        })

    return {
        "regions": results,
        "palette_flags": palette_flags,
        "contrast_flags": contrast_flags,
        "compliant": (len(palette_flags) == 0 and len(contrast_flags) == 0),
        "total_regions": len(results),
        "brand_palette": palette,
    }


def extract_advisory_image_text(content: bytes, filename: str) -> Dict[str, Any]:
    """Extract advisory text and color metadata from image bytes (PNG, SVG, or general image).
    
    OCR quality varies, so all extracted text is marked as advisory.
    """
    fn_lower = filename.lower()
    text_chunks: List[str] = []
    regions: List[Dict[str, Any]] = []

    # SVG handling: extract text tags and fill/stroke colors directly
    if fn_lower.endswith(".svg"):
        try:
            svg_str = content.decode("utf-8")
        except UnicodeDecodeError:
            svg_str = content.decode("latin-1", errors="ignore")

        # Extract text tags: <text ...>content</text>
        svg_texts = re.findall(r"<text[^>]*>(.*?)</text>", svg_str, re.DOTALL | re.IGNORECASE)
        for t in svg_texts:
            clean = re.sub(r"<[^>]+>", "", t).strip()
            if clean:
                text_chunks.append(clean)

        # Extract color attributes like fill="#..."
        colors = re.findall(r'(?:fill|stroke|color)\s*=\s*["\'](#[0-9a-fA-F]{3,6})["\']', svg_str)
        if len(colors) >= 2:
            regions.append({
                "id": "svg-elem-1",
                "label": "SVG graphic element",
                "fg": colors[0],
                "bg": colors[1],
                "large": False,
            })
    elif fn_lower.endswith(".png"):
        # Check for PNG tEXt chunks: chunk format [length 4B][type 4B 'tEXt'][key\0value][CRC 4B]
        idx = 8
        while idx < len(content) - 12:
            try:
                length = int.from_bytes(content[idx:idx+4], "big")
                ctype = content[idx+4:idx+8]
                if ctype == b"tEXt":
                    data = content[idx+8:idx+8+length]
                    parts = data.split(b"\x00", 1)
                    if len(parts) == 2:
                        val = parts[1].decode("latin-1", errors="ignore").strip()
                        if val:
                            text_chunks.append(val)
                idx += 12 + length
            except Exception:
                break

    # Fallback heuristic: look for ASCII strings in binary that look like readable phrases
    if not text_chunks:
        raw_strings = re.findall(rb"[\x20-\x7E]{10,}", content)
        for s in raw_strings[:5]:
            decoded = s.decode("latin-1", errors="ignore").strip()
            if not any(k in decoded for k in ["Creator", "Photoshop", "Adobe", "Exif", "http"]):
                text_chunks.append(decoded)

    extracted_text = " ".join(text_chunks).strip()
    return {
        "text": extracted_text,
        "advisory": True,
        "note": "OCR advisory: text extracted from graphic; verify against original visual.",
        "regions": regions,
    }
