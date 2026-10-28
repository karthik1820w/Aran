"""WCAG 2.x colour contrast (exact formula, no AI)."""
from __future__ import annotations

import re
from typing import Any, Dict, Tuple

_HEX = re.compile(r"^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")


class ColourError(ValueError):
    pass


def parse_hex(value: str) -> Tuple[int, int, int]:
    if not isinstance(value, str):
        raise ColourError("colour must be a string like #1a2b3c")
    m = _HEX.match(value.strip())
    if not m:
        raise ColourError(f"not a valid hex colour: {value!r}")
    digits = m.group(1)
    if len(digits) == 3:
        digits = "".join(c * 2 for c in digits)
    return int(digits[0:2], 16), int(digits[2:4], 16), int(digits[4:6], 16)


def to_hex(rgb: Tuple[int, int, int]) -> str:
    return "#%02x%02x%02x" % rgb


def _channel(c: int) -> float:
    s = c / 255
    return s / 12.92 if s <= 0.03928 else ((s + 0.055) / 1.055) ** 2.4


def luminance(rgb: Tuple[int, int, int]) -> float:
    r, g, b = (_channel(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(fg: str, bg: str) -> float:
    l1, l2 = luminance(parse_hex(fg)), luminance(parse_hex(bg))
    hi, lo = max(l1, l2), min(l1, l2)
    return (hi + 0.05) / (lo + 0.05)


def _blend(rgb: Tuple[int, int, int], target: int, amount: float) -> Tuple[int, int, int]:
    return tuple(round(c + (target - c) * amount) for c in rgb)  # type: ignore[return-value]


def evaluate(fg: str, bg: str, large: bool = False) -> Dict[str, Any]:
    """Return the ratio, AA/AAA results and, when AA fails, the nearest passing foreground."""
    ratio = contrast_ratio(fg, bg)
    aa_min, aaa_min = (3.0, 4.5) if large else (4.5, 7.0)
    result: Dict[str, Any] = {
        "foreground": to_hex(parse_hex(fg)), "background": to_hex(parse_hex(bg)), "large_text": bool(large),
        "ratio": round(ratio, 2), "aa": ratio >= aa_min, "aaa": ratio >= aaa_min,
        "aa_minimum": aa_min, "aaa_minimum": aaa_min, "suggested_foreground": None,
    }
    if not result["aa"]:
        rgb, bg_lum = parse_hex(fg), luminance(parse_hex(bg))
        target = 0 if bg_lum > 0.18 else 255  # darken on light backgrounds, lighten on dark ones
        for step in range(1, 101):
            candidate = to_hex(_blend(rgb, target, step / 100))
            if contrast_ratio(candidate, bg) >= aa_min:
                result["suggested_foreground"] = candidate
                break
    return result
