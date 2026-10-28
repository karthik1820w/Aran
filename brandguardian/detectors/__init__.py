"""Detector registry. Order matters only for the order results stream to the user."""
from __future__ import annotations

from typing import Tuple

from . import accessibility, claims, injection, pii, restricted, terminology, voice
from .base import Context, Detector, DetectorOutput

DETECTORS: Tuple[Detector, ...] = (
    Detector("injection", "Instructions hidden in content", injection.run),
    Detector("pii", "Personal data and credentials", pii.run),
    Detector("restricted", "Restricted phrases", restricted.run),
    Detector("terminology", "Approved terminology", terminology.run),
    Detector("claims", "Claims against the Claim Ledger", claims.run),
    Detector("voice", "Voice and readability", voice.run),
    Detector("accessibility", "Accessibility of images and links", accessibility.run),
)

__all__ = ["DETECTORS", "Context", "Detector", "DetectorOutput"]
