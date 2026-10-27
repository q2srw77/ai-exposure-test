"""Auto-import detector modules so they self-register. New detector = one new file under this package."""

from __future__ import annotations

import importlib
import pkgutil

from .base import Detector, all_extra_paths, enabled_detectors, get_registry, register

# Import every sibling module (except base) so Detector subclasses register themselves.
for _info in pkgutil.iter_modules(__path__, __name__ + "."):
    if _info.name.rsplit(".", 1)[-1] == "base":
        continue
    importlib.import_module(_info.name)

__all__ = [
    "Detector",
    "register",
    "get_registry",
    "all_extra_paths",
    "enabled_detectors",
]
