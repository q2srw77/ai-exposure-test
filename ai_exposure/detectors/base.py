from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from ..models import Finding, ProbeResult

_REGISTRY: dict[str, "Detector"] = {}


class Detector(ABC):
    """Detector plugin. Subclasses with a `name` register themselves on definition."""

    name: ClassVar[str]
    extra_paths: ClassVar[list[str]] = []

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        # Skip abstract / incomplete subclasses.
        if ABC in cls.__bases__:
            return
        name = cls.__dict__.get("name")
        if not name:
            return
        if getattr(cls, "__abstractmethods__", None):
            return
        register(cls())  # type: ignore[call-arg]

    @abstractmethod
    def analyze(self, probe: ProbeResult) -> list[Finding]:
        ...


def register(detector: Detector) -> None:
    _REGISTRY[detector.name] = detector


def get_registry() -> dict[str, Detector]:
    return dict(_REGISTRY)


def all_extra_paths(enabled: list[str] | None = None) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for name, det in _REGISTRY.items():
        if enabled is not None and name not in enabled:
            continue
        for p in det.extra_paths:
            if p not in seen:
                seen.add(p)
                paths.append(p)
    return paths


def enabled_detectors(names: list[str] | None = None) -> list[Detector]:
    if names is None:
        return list(_REGISTRY.values())
    return [_REGISTRY[n] for n in names if n in _REGISTRY]
