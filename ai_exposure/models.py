from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Literal
from pydantic import BaseModel, Field


class Evidence(str, Enum):
    confirmed = "confirmed"
    probable = "probable"
    heuristic = "heuristic"


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ScanOptions(BaseModel):
    domain: str
    use_crtsh: bool = True
    max_hosts: int = 200
    extra_hosts: list[str] = Field(default_factory=list)
    use_dns_wordlist: bool = False
    wordlist_labels: list[str] | None = None  # None = core AI labels
    concurrency: int = 20
    timeout_seconds: float = 8.0
    ports: list[int] = Field(default_factory=lambda: [80, 443, 8000, 8080, 8501, 7860, 11434])
    replay_dir: str | None = None
    enabled_detectors: list[str] | None = None


class ProbeResult(BaseModel):
    host: str
    port: int
    scheme: str
    path: str
    status: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    error: str | None = None

    @property
    def url(self) -> str:
        default = (self.scheme == "https" and self.port == 443) or (self.scheme == "http" and self.port == 80)
        hostport = self.host if default else f"{self.host}:{self.port}"
        return f"{self.scheme}://{hostport}{self.path}"


class Finding(BaseModel):
    detector: str
    title: str
    host: str
    url: str
    severity: Severity
    evidence: Evidence
    owasp_llm: str | None = None
    detail: str = ""
    snippet: str = ""


class ScanResult(BaseModel):
    domain: str
    hosts_discovered: list[str] = Field(default_factory=list)
    hosts_alive: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime | None = None


class ProgressEvent(BaseModel):
    stage: Literal["discovery", "probe", "detect", "report"]
    message: str
    done: int = 0
    total: int = 0
