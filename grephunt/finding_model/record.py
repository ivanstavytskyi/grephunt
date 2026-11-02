"""Finding contract. Reporters, the API, and a future AI agent read this object.

SAST fills location.kind = file. The url and service kinds are reserved
for OSINT, monitoring, and pentest so every module shares one record.
"""
from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, computed_field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    CODE = "code"
    SECRET = "secret"
    DEPENDENCY = "dependency"
    MISCONFIG = "misconfig"


class Module(str, Enum):
    SAST = "sast"
    MONITORING = "monitoring"
    OSINT = "osint"
    PENTEST = "pentest"


class FindingStatus(str, Enum):
    OPEN = "open"
    FIXED = "fixed"
    SUPPRESSED = "suppressed"


class LocationKind(str, Enum):
    FILE = "file"
    URL = "url"
    SERVICE = "service"


class Location(BaseModel):
    """Where the finding is. One kind of field is filled. The others stay empty."""

    kind: LocationKind = LocationKind.FILE
    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    url: str | None = None
    parameter: str | None = None
    host: str | None = None
    port: int | None = None

    @property
    def label(self) -> str:
        if self.kind is LocationKind.FILE:
            if self.path and self.start_line:
                return f"{self.path}:{self.start_line}"
            return self.path or ""
        if self.kind is LocationKind.URL:
            if self.url and self.parameter:
                return f"{self.url}?{self.parameter}"
            return self.url or ""
        if self.host and self.port:
            return f"{self.host}:{self.port}"
        return self.host or ""


class Finding(BaseModel):
    """A normalized finding. Raw scanner output is not stored here."""

    model_config = ConfigDict(use_enum_values=False)

    module: Module = Module.SAST
    category: Category = Category.CODE
    tool: str
    tool_version: str | None = None
    tools: list[str] = Field(default_factory=list)
    rule_id: str
    title: str
    message: str = ""
    severity: Severity
    severity_original: str | None = None
    cwe: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    location: Location
    snippet: str | None = None
    evidence: str | None = None
    status: FindingStatus = FindingStatus.OPEN
    raw_ref: str | None = None
    help_uri: str | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None

    def model_post_init(self, __context: object) -> None:
        if not self.tools:
            self.tools = [self.tool]

    def _dependency_identity(self) -> str:
        cve = ",".join(sorted(self.cve))
        package = (self.package or "").lower()
        return f"dep:{package}:{self.installed_version or ''}:{cve}"

    @computed_field
    @property
    def correlation_key(self) -> str:
        """Correlation inside one scan. The line number is part of the key."""
        if self.category is Category.DEPENDENCY and self.cve:
            return self._dependency_identity()
        path = self.location.path or ""
        line = self.location.start_line
        if self.category is Category.SECRET:
            return f"secret:{path}:{line}"
        if self.cwe:
            return f"{self.category.value}:{path}:{line}:{','.join(sorted(self.cwe))}"
        return f"{self.category.value}:{path}:{line}:{self.tool}:{self.rule_id}"

    @computed_field
    @property
    def fingerprint(self) -> str:
        """Identity across scans. The line number is omitted, so a shifted line is not a new problem.

        Two identical CWE hits in one file share a fingerprint. The problem stays
        open until every such location in the file is gone.
        """
        if self.category is Category.DEPENDENCY and self.cve:
            return self._dependency_identity()
        path = self.location.path or ""
        if self.category is Category.SECRET:
            return f"secret:{path}:{self.rule_id}"
        if self.cwe:
            return f"{self.category.value}:{path}:{','.join(sorted(self.cwe))}"
        return f"{self.category.value}:{path}:{self.tool}:{self.rule_id}"


class TaskStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


class TaskRun(BaseModel):
    """One scan task is one run of one tool."""

    tool: str
    status: TaskStatus
    duration_sec: float = 0.0
    tool_version: str | None = None
    image: str | None = None
    sarif_path: Path | None = None
    error: str | None = None
    findings: list[Finding] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Pipeline result. Reporters read only this object."""

    id: str
    target: str
    runs: list[TaskRun]
    findings: list[Finding] = Field(default_factory=list)
    excluded: int = 0
    raw_total: int = 0
    merged_sarif: Path | None = None
