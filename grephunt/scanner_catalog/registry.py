"""Load descriptors from this directory. A new scanner is a new YAML file and, when needed, a hook."""
from __future__ import annotations

from pathlib import Path

import yaml

from grephunt.scanner_catalog.launch import ScannerTool
from grephunt.scanner_catalog.descriptor import ToolDescriptor
from grephunt.scanner_hooks.bearer import BearerHook
from grephunt.scanner_hooks.semgrep import SemgrepHook
from grephunt.scanner_hooks.trivy import TrivyHook

_DIR = Path(__file__).resolve().parent
_HOOKS = {
    "bearer": BearerHook,
    "semgrep": SemgrepHook,
    "trivy": TrivyHook,
}


class PassthroughHook:
    """A tool with no special behavior. Arguments come from the caller as-is."""

    def __init__(self, name: str) -> None:
        self.name = name

    def is_applicable(self, project) -> bool:
        return True

    def wants_network(self, descriptor, options) -> bool:
        return descriptor.network

    def extra_mounts(self, options, use_docker: bool):
        return []

    def build_args(self, descriptor, src, output, options, use_docker: bool) -> list[str]:
        return []

    def refine_finding(self, finding, result, rule):
        return finding


def load_descriptors(directory: Path | None = None) -> dict[str, ToolDescriptor]:
    folder = directory or _DIR
    found: dict[str, ToolDescriptor] = {}
    for path in sorted(folder.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        descriptor = ToolDescriptor.model_validate(raw)
        found[descriptor.name] = descriptor
    return found


def load_tools(directory: Path | None = None) -> dict[str, ScannerTool]:
    tools: dict[str, ScannerTool] = {}
    for name, descriptor in load_descriptors(directory).items():
        hook_type = _HOOKS.get(name, PassthroughHook)
        hook = hook_type() if hook_type is not PassthroughHook else PassthroughHook(name)
        tools[name] = ScannerTool(descriptor, hook)
    return tools
