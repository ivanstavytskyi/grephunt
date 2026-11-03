"""Load descriptors from this directory.

A new scanner is a YAML file with an argument template. A Python hook in
scanner_hooks/ is only for tools that need more than the template gives.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from grephunt.scanner_catalog.launch import ScannerTool
from grephunt.scanner_catalog.descriptor import ToolDescriptor
from grephunt.scanner_hooks.bearer import BearerHook
from grephunt.scanner_hooks.dependencies import GrypeHook, OsvScannerHook
from grephunt.scanner_hooks.generic import GenericHook
from grephunt.scanner_hooks.semgrep import SemgrepHook
from grephunt.scanner_hooks.trivy import TrivyHook

_DIR = Path(__file__).resolve().parent
_HOOKS = {
    "bearer": BearerHook,
    "grype": GrypeHook,
    "osv-scanner": OsvScannerHook,
    "semgrep": SemgrepHook,
    "trivy": TrivyHook,
}


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
        hook_type = _HOOKS.get(name)
        if hook_type is not None and issubclass(hook_type, GenericHook):
            hook = hook_type(descriptor)
        elif hook_type is not None:
            hook = hook_type()
        elif descriptor.args is not None:
            hook = GenericHook(descriptor)
        else:
            raise ValueError(f"{name}.yaml has no args, and there is no Python hook for it")
        tools[name] = ScannerTool(descriptor, hook)
    return tools
