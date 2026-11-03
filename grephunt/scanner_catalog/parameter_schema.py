"""Validate per-tool scan parameters declared in YAML descriptors."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from grephunt.scanner_catalog.descriptor import ParameterSpec, ToolDescriptor

_REGISTRY_CONFIG = re.compile(r"^[pr]/[A-Za-z0-9_./-]{1,120}$")


def default_values(descriptor: ToolDescriptor) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for spec in descriptor.parameters:
        if spec.default is not None:
            values[spec.name] = _copy_default(spec)
        elif spec.type == "multi":
            values[spec.name] = list(spec.choices)
        elif spec.type == "string_list":
            values[spec.name] = []
        else:
            values[spec.name] = ""
    return values


def _copy_default(spec: ParameterSpec) -> Any:
    if spec.type == "multi" or spec.type == "string_list":
        if isinstance(spec.default, list):
            return [str(item) for item in spec.default]
        if isinstance(spec.default, str) and spec.type == "string_list":
            return [item.strip() for item in spec.default.split(",") if item.strip()]
        return []
    if isinstance(spec.default, str):
        return spec.default
    return ""


def _valid_config_entry(value: str) -> bool:
    text = value.strip()
    if not text:
        return False
    if _REGISTRY_CONFIG.match(text):
        return True
    if text.startswith(("http://", "https://")):
        parsed = urlparse(text)
        return bool(parsed.scheme and parsed.netloc)
    return True


def coerce_parameter(spec: ParameterSpec, raw: Any) -> Any:
    if spec.type == "multi":
        items = raw
        if items is None:
            items = spec.default if spec.default is not None else spec.choices
        if isinstance(items, str):
            items = [part.strip() for part in items.split(",") if part.strip()]
        if not isinstance(items, list):
            raise ValueError(f"{spec.name} must be a list")
        allowed = {choice.lower(): choice for choice in spec.choices}
        if not allowed:
            raise ValueError(f"{spec.name} has no choices in the descriptor")
        cleaned: list[str] = []
        for item in items:
            key = str(item).strip().lower()
            if key not in allowed:
                raise ValueError(f"{spec.name}: unknown value {item!r}")
            canonical = allowed[key]
            if canonical not in cleaned:
                cleaned.append(canonical)
        if not cleaned:
            raise ValueError(f"{spec.name}: pick at least one value")
        return cleaned

    if spec.type == "string_list":
        items = raw
        if items is None:
            items = spec.default
        if isinstance(items, str):
            items = [part.strip() for part in items.split(",") if part.strip()]
        if not isinstance(items, list):
            raise ValueError(f"{spec.name} must be a list of strings")
        cleaned = [str(item).strip() for item in items if str(item).strip()]
        if not cleaned:
            raise ValueError(f"{spec.name}: add at least one entry")
        bad = [item for item in cleaned if not _valid_config_entry(item)]
        if bad:
            raise ValueError(f"{spec.name}: invalid ruleset {bad[0]!r}")
        return cleaned

    text = "" if raw is None else str(raw).strip()
    if not text:
        if isinstance(spec.default, str) and spec.default.strip():
            return spec.default.strip()
        raise ValueError(f"{spec.name} cannot be empty")
    return text


def validate_tool_params(descriptor: ToolDescriptor, raw: dict[str, Any] | None) -> dict[str, Any]:
    incoming = raw or {}
    unknown = sorted(key for key in incoming if key not in {spec.name for spec in descriptor.parameters})
    if unknown:
        raise ValueError(f"{descriptor.name}: unknown parameter(s) {', '.join(unknown)}")
    values: dict[str, Any] = {}
    for spec in descriptor.parameters:
        values[spec.name] = coerce_parameter(spec, incoming.get(spec.name))
    return values


def validate_scan_params(
    scanners: list[str],
    descriptors: dict[str, ToolDescriptor],
    raw: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    incoming = raw or {}
    validated: dict[str, dict[str, Any]] = {}
    for name in scanners:
        descriptor = descriptors.get(name)
        if descriptor is None or not descriptor.parameters:
            continue
        tool_raw = incoming.get(name)
        if not isinstance(tool_raw, dict):
            tool_raw = {}
        validated[name] = validate_tool_params(descriptor, tool_raw)
    extra = sorted(key for key in incoming if key not in scanners)
    if extra:
        raise ValueError(f"params for scanners that are not selected: {', '.join(extra)}")
    return validated


def parameter_summaries(
    descriptors: dict[str, ToolDescriptor],
    params: dict[str, dict[str, Any]],
) -> dict[str, str]:
    lines: dict[str, str] = {}
    for tool, values in params.items():
        descriptor = descriptors.get(tool)
        if descriptor is None:
            continue
        parts: list[str] = []
        for spec in descriptor.parameters:
            value = values.get(spec.name)
            if spec.type == "multi" and isinstance(value, list):
                parts.append(", ".join(value))
            elif spec.type == "string_list" and isinstance(value, list):
                shown = value[:2]
                tail = "…" if len(value) > 2 else ""
                parts.append(", ".join(shown) + tail)
            elif isinstance(value, str) and value:
                parts.append(value)
        if parts:
            lines[tool] = " · ".join(parts)
    return lines
