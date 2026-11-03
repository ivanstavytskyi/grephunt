"""Semgrep-specific behavior: local rules, excludes, and network only for registry configs."""
from __future__ import annotations

from pathlib import Path

from grephunt.finding_model.record import Finding
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scanner_catalog.descriptor import ToolDescriptor

# Always applied, in addition to the rulesets chosen in the UI.
BUNDLED_RULES = Path(__file__).resolve().parents[1] / "scanner_catalog" / "rules"
_BUNDLED_MOUNT = "/rules/grephunt"


class SemgrepHook:
    name = "semgrep"

    def is_applicable(self, project: Path) -> bool:
        return True

    def wants_network(self, descriptor: ToolDescriptor, options: ScanOptions) -> bool:
        if not descriptor.network:
            return False
        return any(not Path(config).exists() for config in options.configs)

    def _local_configs(self, options: ScanOptions) -> list[tuple[str, Path]]:
        return [(config, Path(config).resolve()) for config in options.configs if Path(config).exists()]

    def extra_mounts(self, options: ScanOptions, use_docker: bool) -> list[tuple[Path, str]]:
        if not use_docker:
            return []
        mounts: list[tuple[Path, str]] = []
        for index, (_, path) in enumerate(self._local_configs(options)):
            host = path if path.is_dir() else path.parent
            mounts.append((host, f"/rules/{index}"))
        if BUNDLED_RULES.is_dir():
            mounts.append((BUNDLED_RULES, _BUNDLED_MOUNT))
        return mounts

    def _container_config(self, config: str, options: ScanOptions) -> str:
        for index, (name, path) in enumerate(self._local_configs(options)):
            if name != config:
                continue
            if path.is_dir():
                return f"/rules/{index}"
            return f"/rules/{index}/{path.name}"
        return config

    def build_args(self, descriptor: ToolDescriptor, src: str, output: str, options: ScanOptions, use_docker: bool) -> list[str]:
        args = [
            "scan", "--sarif", "--output", output, "--quiet",
            "--metrics", "off", "--disable-version-check", "--timeout", "30",
        ]
        for config in options.configs:
            rendered = self._container_config(config, options) if use_docker else (
                str(Path(config).resolve()) if Path(config).exists() else config
            )
            args += ["--config", rendered]
        if BUNDLED_RULES.is_dir():
            args += ["--config", _BUNDLED_MOUNT if use_docker else str(BUNDLED_RULES)]
        for pattern in options.excludes:
            args += ["--exclude", pattern]
        # Trivy still scans vendor trees for CVEs; Semgrep on node_modules OOMs large JS apps.
        for pattern in ("node_modules", "vendor", "bower_components", ".yarn"):
            args += ["--exclude", pattern]
        args.append(src)
        return args

    def refine_finding(self, finding: Finding, result: dict, rule: dict) -> Finding:
        return finding
