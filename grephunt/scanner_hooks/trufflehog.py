"""TruffleHog: optional key verification, chosen per scan.

With verification on, TruffleHog tries each key it finds against the key's own service
(for example AWS or GitHub) and reports whether it works. That needs the network and it
uses the found credential, so it is a scan parameter a person sees and can turn off: many
bug bounty programs forbid using credentials found in a target's code.
"""
from __future__ import annotations

from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scanner_catalog.descriptor import ToolDescriptor
from grephunt.scanner_hooks.generic import GenericHook

_NO_VERIFY = "--no-verification"


def verification_on(options: ScanOptions) -> bool:
    values = options.params.get("trufflehog") or {}
    return values.get("verify") is True


class TrufflehogHook(GenericHook):
    def wants_network(self, descriptor: ToolDescriptor, options: ScanOptions) -> bool:
        return descriptor.network and verification_on(options)

    def build_args(self, descriptor: ToolDescriptor, src: str, output: str, options: ScanOptions, use_docker: bool) -> list[str]:
        args = super().build_args(descriptor, src, output, options, use_docker)
        if verification_on(options):
            return [arg for arg in args if arg != _NO_VERIFY]
        if _NO_VERIFY not in args:
            args.append(_NO_VERIFY)
        return args
