"""Build a tiny container image tar without Docker: one layer with an old Flask install.

docker_archive() writes what `docker save` writes (manifest.json, config,
layer). oci_archive() writes an OCI image layout. Scanners that read Python
package metadata see flask 0.12.2, which has known CVEs.
"""
from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

_METADATA = b"Metadata-Version: 2.1\nName: Flask\nVersion: 0.12.2\nSummary: fixture\n"
_SITE = "usr/local/lib/python3.9/site-packages/Flask-0.12.2.dist-info"


def _add(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o644
    archive.addfile(info, io.BytesIO(data))


def _add_dir(archive: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    archive.addfile(info)


def _layer() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as layer:
        parts = _SITE.split("/")
        for index in range(1, len(parts) + 1):
            _add_dir(layer, "/".join(parts[:index]))
        _add(layer, f"{_SITE}/METADATA", _METADATA)
        _add(layer, f"{_SITE}/RECORD", b"flask/__init__.py,,\n")
        _add(layer, f"{_SITE}/INSTALLER", b"pip\n")
    return buffer.getvalue()


def _config(layer_digest: str) -> bytes:
    return json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {"Env": ["PATH=/usr/local/bin:/usr/bin:/bin"]},
            "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
            "history": [{"created_by": "grephunt test fixture"}],
        }
    ).encode()


def docker_archive(path: Path) -> Path:
    layer = _layer()
    layer_digest = "sha256:" + hashlib.sha256(layer).hexdigest()
    config = _config(layer_digest)
    config_name = hashlib.sha256(config).hexdigest() + ".json"
    manifest = [{"Config": config_name, "RepoTags": ["grephunt/fixture:1"], "Layers": ["layer/layer.tar"]}]
    with tarfile.open(path, mode="w") as archive:
        _add(archive, config_name, config)
        _add_dir(archive, "layer")
        _add(archive, "layer/layer.tar", layer)
        _add(archive, "manifest.json", json.dumps(manifest).encode())
    return path


def oci_archive(path: Path) -> Path:
    layer = _layer()
    layer_digest = hashlib.sha256(layer).hexdigest()
    config = _config("sha256:" + layer_digest)
    config_digest = hashlib.sha256(config).hexdigest()
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": f"sha256:{config_digest}", "size": len(config)},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": f"sha256:{layer_digest}", "size": len(layer)}],
        }
    ).encode()
    manifest_digest = hashlib.sha256(manifest).hexdigest()
    index = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": f"sha256:{manifest_digest}",
                    "size": len(manifest),
                    "annotations": {"org.opencontainers.image.ref.name": "1"},
                }
            ],
        }
    ).encode()
    with tarfile.open(path, mode="w") as archive:
        _add(archive, "oci-layout", b'{"imageLayoutVersion": "1.0.0"}')
        _add(archive, "index.json", index)
        for directory in ("blobs", "blobs/sha256"):
            _add_dir(archive, directory)
        _add(archive, f"blobs/sha256/{layer_digest}", layer)
        _add(archive, f"blobs/sha256/{config_digest}", config)
        _add(archive, f"blobs/sha256/{manifest_digest}", manifest)
    return path
