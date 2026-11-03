"""Container images given as a tar file: `docker save` output or an OCI image layout.

The archive is never unpacked by GrepHunt. It is mounted read-only into the
scanner containers, and the scanners read the layers themselves.
"""
from __future__ import annotations

import tarfile
from pathlib import Path
from typing import Literal

ImageFormat = Literal["docker", "oci"]

IMAGE_MOUNT = "/image/image.tar"
_MAX_MEMBERS_TO_CHECK = 100_000


def detect_image_format(path: Path) -> ImageFormat:
    """docker: manifest.json at the top (docker save). oci: oci-layout and index.json at the top.

    Raises ValueError for anything else, including a tar of a source folder.
    """
    if not path.is_file():
        raise ValueError(f"image archive not found: {path}")
    try:
        with tarfile.open(path, mode="r:") as archive:
            names: set[str] = set()
            for index, member in enumerate(archive):
                if index >= _MAX_MEMBERS_TO_CHECK:
                    break
                name = member.name.replace("\\", "/").lstrip("./")
                if "/" not in name:
                    names.add(name)
                if "manifest.json" in names or {"oci-layout", "index.json"} <= names:
                    break
    except tarfile.ReadError as exc:
        raise ValueError("the file is not an uncompressed tar archive (use docker save -o image.tar)") from exc
    if "manifest.json" in names:
        return "docker"
    if {"oci-layout", "index.json"} <= names:
        return "oci"
    raise ValueError(
        "the tar file is not a container image: there is no manifest.json (docker save) "
        "and no oci-layout with index.json (OCI layout)"
    )


def image_reference(path: str, image_format: ImageFormat) -> str:
    """Source string that Grype and Syft understand."""
    scheme = "docker-archive" if image_format == "docker" else "oci-archive"
    return f"{scheme}:{path}"
