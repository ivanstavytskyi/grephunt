"""Download the Kubescape CLI into the grephunt-kubescape cache (prepare step)."""
from __future__ import annotations

import hashlib
import sys
import tarfile
import urllib.request
from io import BytesIO
from pathlib import Path


def main() -> None:
    dest = Path(sys.argv[1])
    version = sys.argv[2]
    expected = sys.argv[3]
    binary = dest / "kubescape"
    if binary.is_file():
        return
    dest.mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/kubescape/kubescape/releases/download/v{version}/kubescape-ubuntu-latest.tar.gz"
    payload = urllib.request.urlopen(url, timeout=180).read()
    digest = hashlib.sha256(payload).hexdigest()
    if digest != expected:
        raise SystemExit(f"kubescape binary sha256 mismatch: got {digest}")
    with tarfile.open(fileobj=BytesIO(payload), mode="r:gz") as archive:
        member = archive.getmember("kubescape-ubuntu-latest")
        extracted = archive.extractfile(member)
        if extracted is None:
            raise SystemExit("kubescape archive is empty")
        binary.write_bytes(extracted.read())
    binary.chmod(0o755)


if __name__ == "__main__":
    main()
