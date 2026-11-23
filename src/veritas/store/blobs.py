"""Content-addressed, immutable blob storage."""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path


class IntegrityError(Exception):
    pass


class BlobStore:
    """Immutable blobs addressed by 'sha256:<hex>'. Reads re-verify the hash."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def path_for(self, ref: str) -> Path:
        algo, _, hexdigest = ref.partition(":")
        if algo != "sha256" or len(hexdigest) != 64 or not all(c in "0123456789abcdef" for c in hexdigest):
            raise ValueError(f"not a sha256 reference: {ref!r}")
        return self.root / "sha256" / hexdigest[:2] / hexdigest[2:]

    def put(self, data: bytes) -> str:
        ref = "sha256:" + hashlib.sha256(data).hexdigest()
        dest = self.path_for(ref)
        if dest.exists():
            return ref
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, dest)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return ref

    def get(self, ref: str) -> bytes:
        data = self.path_for(ref).read_bytes()
        if "sha256:" + hashlib.sha256(data).hexdigest() != ref:
            raise IntegrityError(f"blob {ref} does not match its address")
        return data

    def has(self, ref: str) -> bool:
        return self.path_for(ref).exists()
