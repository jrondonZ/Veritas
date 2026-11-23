"""Read the metadata header of a GGUF weights file (llama.cpp's format), without loading any tensor.

The file comes from the operator, so parsing is bounded: counts, key lengths, and
string lengths are capped, and only the few keys Veritas records are kept. Arrays
(such as the tokenizer vocabulary) are skipped element by element.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

MAGIC = b"GGUF"
MAX_KV = 100_000
MAX_KEY = 256
MAX_STRING = 16 * 1024 * 1024
MAX_ARRAY = 10_000_000

# GGUF value types -> struct format (fixed-size scalars)
_SCALARS = {0: "<B", 1: "<b", 2: "<H", 3: "<h", 4: "<I", 5: "<i", 6: "<f", 7: "<?", 10: "<Q", 11: "<q", 12: "<d"}
_STRING, _ARRAY = 8, 9

# general.file_type -> quantization label (llama.cpp's LLAMA_FTYPE values)
FILE_TYPES = {
    0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1", 7: "Q8_0", 8: "Q5_0", 9: "Q5_1", 10: "Q2_K", 11: "Q3_K_S",
    12: "Q3_K_M", 13: "Q3_K_L", 14: "Q4_K_S", 15: "Q4_K_M", 16: "Q5_K_S", 17: "Q5_K_M", 18: "Q6_K",
    19: "IQ2_XXS", 20: "IQ2_XS", 21: "Q2_K_S", 22: "IQ3_XS", 23: "IQ3_XXS", 24: "IQ1_S", 25: "IQ4_NL",
    26: "IQ3_S", 27: "IQ3_M", 28: "IQ2_S", 29: "IQ2_M", 30: "IQ4_XS", 31: "IQ1_M", 32: "BF16",
}  # fmt: skip
_KEPT = {"general.architecture", "general.name", "general.license", "general.file_type", "general.size_label"}


class GgufError(ValueError):
    pass


@dataclass(frozen=True)
class GgufInfo:
    version: int
    tensors: int
    architecture: str | None
    name: str | None
    license: str | None
    quantization: str | None
    size_label: str | None
    context_length: int | None
    chat_template: bool  # whether the file carries a chat template (llama-server needs one for chat requests)


class _Reader:
    def __init__(self, f: IO[bytes]):
        self.f = f

    def read(self, n: int) -> bytes:
        data = self.f.read(n)
        if len(data) != n:
            raise GgufError("the file ends inside its metadata header")
        return data

    def unpack(self, fmt: str) -> Any:
        return struct.unpack(fmt, self.read(struct.calcsize(fmt)))[0]

    def string(self, limit: int = MAX_STRING) -> str:
        length = self.unpack("<Q")
        if length > limit:
            raise GgufError(f"a metadata string of {length} bytes exceeds the {limit}-byte limit")
        return self.read(length).decode("utf-8", "replace")

    def value(self, vtype: int) -> Any:
        if vtype in _SCALARS:
            return self.unpack(_SCALARS[vtype])
        if vtype == _STRING:
            return self.string()
        if vtype == _ARRAY:
            self.skip(vtype)
            return None
        raise GgufError(f"unknown metadata value type {vtype}")

    def skip(self, vtype: int) -> None:
        if vtype in _SCALARS:
            self.read(struct.calcsize(_SCALARS[vtype]))
        elif vtype == _STRING:
            self.f.seek(self._length(MAX_STRING), 1)
        elif vtype == _ARRAY:
            item, count = self.unpack("<I"), self.unpack("<Q")
            if count > MAX_ARRAY:
                raise GgufError(f"a metadata array of {count} items exceeds the limit")
            if item in _SCALARS:
                self.f.seek(count * struct.calcsize(_SCALARS[item]), 1)
            else:
                for _ in range(count):
                    self.skip(item)
        else:
            raise GgufError(f"unknown metadata value type {vtype}")

    def _length(self, limit: int) -> int:
        length: int = self.unpack("<Q")
        if length > limit:
            raise GgufError(f"a metadata string of {length} bytes exceeds the {limit}-byte limit")
        return length


def read_metadata(path: str | Path) -> GgufInfo:
    with open(path, "rb") as f:
        reader = _Reader(f)
        if reader.read(4) != MAGIC:
            raise GgufError("not a GGUF file")
        version = reader.unpack("<I")
        if version not in (2, 3):
            raise GgufError(f"GGUF version {version} is not supported")
        tensors, kv_count = reader.unpack("<Q"), reader.unpack("<Q")
        if kv_count > MAX_KV:
            raise GgufError(f"{kv_count} metadata entries exceed the limit")
        meta: dict[str, Any] = {}
        has_template = False
        for _ in range(kv_count):
            key = reader.string(MAX_KEY)
            vtype = reader.unpack("<I")
            if key == "tokenizer.chat_template":
                has_template = True
                reader.skip(vtype)
            elif key in _KEPT or key.endswith(".context_length"):
                meta[key] = reader.value(vtype)
            else:
                reader.skip(vtype)
    arch = meta.get("general.architecture")
    file_type = meta.get("general.file_type")
    context = meta.get(f"{arch}.context_length") if isinstance(arch, str) else None
    return GgufInfo(
        version=version,
        tensors=tensors,
        architecture=arch if isinstance(arch, str) else None,
        name=meta.get("general.name") if isinstance(meta.get("general.name"), str) else None,
        license=meta.get("general.license") if isinstance(meta.get("general.license"), str) else None,
        quantization=FILE_TYPES.get(file_type, f"type-{file_type}") if isinstance(file_type, int) else None,
        size_label=meta.get("general.size_label") if isinstance(meta.get("general.size_label"), str) else None,
        context_length=context if isinstance(context, int) else None,
        chat_template=has_template,
    )
