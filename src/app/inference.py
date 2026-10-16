from __future__ import annotations

import json
import os
import struct
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol


class Predictor(Protocol):
    def predict(self, features: Sequence[float]) -> float: ...


class Classifier:
    def __init__(self, artifact: str | Path,
                 configuration: str | Path | None = None,
                 backend: str | None = None) -> None:
        bundled = Path(sys.executable).resolve().parent / "libmln_runtime.so.0.1.0"
        if "MLN_RUNTIME_LIBRARY" not in os.environ and bundled.is_file():
            os.environ["MLN_RUNTIME_LIBRARY"] = str(bundled)
        from myelin import Runtime

        self._runtime = Runtime(configuration)
        self._session = self._runtime.session()
        self._session.load(artifact, backend)

    def predict(self, features: Sequence[float]) -> float:
        if len(features) != 18:
            raise ValueError("LaTaupe expects eighteen HTTP features")
        result = self._session.invoke(struct.pack("<18f", *features))
        if len(result) != 4:
            raise RuntimeError("PLeX classifier returned an invalid float32 result")
        risk = struct.unpack("<f", result)[0]
        if not 0.0 <= risk <= 1.0:
            raise RuntimeError("PLeX classifier returned risk outside [0, 1]")
        return risk

    def close(self) -> None:
        self._session.close()
        self._runtime.close()


def order(path: str | Path) -> list[str]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    names = document.get("features")
    if not isinstance(names, list) or not names or not all(isinstance(name, str) for name in names):
        raise ValueError("feature schema must contain a non-empty string list")
    return names
