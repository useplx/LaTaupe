from __future__ import annotations

import os
import sqlite3
import sys
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path

from platformdirs import user_data_path


def data() -> Path:
    directory = user_data_path("LaTaupe", appauthor=False)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def qwen() -> Path | None:
    if value := os.getenv("LATAUPE_QWEN_ARTIFACT"):
        artifact = Path(value).expanduser()
        return artifact if artifact.is_file() else None
    candidates = (
        Path(str(files("model").joinpath("assets/qwen3.5.mln"))),
        data() / "models/qwen3.5.mln",
        Path.cwd().parent / "PLeX/Qwen3.5/build/qwen3.5.mln",
        Path.home() / "Documents/PLeX/Qwen3.5/build/qwen3.5.mln",
    )
    return next((path for path in candidates if path.is_file()), None)


def runtime() -> Path | None:
    if value := os.getenv("LATAUPE_MYELIN_CONFIG"):
        path = Path(value).expanduser()
        return path if path.is_file() else None
    candidates = (
        Path.cwd() / "myelin.toml",
        Path(__file__).resolve().parents[2] / "myelin.toml",
        Path(sys.executable).resolve().parent / "myelin.toml",
    )
    return next((path for path in candidates if path.is_file()), None)


def port() -> int:
    if value := os.getenv("LATAUPE_PROXY_PORT"):
        return int(value)
    database = data() / "lataupe.db"
    if database.is_file():
        try:
            connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
            row = connection.execute(
                "SELECT value FROM settings WHERE key='proxy_port'"
            ).fetchone()
            connection.close()
            if row and 1024 <= int(row[0]) <= 65535:
                return int(row[0])
        except (sqlite3.Error, ValueError):
            pass
    return 8081


@dataclass(frozen=True)
class Settings:
    listen_host: str = field(default_factory=lambda: os.getenv(
        "LATAUPE_LISTEN_HOST", "127.0.0.1"
    ))
    proxy_port: int = field(default_factory=port)
    upstream_http: str = field(default_factory=lambda: os.getenv(
        "LATAUPE_UPSTREAM_HTTP", "http://127.0.0.1:3000"
    ))
    upstream_timeout: float = 10.0
    max_body_bytes: int = 1_048_576
    database: Path = field(default_factory=lambda: data() / "lataupe.db")
    model: Path = field(default_factory=lambda: Path(str(
        files("model").joinpath("assets/lataupe.mln")
    )))
    qwen_artifact: Path | None = field(default_factory=qwen)
    myelin: Path | None = field(default_factory=runtime)
    source_root: Path = field(default_factory=lambda: Path(
        os.getenv("LATAUPE_SOURCE_ROOT", Path.cwd())
    ).expanduser().resolve())
    enforcement_enabled: bool = True
    observe_at: float = 0.55
    block_at: float = 0.82
