from __future__ import annotations

from typing import TypedDict

from .engine import Engine
from .markdown import render


class State(TypedDict):
    health: dict[str, str]
    summary: dict[str, object]
    mitigations: list[dict[str, object]]
    reports: list[dict[str, object]]
    config: dict[str, object]


class Controller:
    """Thread-safe bridge exposed to the private PyWebView document."""

    def __init__(self, engine: Engine, backends: dict[str, tuple[str, ...]], proxy_port: int) -> None:
        self.engine = engine
        self.backends = backends
        self.proxy_port = proxy_port

    def config(self) -> dict[str, object]:
        policy = self.engine.policy
        settings = self.engine.store.settings.get()
        return {"enforcement_enabled": policy.enforcement_enabled,
                "observe_at": policy.observe_at, "block_at": policy.block_at,
                "language": settings.get("language", "pt"),
                "xgboost_backend": settings.get("xgboost_backend", ""),
                "qwen_backend": settings.get("qwen_backend", ""),
                "proxy_port": int(settings.get("proxy_port", self.proxy_port)),
                "backends": self.backends}

    def state(self) -> State:
        reports = self.engine.store.report.list(100)
        for report in reports:
            report["html"] = render(str(report.get("content") or report.get("error") or ""))
        return {
            "health": {"status": "ok",
                       "mode": "enforce" if self.engine.policy.enforcement_enabled else "observe",
                       "model": type(self.engine.classifier).__name__},
            "summary": self.engine.store.summary(),
            "mitigations": self.engine.store.mitigations(100),
            "reports": reports,
            "config": self.config(),
        }

    def update(self, value: dict[str, object]) -> dict[str, object]:
        enforcement = bool(value.get("enforcement_enabled", False))
        observe_at = float(value.get("observe_at", -1))
        block_at = float(value.get("block_at", -1))
        language = str(value.get("language", "pt"))
        xgboost_backend = str(value.get("xgboost_backend", ""))
        qwen_backend = str(value.get("qwen_backend", ""))
        proxy_port = int(value.get("proxy_port", self.proxy_port))
        if not 0 <= observe_at <= block_at <= 1:
            raise ValueError("thresholds must be ordered between zero and one")
        if language not in {"pt", "en", "es", "fr", "de", "it", "ja", "zh", "ar"}:
            raise ValueError("unsupported language")
        if xgboost_backend and xgboost_backend not in self.backends["xgboost"]:
            raise ValueError("backend is not present in the XGBoost artifact")
        if qwen_backend and qwen_backend not in self.backends["qwen"]:
            raise ValueError("backend is not present in the Qwen artifact")
        if not 1024 <= proxy_port <= 65535:
            raise ValueError("proxy port must be between 1024 and 65535")
        object.__setattr__(self.engine.policy, "enforcement_enabled", enforcement)
        object.__setattr__(self.engine.policy, "observe_at", observe_at)
        object.__setattr__(self.engine.policy, "block_at", block_at)
        self.engine.store.settings.set({"enforcement_enabled": str(enforcement).lower(),
                                        "observe_at": str(observe_at), "block_at": str(block_at),
                                        "language": language,
                                        "xgboost_backend": xgboost_backend,
                                        "qwen_backend": qwen_backend})
        self.engine.store.settings.set({"proxy_port": str(proxy_port)})
        return self.config()
