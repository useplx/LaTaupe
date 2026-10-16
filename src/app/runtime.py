from __future__ import annotations

import threading
from typing import Self

import uvicorn

from .config import Settings
from .controller import Controller
from .engine import Engine
from .inference import Classifier
from .policy import Policy
from .proxy import create
from .reports import Generator, Reporter
from .store import Store


class Runtime:
    def __init__(self, settings: Settings) -> None:
        from myelin import Metadata

        self.settings = settings
        store = Store(settings.database)
        persisted = store.settings.get()
        backends = {
            "xgboost": Metadata.read(settings.model).backends,
            "qwen": (Metadata.read(settings.qwen_artifact).backends
                     if settings.qwen_artifact else ()),
        }
        xgboost_backend = persisted.get("xgboost_backend") or None
        qwen_backend = persisted.get("qwen_backend") or None
        if xgboost_backend not in backends["xgboost"]:
            xgboost_backend = None
        if qwen_backend not in backends["qwen"]:
            qwen_backend = None
        policy = Policy(float(persisted.get("observe_at", settings.observe_at)),
                              float(persisted.get("block_at", settings.block_at)),
                              persisted.get("enforcement_enabled", "true") == "true")
        self.engine = Engine(Classifier(settings.model, settings.myelin, xgboost_backend),
                             store, policy)
        self.controller = Controller(self.engine, backends, settings.proxy_port)
        generator = (Generator(settings.qwen_artifact, settings.myelin, qwen_backend)
                     if settings.qwen_artifact else None)
        self.reports = Reporter(store, settings.source_root, generator)
        proxy = create(self.engine, self.reports, settings.upstream_http,
                       settings.upstream_timeout, settings.max_body_bytes)
        self.server = uvicorn.Server(uvicorn.Config(
            proxy, host=settings.listen_host, port=settings.proxy_port, log_level="warning"
        ))
        self.thread = threading.Thread(target=self.server.run, name="lataupe-proxy", daemon=True)
        self._close_lock = threading.Lock()
        self._closed = False

    def start(self) -> None:
        self.reports.start()
        self.thread.start()

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
            self.server.should_exit = True
            if self.thread.is_alive():
                self.thread.join(timeout=5)
            self.reports.stop()
            self.engine.store.close()
            close = getattr(self.engine.classifier, "close", None)
            if close:
                close()

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, *_error: object) -> None:
        self.close()
