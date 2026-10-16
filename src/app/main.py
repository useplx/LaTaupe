# nuitka-project: --mode=standalone
# nuitka-project: --include-data-dir={MAIN_DIRECTORY}/assets=app/assets
# nuitka-project: --include-data-files={MAIN_DIRECTORY}/../model/assets/lataupe.mln=model/assets/lataupe.mln
# nuitka-project: --include-data-files={MAIN_DIRECTORY}/../../myelin.toml=myelin.toml
# nuitka-project: --output-filename=lataupe
# nuitka-project: --nofollow-import-to=matplotlib,pandas,sklearn,seaborn
# nuitka-project: --enable-plugin=pyside6

from __future__ import annotations

import os
import socket
import sys
import threading
from pathlib import Path

os.environ.setdefault("QT_API", "pyside6")
bundled_runtime = Path(sys.executable).resolve().parent / "libmln_runtime.so.0.1.0"
if bundled_runtime.is_file():
    os.environ.setdefault("MLN_RUNTIME_LIBRARY", str(bundled_runtime))

import webview
from PySide6.QtWidgets import QApplication, QMessageBox

from app.config import Settings
from app.runtime import Runtime
from app.tray import create
from app.ui import render


def main() -> None:
    application = QApplication.instance() or QApplication([])
    application.setApplicationName("LaTaupe")
    settings = Settings()
    if occupied(settings.listen_host, settings.proxy_port):
        QMessageBox.critical(
            None,
            "LaTaupe",
            f"A porta {settings.proxy_port} ja esta em uso. Feche a outra instancia do LaTaupe.",
        )
        return
    stopped = threading.Event()
    try:
        with Runtime(settings) as runtime:
            window = webview.create_window(
                "LaTaupe ML-Powered WAF",
                html=render(),
                js_api=runtime.controller,
                width=1280,
                height=820,
                min_size=(760, 560),
                background_color="#242424",
            )
            if window is None:
                raise RuntimeError("PyWebView did not create the application window")

            exiting = threading.Event()
            indicator = create(window.show, lambda: quit(window, indicator, exiting))

            def close() -> bool:
                if not exiting.is_set():
                    exiting.set()
                    indicator.stop()
                    threading.Thread(
                        target=deadline, args=(stopped,), name="lataupe-shutdown", daemon=True
                    ).start()
                return True

            window.events.closing += close
            try:
                webview.start(gui="qt", private_mode=True)
            finally:
                indicator.stop()
    finally:
        stopped.set()


def quit(window: webview.Window, tray: object, exiting: threading.Event) -> None:
    exiting.set()
    stop = getattr(tray, "stop", None)
    if stop:
        stop()
    window.destroy()


def occupied(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.2)
        return probe.connect_ex((host, port)) == 0


def deadline(stopped: threading.Event, seconds: float = 10.0) -> None:
    if not stopped.wait(seconds):
        os._exit(0)


if __name__ == "__main__":
    main()
