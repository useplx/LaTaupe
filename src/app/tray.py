from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QAction, QColor, QIcon, QPainter, QPen, QPixmap, QPolygon
from PySide6.QtWidgets import QMenu, QSystemTrayIcon


def icon() -> QIcon:
    image = QPixmap(64, 64)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor("#1c71d8"))
    painter.drawRoundedRect(8, 8, 48, 48, 10, 10)
    painter.setBrush(QColor("#ffffff"))
    painter.drawEllipse(20, 18, 8, 8)
    painter.drawEllipse(36, 18, 8, 8)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.setPen(QPen(QColor("#ffffff"), 5))
    painter.drawPolyline(QPolygon([QPoint(22, 43), QPoint(32, 33), QPoint(42, 43)]))
    painter.end()
    return QIcon(image)


class Tray:
    def __init__(self, show: Callable[[], None], quit: Callable[[], None]) -> None:
        self.available = QSystemTrayIcon.isSystemTrayAvailable()
        self._icon = QSystemTrayIcon(icon())
        self._icon.setToolTip("LaTaupe ML-Powered WAF")
        menu = QMenu()
        open_action = QAction("Abrir LaTaupe", menu)
        open_action.triggered.connect(show)
        quit_action = QAction("Sair", menu)
        quit_action.triggered.connect(quit)
        menu.addAction(open_action)
        menu.addSeparator()
        menu.addAction(quit_action)
        self._icon.setContextMenu(menu)
        self._icon.activated.connect(
            lambda reason: show() if reason == QSystemTrayIcon.ActivationReason.Trigger else None
        )
        if self.available:
            self._icon.show()

    def stop(self) -> None:
        self._icon.hide()


def create(show: Callable[[], None], quit: Callable[[], None]) -> Tray:
    return Tray(show, quit)
