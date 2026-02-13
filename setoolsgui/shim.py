# Copyright 2026, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
# pylint: disable=no-name-in-module
# mypy: disable-error-code="assignment, no-redef, import-error"

import os

# If PYTEST_QT_API is set, match it to be in sync with requested unit tests.
match os.getenv("PYTEST_QT_API", ""):
    case "pyqt6":
        from PyQt6 import QtCore, QtGui, QtWidgets
        from PyQt6.QtCore import pyqtSignal as QtSignal, pyqtSlot as QtSlot
    case "pyside6":
        from PySide6 import QtCore, QtGui, QtWidgets
        from PySide6.QtCore import Signal as QtSignal, Slot as QtSlot
    case _:
        # Try PyQt6 first, then fall back to PySide6
        try:
            from PyQt6 import QtCore, QtGui, QtWidgets
            from PyQt6.QtCore import pyqtSignal as QtSignal, pyqtSlot as QtSlot

        except ImportError:
            try:
                from PySide6 import QtCore, QtGui, QtWidgets
                from PySide6.QtCore import Signal as QtSignal, Slot as QtSlot

            except ImportError as e:
                raise ImportError(
                    "Neither PyQt6 nor PySide6 could be imported. "
                    "Install one of them, e.g. `pip install PyQt6` or `pip install PySide6`."
                ) from e

__all__ = ["QtCore", "QtGui", "QtWidgets", "QtSignal", "QtSlot"]
