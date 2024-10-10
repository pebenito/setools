# SPDX-License-Identifier: GPL-2.0-only
import typing

from PyQt6 import QtWidgets
import pytest
from pytestqt.qtbot import QtBot

import setools
from setoolsgui.widgets.categoryquery import CategoryQueryTab


@pytest.fixture
def widget(mock_policy, request: pytest.FixtureRequest, qtbot: QtBot) -> CategoryQueryTab:
    """Pytest fixture to set up the widget."""
    marker = request.node.get_closest_marker("obj_args")
    kwargs = marker.kwargs if marker else {}
    w = CategoryQueryTab(mock_policy, **kwargs)
    qtbot.addWidget(w)
    w.show()
    return w


def test_docs(widget: CategoryQueryTab) -> None:
    """Check that docs are provided for the widget."""
    assert widget.whatsThis()
    assert widget.table_results.whatsThis()
    assert widget.raw_results.whatsThis()

    for w in widget.criteria:
        assert w.toolTip()
        assert w.whatsThis()

    results = typing.cast(QtWidgets.QTabWidget, widget.results)
    for index in range(results.count()):
        assert results.tabWhatsThis(index)


def test_layout(widget: CategoryQueryTab) -> None:
    """Test the layout of the criteria frame."""
    name, = widget.criteria

    assert widget.criteria_frame_layout.columnCount() == 2
    assert widget.criteria_frame_layout.rowCount() == 2
    assert widget.criteria_frame_layout.itemAtPosition(0, 0).widget() == name
    assert widget.criteria_frame_layout.itemAtPosition(0, 1) is None
    assert widget.criteria_frame_layout.itemAtPosition(1, 0).widget() == widget.buttonBox
    assert widget.criteria_frame_layout.itemAtPosition(1, 1).widget() == widget.buttonBox


def test_criteria_mapping(widget: CategoryQueryTab) -> None:
    """Test that widgets save to the correct query fields."""
    name, = widget.criteria

    assert isinstance(widget.query, setools.CategoryQuery)
    assert name.attrname == "name"