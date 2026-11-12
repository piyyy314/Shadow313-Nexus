"""Security and responsive-layout checks for the legacy local dashboard."""

from pathlib import Path

import pytest

from shadow313.v2.dashboard.app import (
    DASHBOARD_HTML,
    DashboardModule,
    _is_loopback_host,
)


class FakeConfig:
    def get(self, key, default=None):
        if key == "dashboard":
            return {"host": "0.0.0.0", "port": 7313}
        return default


class FakeOutput:
    def section(self, *args, **kwargs):
        return None


class FakeKernel:
    config = FakeConfig()
    out = FakeOutput()


def test_dashboard_host_guard_allows_only_loopback():
    assert _is_loopback_host("localhost")
    assert _is_loopback_host("127.0.0.1")
    assert _is_loopback_host("::1")
    assert not _is_loopback_host("0.0.0.0")
    assert not _is_loopback_host("192.168.1.10")
    assert not _is_loopback_host("dashboard.internal")


def test_dashboard_refuses_remote_binding_without_authentication():
    module = DashboardModule(FakeKernel())

    with pytest.raises(RuntimeError, match="local-only"):
        module.run()


def test_dashboard_renders_chat_and_sse_content_as_text():
    assert "box.innerHTML +=" not in DASHBOARD_HTML
    assert "feed.innerHTML +=" not in DASHBOARD_HTML
    assert "document.createTextNode" in DASHBOARD_HTML
    assert "textContent = label" in DASHBOARD_HTML
    assert "onkeydown=" not in DASHBOARD_HTML
    assert "onclick=" not in DASHBOARD_HTML
    assert "{# nosec" not in DASHBOARD_HTML


def test_dashboard_layout_is_responsive_and_feed_label_is_accurate():
    assert "@media (max-width: 760px)" in DASHBOARD_HTML
    assert "Connection Status" in DASHBOARD_HTML
    assert "Live Event Feed" not in DASHBOARD_HTML
