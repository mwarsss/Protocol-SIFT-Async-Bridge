"""
pytest configuration — ensures each test class gets a clean job registry
by reloading the server module to reset the global dict and thread pool.
"""
import importlib
import json
import sys

import pytest


@pytest.fixture(autouse=True)
def _fresh_module(monkeypatch):
    """
    Reload server.mcp_vol_server before each test so the global
    _job_registry dict and ThreadPoolExecutor start from a clean state.
    """
    fake_images = {
        "test-win10": "/tmp/fake_win10.raw",
        "test-linux": "/tmp/fake_linux.lime",
    }
    monkeypatch.setenv("VOL_CASE_IMAGES", json.dumps(fake_images))
    monkeypatch.setenv("MAX_OUTPUT_LINES", "20")
    monkeypatch.setenv("PLUGIN_TIMEOUT_SECS", "10")
    monkeypatch.setenv("MAX_WORKERS", "2")

    # Purge the cached module so env patches take effect on re-import
    for key in list(sys.modules.keys()):
        if "mcp_vol_server" in key:
            del sys.modules[key]

    yield

    # Teardown: purge again so the next test starts clean
    for key in list(sys.modules.keys()):
        if "mcp_vol_server" in key:
            del sys.modules[key]
