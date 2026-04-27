from __future__ import annotations

import asyncio
import logging

from app.chat.mcp_pool import McpClientPool


class _NoCloseClient:
    def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        raise NotImplementedError("context manager support has been removed")


def test_disconnect_ignores_clients_without_close(caplog) -> None:
    pool = McpClientPool()
    pool._client = _NoCloseClient()
    pool._tools = ["tool"]
    pool._connected = True

    with caplog.at_level(logging.WARNING):
        asyncio.run(pool.disconnect())

    assert pool._client is None
    assert pool.tools == []
    assert pool.is_connected is False
    assert "Error closing MCP client" not in caplog.text
