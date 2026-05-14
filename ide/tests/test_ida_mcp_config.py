from pathlib import Path

from shared.database import DatabaseStore
from shared.ida_mcp_config import IdaMcpConfigStore


def _make_store(tmp_path: Path, config_path: Path | None = None) -> IdaMcpConfigStore:
    """Create an IdaMcpConfigStore with an isolated test database."""
    db = DatabaseStore(db_path=tmp_path / "test.db")
    path = config_path or (tmp_path / "config.conf")
    return IdaMcpConfigStore(config_path=path, db=db)


def test_ida_mcp_config_store_loads_and_preserves_unknown_lines(tmp_path: Path) -> None:
    config_path = tmp_path / "config.conf"
    config_path.write_text(
        "\n".join(
            [
                "enable_http = true # active",
                "# http_port = 22334",
                '# http_host = "0.0.0.0"',
                'custom_key = "keep-me"',
                "# untouched comment",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    store = _make_store(tmp_path, config_path)
    config = store.load()

    assert config.enable_http is True
    assert config.http_port == 22334

    updated = store.update(http_port=31337, debug=True)
    text = config_path.read_text(encoding="utf-8")

    assert updated.http_port == 31337
    assert updated.debug is True
    assert 'custom_key = "keep-me"' in text
    assert "# untouched comment" in text
    assert "http_port = 31337" in text
    assert "debug = true" in text


def test_ida_mcp_config_store_round_trips_extended_runtime_fields(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.conf"
    config_path.write_text(
        "\n".join(
            [
                "wsl_path_bridge = true",
                "ida_default_port = 10010",
                'ida_host = "127.0.0.2"',
                'gateway_token = "secret"',
                'open_in_ida_bundle_dir = "C:/bundle"',
                "open_in_ida_autonomous = false",
                "auto_start = true",
                'server_name = "IDA-MCP-Test"',
                "request_timeout = 45",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    store = _make_store(tmp_path, config_path)
    config = store.load()

    assert config.wsl_path_bridge is True
    assert config.ida_default_port == 10010
    assert config.ida_host == "127.0.0.2"
    assert config.gateway_token == "secret"
    assert config.open_in_ida_bundle_dir == "C:/bundle"
    assert config.open_in_ida_autonomous is False
    assert config.auto_start is True
    assert config.server_name == "IDA-MCP-Test"
    assert config.request_timeout == 45

    updated = store.update(
        wsl_path_bridge=False,
        ida_default_port=10020,
        ida_host="127.0.0.3",
        gateway_token="next-secret",
        open_in_ida_bundle_dir="C:/bundle2",
        open_in_ida_autonomous=True,
        auto_start=False,
        server_name="IDA-MCP-Prod",
        request_timeout=90,
    )
    text = config_path.read_text(encoding="utf-8")

    assert updated.wsl_path_bridge is False
    assert updated.ida_default_port == 10020
    assert updated.ida_host == "127.0.0.3"
    assert updated.gateway_token == "next-secret"
    assert updated.open_in_ida_bundle_dir == "C:/bundle2"
    assert updated.open_in_ida_autonomous is True
    assert updated.auto_start is False
    assert updated.server_name == "IDA-MCP-Prod"
    assert updated.request_timeout == 90
    assert "wsl_path_bridge = false" in text
    assert "ida_default_port = 10020" in text
    assert 'ida_host = "127.0.0.3"' in text
    assert 'gateway_token = "next-secret"' in text
    assert 'open_in_ida_bundle_dir = "C:/bundle2"' in text
    assert "open_in_ida_autonomous = true" in text
    assert "auto_start = false" in text
    assert 'server_name = "IDA-MCP-Prod"' in text
