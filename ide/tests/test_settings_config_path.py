from pathlib import Path

from supervisor.config_store import IdeConfigStore
from supervisor.manager import SupervisorManager


def test_manager_infers_ida_mcp_config_from_plugins_dir(tmp_path: Path) -> None:
    ide_config_path = tmp_path / "ide_config.json"
    plugins_dir = tmp_path / "plugins"
    inferred_config_path = plugins_dir / "ida_mcp" / "config.conf"
    inferred_config_path.parent.mkdir(parents=True)
    inferred_config_path.write_text(
        'http_host = "127.0.0.1"\nhttp_port = 22334\n',
        encoding="utf-8",
    )

    config_store = IdeConfigStore(config_path=ide_config_path)
    config_store.update(plugin_dir=str(plugins_dir))
    manager = SupervisorManager(config_store=config_store)

    config = manager.get_ida_mcp_config()
    info = manager.get_ida_mcp_config_store_info()

    assert config.http_port == 22334
    assert config.config_path == str(inferred_config_path)
    assert info.path == str(inferred_config_path)


def test_manager_updates_inferred_ida_mcp_config_in_plugin_dir(tmp_path: Path) -> None:
    ide_config_path = tmp_path / "ide_config.json"
    plugins_dir = tmp_path / "plugins"
    inferred_config_path = plugins_dir / "ida_mcp" / "config.conf"
    inferred_config_path.parent.mkdir(parents=True)
    inferred_config_path.write_text("http_port = 11111\n", encoding="utf-8")

    config_store = IdeConfigStore(config_path=ide_config_path)
    config_store.update(plugin_dir=str(plugins_dir))
    manager = SupervisorManager(config_store=config_store)

    updated = manager.update_ida_mcp_config(debug=True)

    assert updated.config_path == str(inferred_config_path)
    assert "debug = true" in inferred_config_path.read_text(encoding="utf-8")


def test_manager_writes_missing_ida_mcp_config_to_plugin_dir(tmp_path: Path) -> None:
    ide_config_path = tmp_path / "ide_config.json"
    plugins_dir = tmp_path / "plugins"
    inferred_config_path = plugins_dir / "ida_mcp" / "config.conf"

    config_store = IdeConfigStore(config_path=ide_config_path)
    config_store.update(plugin_dir=str(plugins_dir))
    manager = SupervisorManager(config_store=config_store)

    updated = manager.update_ida_mcp_config(debug=True)

    assert updated.config_path == str(inferred_config_path)
    assert inferred_config_path.exists()
    assert "debug = true" in inferred_config_path.read_text(encoding="utf-8")
