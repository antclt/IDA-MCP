# IDA-MCP Project Map

## Responsibility

IDA-MCP is the standalone IDA Pro plugin and MCP gateway project. It owns IDA
runtime integration, FastMCP tools/resources, direct instance MCP transport,
gateway/proxy behavior, CLI control, and live-IDA integration tests.

It does not own the desktop IDE, chat/workspace state, installer UI, or other
Sarma application code.

## Entry Points

| Entry | Responsibility |
| --- | --- |
| `ida_mcp.py` | IDA plugin file exposing `PLUGIN_ENTRY()` |
| `ida_mcp/plugin_runtime.py` | Per-IDA-instance server lifecycle, registration, heartbeat |
| `ida_mcp/registry_server.py` | Standalone gateway with `/internal/*` and `/mcp` |
| `ida_mcp/command.py` | CLI for gateway, IDA lifecycle, tool calls, and resources |
| `API.md` | Tool, resource, proxy, and internal HTTP contract |
| `test/test.py` | Live-IDA test runner |

## Directory Map

| Path | Responsibility |
| --- | --- |
| `ida_mcp.py` | Thin IDA plugin loader and lifecycle bridge |
| `ida_mcp/` | Core plugin package, API modules, gateway, proxy, CLI helpers |
| `ida_mcp/proxy/` | Gateway MCP proxy tool registration, lifecycle helpers, routing state |
| `test/` | pytest suite that exercises a live gateway and registered IDA instance |
| `ida-plugin.json` | IDA plugin metadata descriptor |
| `requirements.txt` | IDA Python runtime dependencies |

## Runtime Boundaries

- IDA runtime: all SDK calls must be wrapped with `@idaread` or `@idawrite` from `ida_mcp/sync.py`.
- Gateway runtime: standalone Python process, separate from IDA, owning instance registry and proxy routing.
- Direct instance runtime: per-IDA FastMCP server exposing tools and `ida://` resources.
- Test runtime: ordinary pytest process that talks to a running gateway and live IDA instance.

## Tool Registration

1. Add the implementation to the appropriate `ida_mcp/api_*.py` module.
2. Decorate it with `@tool` and `@idaread` or `@idawrite`.
3. If adding a new module, import it from `ida_mcp/api_loader.py`.
4. Update `API.md` when request/response contracts change.

## Safety

Unsafe tools include `py_eval` and debugger operations. They are privileged and
controlled by `enable_unsafe` in `ida_mcp/config.conf`.

## Relationship To Sarma

Sarma vendors this repository as `ide/resources/ida_mcp`. Sarma may launch the
CLI, copy plugin files into IDA's plugin directory, and call gateway APIs, but
this repository must not import Sarma IDE modules.
