import os
import socket
import threading
import time
import traceback

from ida_mcp import registry
from ida_mcp.config import (
    get_gateway_internal_host,
    get_gateway_internal_port,
    get_http_bind_host,
    get_http_path,
    get_http_port,
    get_ida_default_port,
    get_server_name,
    is_http_enabled,
    is_unsafe_enabled,
)
from ida_mcp.runtime import start_http_proxy_if_gateway
from ida_mcp.server_factory import create_mcp_server

_server_thread: threading.Thread | None = (
    None  # background uvicorn thread (runs the FastMCP ASGI service)
)
_uv_server = None  # type: ignore               # uvicorn.Server reference, used for graceful shutdown (should_exit)
_startup_thread: threading.Thread | None = (
    None  # startup preflight thread (checks gateway health before launching instance listener)
)
_startup_stop = threading.Event()  # startup preflight cancellation signal (set in stop_server)
_stop_lock = threading.Lock()  # mutex to prevent concurrent re-entry into stop_server
_active_port: int | None = None  # actual MCP listen port of the current instance (set after startup, cleared on stop)
_hb_thread: threading.Thread | None = (
    None  # heartbeat/keepalive thread (monitors coordinator state and periodically refreshes registration)
)
_hb_stop = threading.Event()  # heartbeat thread stop signal (set in stop_server)
_tick_thread: threading.Thread | None = None
_tick_stop_event = threading.Event()
_last_register_ts: float | None = (
    None  # timestamp of the most recent successful registry.init_and_register call (updated only on re-registration after loss)
)
_ENABLE_PERIODIC_REFRESH = (
    False  # set to True to enable "timeout periodic refresh" logic; by default only re-register on loss
)
_REGISTER_INTERVAL = 300  # (optional) original threshold for periodic refresh; disabled by default
_HEARTBEAT_INTERVAL = 5  # heartbeat loop wake/polling interval
_HEARTBEAT_WARN_INTERVAL = 300  # minimum interval between repeated heartbeat failure warnings
_cached_input_file: str | None = (
    None  # cached input binary path (initialized on main thread only; heartbeat thread avoids calling IDA API directly)
)
_cached_idb_path: str | None = (
    None  # cached IDB path (same as above; avoid background thread accessing IDA C interface)
)
_hb_failure_count = 0  # consecutive heartbeat re-registration failure count
_hb_last_failure_sig: str | None = None  # most recent heartbeat failure signature
_hb_last_warn_ts = 0.0  # most recent heartbeat warning timestamp
_last_main_thread_tick_at: float | None = None
_MAIN_THREAD_TICK_INTERVAL = 5.0

_host_tick_fn = None
_host_prime_paths = None


def register_host_callbacks(*, tick_loop_fn=None, prime_paths_fn=None):
    global _host_tick_fn, _host_prime_paths
    if tick_loop_fn is not None:
        _host_tick_fn = tick_loop_fn
    if prime_paths_fn is not None:
        _host_prime_paths = prime_paths_fn


def set_path_cache(input_file, idb_path):
    global _cached_input_file, _cached_idb_path
    _cached_input_file = input_file
    _cached_idb_path = idb_path


def set_main_thread_tick(ts=None):
    global _last_main_thread_tick_at
    _last_main_thread_tick_at = time.time() if ts is None else ts


def start_tick_thread() -> None:
    global _tick_thread
    set_main_thread_tick()
    if _tick_thread is not None and _tick_thread.is_alive():
        return
    _tick_stop_event.clear()
    if _host_tick_fn is None:
        return
    _tick_thread = threading.Thread(
        target=_host_tick_fn,
        name="IDA-MCP-MainThreadTick",
        daemon=True,
    )
    _tick_thread.start()


def _wait_for_server_start(ready_event: threading.Event, server_obj) -> None:
    """Wait for uvicorn to set the started flag to True."""
    try:
        for _ in range(100):
            if getattr(server_obj, "started", False):
                ready_event.set()
                return
            if getattr(server_obj, "should_exit", False):
                return
            time.sleep(0.05)
    except Exception:
        return


def _port_is_listening(host: str, port: int, timeout: float = 0.2) -> bool:
    """Check whether the MCP HTTP listener is already accepting TCP connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _complete_startup_in_background(
    host: str,
    port: int,
    server_ready: threading.Event,
    server_failed: threading.Event,
) -> None:
    """Finish registration after the HTTP listener is ready without blocking the UI thread."""
    start_ts = time.monotonic()
    warned_slow = False
    while True:
        if _uv_server is not None and getattr(_uv_server, "should_exit", False):
            return
        if server_ready.is_set() or _port_is_listening(host, port):
            break
        if server_failed.is_set() or not (_server_thread and _server_thread.is_alive()):
            _error(f"Server failed before bind on {host}:{port}")
            return
        if not warned_slow and (time.monotonic() - start_ts) >= 5.0:
            warned_slow = True
            _warn(
                f"Server startup is taking longer than expected on {host}:{port}; registration continues in background."
            )
        time.sleep(0.1)

    # Only mark the instance as active after gateway registration succeeds.
    global _active_port
    if _active_port == port:
        return
    if _uv_server is not None and getattr(_uv_server, "should_exit", False):
        return
    _info(
        f"Instance MCP listener is ready at http://{host}:{port}/mcp/; "
        "registering with gateway."
    )
    if not _register_with_coordinator(port):
        _warn(
            f"Instance MCP server is listening on {host}:{port}, but gateway registration is incomplete."
        )
        return
    _active_port = port
    start_tick_thread()
    # record registration time and start heartbeat thread
    global _hb_thread, _last_register_ts
    _last_register_ts = time.time()
    if _hb_thread is None or not _hb_thread.is_alive():
        _hb_stop.clear()
        _hb_thread = threading.Thread(
            target=_heartbeat_loop, name="IDA-MCP-Heartbeat", daemon=True
        )
        _hb_thread.start()
        _info("Heartbeat thread started.")


def _heartbeat_loop():
    """Background heartbeat: periodically verify the coordinator is still reachable and
    this instance's record exists, otherwise re-register.

    Triggers:
        * coordinator list is empty (all instances lost) -> re-register (may rebuild coordinator)
        * this instance's pid is absent from get_instances() results -> re-register
        * under normal conditions, refresh every _REGISTER_INTERVAL seconds (updates started time to stay active)

    Design considerations:
        * registry currently has no heartbeat timeout, but the coordinator thread may be killed by the system or exceptions.
        * uses lightweight polling to avoid calling the IDA main thread; only accesses registry (pure network/memory operations).
        * exits immediately if the server has stopped (_active_port is None).
    """
    global _last_register_ts
    pid = os.getpid()

    # wait for server initialization (up to 10 seconds)
    for _ in range(20):
        if _hb_stop.is_set():
            _info("Heartbeat thread exit (stop signal during startup).")
            return
        if _uv_server is not None:
            break
        time.sleep(0.5)

    while not _hb_stop.is_set():
        # exit if service has already stopped
        if _active_port is None:
            break
        # server may be restarting; skip this round
        if _uv_server is None:
            _hb_stop.wait(_HEARTBEAT_INTERVAL)
            continue
        try:
            inst_list = registry.get_instances()
        except Exception:
            inst_list = []
        tick_at = _last_main_thread_tick_at
        tick_lag = None if tick_at is None else max(time.time() - tick_at, 0.0)
        if _active_port is not None:
            try:
                registry.update_instance_status(
                    pid=pid,
                    port=_active_port,
                    lifecycle_state="ready",
                    ready=True,
                    main_thread_last_tick_at=tick_at,
                    main_thread_lag_seconds=tick_lag,
                )
            except Exception:
                pass
        need_register = False
        now = time.time()
        if not inst_list:
            need_register = True
        else:
            found = any(e.get("pid") == pid for e in inst_list)
            if not found:
                need_register = True
        # no longer perform "time-driven forced refresh" by default; only re-register when instance is missing or coordinator is rebuilt.
        if (
            not need_register
            and _ENABLE_PERIODIC_REFRESH
            and _last_register_ts
            and (now - _last_register_ts) > _REGISTER_INTERVAL
        ):
            need_register = True  # optional: restore old logic when user explicitly enables it
        if need_register and _active_port is not None:
            try:
                # use only cached paths/files to avoid background thread touching IDA API
                registry.init_and_register(
                    _active_port, _cached_input_file, _cached_idb_path
                )
                registry.update_instance_status(
                    pid=pid,
                    port=_active_port,
                    lifecycle_state="ready",
                    ready=True,
                    main_thread_last_tick_at=tick_at,
                    main_thread_lag_seconds=tick_lag,
                )
                _last_register_ts = now
                _reset_heartbeat_failure_tracking(log_recovery=True)
                if inst_list:
                    _info(
                        "Heartbeat re-register (periodic refresh) done."
                    ) if _ENABLE_PERIODIC_REFRESH else None
                else:
                    _info(
                        "Heartbeat re-register successful (gateway rebuilt or entry missing)."
                    )
            except Exception as e:  # pragma: no cover
                _report_heartbeat_failure(str(e))
        _hb_stop.wait(_HEARTBEAT_INTERVAL)
    _info("Heartbeat thread exit.")


# ---------------- Logging Helpers (INFO/WARN/ERROR) -----------------


def _now_ts() -> str:
    return time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"


def _log(level: str, msg: str):
    """Unified log output with timestamp (HH:MM:SS.mmm)."""
    print(f"[IDA-MCP][{level}][{_now_ts()}] {msg}")


def _info(msg: str):
    _log("INFO", msg)


def _warn(msg: str):
    _log("WARN", msg)


def _error(msg: str):
    _log("ERROR", msg)


def _gateway_diagnostics_text() -> str:
    """Summarize gateway launch diagnostics for IDA main-log output."""
    status_getter = getattr(registry, "get_registry_server_status", None)
    if not callable(status_getter):
        return ""
    try:
        status = status_getter() or {}
    except Exception:
        return ""

    parts = []
    if status.get("python"):
        parts.append(f"python={status['python']}")
    if status.get("log"):
        parts.append(f"log={status['log']}")
    if status.get("last_error"):
        parts.append(f"last_error={status['last_error']}")
    return ", ".join(parts)


def _report_heartbeat_failure(error_text: str) -> None:
    """Throttle repeated heartbeat registration failures in the main log."""
    global _hb_failure_count, _hb_last_failure_sig, _hb_last_warn_ts

    now = time.time()
    repeated = error_text == _hb_last_failure_sig
    _hb_failure_count += 1
    should_warn = (
        _hb_failure_count == 1
        or not repeated
        or (now - _hb_last_warn_ts) >= _HEARTBEAT_WARN_INTERVAL
    )
    if not should_warn:
        return

    suppressed = _hb_failure_count - 1
    prefix = "Heartbeat re-register failed"
    if suppressed > 0:
        prefix += f" ({suppressed} similar failure(s) suppressed)"
    _warn(f"{prefix}: {error_text}")
    _hb_last_failure_sig = error_text
    _hb_last_warn_ts = now


def _reset_heartbeat_failure_tracking(log_recovery: bool = False) -> None:
    """Clear heartbeat failure throttling state after success or shutdown."""
    global _hb_failure_count, _hb_last_failure_sig, _hb_last_warn_ts
    if log_recovery and _hb_failure_count > 0:
        _info(
            f"Heartbeat re-register recovered after {_hb_failure_count} consecutive failure(s)."
        )
    _hb_failure_count = 0
    _hb_last_failure_sig = None
    _hb_last_warn_ts = 0.0


def _find_free_port(preferred: int, host: str = "127.0.0.1", max_scan: int = 50) -> int:
    """Port scan: try binding upward from preferred and return the first free port;
    if all fail, return preferred as fallback.

    Args:
        preferred: starting port number
        host: address to bind (must match the actual listen address)
        max_scan: maximum scan attempts

    Note: default port starts at 9000 to avoid the Windows Hyper-V reserved port range (8709-8808).
    Does not use SO_REUSEADDR because on Windows it behaves like SO_REUSEPORT.
    """
    for i in range(max_scan):
        p = preferred + i
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, p))
            except OSError:
                continue
            return p
    _warn(f"Port scan exhausted; falling back to preferred {preferred}")
    return preferred


def _select_start_port(host: str) -> int:
    """Select a bindable MCP port, treating bootstrap IDA_MCP_PORT as a preferred starting point."""
    env_port = os.getenv("IDA_MCP_PORT")
    if env_port and env_port.isdigit():
        return _find_free_port(int(env_port), host)
    return _find_free_port(get_ida_default_port(), host)


def _ensure_gateway_ready_for_startup() -> bool:
    """Confirm the standalone gateway is healthy before exposing the instance listener."""
    gateway_host = get_gateway_internal_host()
    gateway_port = get_gateway_internal_port()
    _info(
        f"Checking gateway health at {gateway_host}:{gateway_port} before starting instance MCP listener."
    )
    if registry.ensure_registry_server():
        _info(
            f"Gateway is healthy at {gateway_host}:{gateway_port}; continuing instance startup."
        )
        return True

    _error(
        f"Gateway preflight failed at {gateway_host}:{gateway_port}; "
        "instance MCP listener will not be started."
    )
    diag = _gateway_diagnostics_text()
    if diag:
        _error(f"Gateway diagnostics: {diag}")
    return False


def _register_with_coordinator(port: int) -> bool:
    """Register the current instance metadata with the coordinator.

    Args:
        port: the current instance's FastMCP HTTP listen port.
    Notes:
        * If the standalone coordinator/HTTP proxy is not yet running, it will be launched on demand.
        * Registration includes: pid / port / input file path / idb path / Python version, etc.
    """
    global _cached_input_file, _cached_idb_path
    if _host_prime_paths:
        _host_prime_paths()
    try:
        registry.init_and_register(port, _cached_input_file, _cached_idb_path)
        http_proxy_ready = start_http_proxy_if_gateway()
        _reset_heartbeat_failure_tracking()
        _info(
            f"Registered instance at port={port} pid={os.getpid()} input='{_cached_input_file}' idb='{_cached_idb_path}'"
        )
        if http_proxy_ready:
            _info(
                f"HTTP MCP proxy listening on "
                f"http://{get_http_bind_host()}:{get_http_port()}{get_http_path()}"
            )
        elif is_http_enabled():
            proxy_status = getattr(registry, "get_http_proxy_status", lambda: {})()
            status_parts = []
            if proxy_status.get("python"):
                status_parts.append(f"python={proxy_status['python']}")
            if proxy_status.get("log"):
                status_parts.append(f"log={proxy_status['log']}")
            if proxy_status.get("last_error"):
                status_parts.append(f"last_error={proxy_status['last_error']}")
            suffix = f" ({', '.join(status_parts)})" if status_parts else ""
            _warn(f"HTTP MCP proxy launch requested but not yet reachable{suffix}")
        gateway_suffix = get_http_path() if is_http_enabled() else ""
        _info(
            f"Gateway listening on {get_http_bind_host()}:{get_http_port()}{gateway_suffix}"
        )
        return True
    except Exception as e:  # pragma: no cover
        _error(f"Gateway registration failed: {e}")
        diag = _gateway_diagnostics_text()
        if diag:
            _error(f"Gateway diagnostics: {diag}")
        traceback.print_exc()
        return False


def _update_lifecycle_state(port: int, state: str, ready: bool) -> None:
    try:
        registry.update_instance_status(
            pid=os.getpid(),
            port=port,
            lifecycle_state=state,
            ready=ready,
        )
    except Exception:
        pass


def is_running() -> bool:
    return (_startup_thread is not None and _startup_thread.is_alive()) or (
        _server_thread is not None and _server_thread.is_alive()
    )


def stop_server():
    """Stop the server (toggle).

    Steps:
        1. Set ``_uv_server.should_exit`` to trigger uvicorn event loop exit.
        2. Join background threads (up to 5 seconds).
        3. Deregister the current instance from the standalone coordinator.
    Concurrency safety:
        Uses ``_stop_lock`` to prevent multiple simultaneous calls.
    """
    global _startup_thread, _uv_server, _server_thread
    with _stop_lock:
        startup_thread = _startup_thread
        startup_active = startup_thread is not None and startup_thread.is_alive()
        if _uv_server is None and not startup_active:
            _info("Stop requested, but server not running.")
            return
        if startup_active:
            _startup_stop.set()
            _info("Startup cancellation requested.")
        try:
            # Graceful shutdown
            if _uv_server is not None:
                _uv_server.should_exit = True  # type: ignore[attr-defined]
                _info("Shutdown signal sent to uvicorn server.")
        except Exception as e:  # pragma: no cover
            _error(f"Failed to signal shutdown: {e}")
        if startup_thread:
            startup_thread.join(timeout=5)
            if not startup_thread.is_alive():
                _startup_thread = None
        if _server_thread:
            # Join server thread with timeout
            _server_thread.join(timeout=5)
        global _active_port
        _server_thread = None
        _uv_server = None
        if _active_port is not None:
            try:
                registry.deregister()
            except Exception as e:  # pragma: no cover
                _warn(f"Deregister failed: {e}")
        _active_port = None
        # stop heartbeat thread
        global _hb_thread, _tick_thread, _last_main_thread_tick_at
        if _hb_thread and _hb_thread.is_alive():
            _hb_stop.set()
            _hb_thread.join(timeout=3)
        _hb_thread = None
        if _tick_thread and _tick_thread.is_alive():
            _tick_stop_event.set()
            _tick_thread.join(timeout=1)
        _tick_thread = None
        _last_main_thread_tick_at = None
        _reset_heartbeat_failure_tracking()
        _info("Server stopped.")


def _start_instance_server_threads(host: str, port: int) -> None:
    """Launch the instance uvicorn worker only after gateway preflight has passed."""
    global _server_thread, _uv_server
    server_ready = threading.Event()
    server_failed = threading.Event()

    def worker():
        global _uv_server
        try:
            # Windows console noise suppression: use Selector event loop instead of Proactor,
            # avoiding the ConnectionResetError(WinError 10054) callback exception printed by
            # asyncio in _ProactorBasePipeTransport._call_connection_lost.
            if os.name == "nt":
                try:
                    import asyncio  # type: ignore

                    if hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
                        asyncio.set_event_loop_policy(
                            asyncio.WindowsSelectorEventLoopPolicy()
                        )  # type: ignore[attr-defined]
                except Exception:
                    pass  # policy setup failure does not affect subsequent logic; at most produces original console messages
            server = create_mcp_server(
                name=get_server_name(),
                enable_unsafe=is_unsafe_enabled(),
            )
            # build ASGI app (Streamable HTTP), mount path '/mcp'
            app = server.http_app(path="/mcp")  # type: ignore[attr-defined]
            # re-apply warning filters before importing uvicorn
            import warnings as _w

            _w.filterwarnings(
                "ignore", category=DeprecationWarning, module=r"websockets"
            )
            _w.filterwarnings("ignore", category=DeprecationWarning, module=r"uvicorn")
            import uvicorn  # Local import to avoid overhead if never started

            # use warning log level and disable access log to avoid meaningless CTRL+C messages
            config = uvicorn.Config(
                app, host=host, port=port, log_level="warning", access_log=False
            )
            _uv_server = uvicorn.Server(config)
            # do not use uvicorn.Server.run() (it creates/manages its own event loop);
            # instead create the loop explicitly in this thread and install an exception handler
            # to suppress the common Windows WinError 10054 "remote host forcibly closed connection" noise.
            import asyncio

            def _exception_handler(loop, context):  # type: ignore[no-untyped-def]
                exc = context.get("exception")
                if exc is not None:
                    winerr = getattr(exc, "winerror", None)
                    if winerr == 10054 and isinstance(
                        exc, (ConnectionResetError, OSError)
                    ):
                        return
                msg = str(context.get("message") or "")
                if "10054" in msg and "ConnectionResetError" in msg:
                    return
                loop.default_exception_handler(context)

            loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(loop)
                loop.set_exception_handler(_exception_handler)
                threading.Thread(
                    target=_wait_for_server_start,
                    args=(server_ready, _uv_server),
                    name="IDA-MCP-ServerReady",
                    daemon=True,
                ).start()
                if hasattr(_uv_server, "serve"):
                    loop.run_until_complete(_uv_server.serve())  # type: ignore[attr-defined]
                else:  # pragma: no cover
                    _uv_server.run()
            finally:
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                except Exception:
                    pass
                try:
                    loop.run_until_complete(loop.shutdown_default_executor())
                except Exception:
                    pass
                try:
                    loop.close()
                except Exception:
                    pass
        except Exception as e:  # pragma: no cover
            server_failed.set()
            _error(f"Server crashed: {e}")
            traceback.print_exc()
        finally:
            _uv_server = None
            _info("Server thread exit.")

    _server_thread = threading.Thread(target=worker, name="IDA-MCP-Server", daemon=True)
    _server_thread.start()
    threading.Thread(
        target=_complete_startup_in_background,
        args=(host, port, server_ready, server_failed),
        name="IDA-MCP-StartupFinalize",
        daemon=True,
    ).start()


def start_server_async(host: str, port: int):
    """Asynchronously (in a thread) start the uvicorn FastMCP service.

    Design highlights:
        * Uses daemon threads to avoid blocking the IDA main thread.
        * Before launching the instance listener, confirms the standalone gateway is ready to avoid misleading users into thinking initialization is complete.
        * Achieves graceful shutdown by keeping a ``_uv_server`` reference (set should_exit).
        * Registers with the coordinator only after the instance MCP port is confirmed listening.
    """
    global _startup_thread
    if is_running():
        _info("Server already running; start request ignored.")
        return

    _startup_stop.clear()

    def bootstrap():
        global _startup_thread
        try:
            if _startup_stop.is_set():
                return
            if not _ensure_gateway_ready_for_startup():
                return
            _update_lifecycle_state(port, "analyzing", ready=False)
            if _startup_stop.is_set():
                _info("Startup cancelled before instance MCP listener launch.")
                return
            _info(
                f"Gateway preflight complete; starting instance MCP listener at http://{host}:{port}/mcp/"
            )
            _start_instance_server_threads(host, port)
        finally:
            _startup_thread = None

    _startup_thread = threading.Thread(
        target=bootstrap, name="IDA-MCP-Startup", daemon=True
    )
    _startup_thread.start()
