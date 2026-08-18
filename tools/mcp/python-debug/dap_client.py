from __future__ import annotations

import asyncio
import json
import logging
import sys
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)


class DapError(Exception):
    def __init__(self, message: str, body: dict | None = None):
        super().__init__(message)
        self.body = body


@dataclass
class DapClient:
    """Async DAP client that communicates with debugpy via subprocess stdio or TCP."""

    _process: asyncio.subprocess.Process | None = field(default=None, repr=False)
    _reader: asyncio.StreamReader | None = field(default=None, repr=False)
    _writer: asyncio.StreamWriter | None = field(default=None, repr=False)
    _seq: int = field(default=0, repr=False)
    _pending: dict[int, asyncio.Future] = field(default_factory=dict, repr=False)
    _event_handlers: dict[str, list[Callable]] = field(default_factory=dict, repr=False)
    _recv_task: asyncio.Task | None = field(default=None, repr=False)
    _connected: bool = False
    _mode: str = field(default="subprocess", repr=False)

    @property
    def connected(self) -> bool:
        return self._connected

    async def start(self, python: str | None = None) -> None:
        python = python or sys.executable
        self._process = await asyncio.create_subprocess_exec(
            python, "-m", "debugpy.adapter",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._reader = self._process.stdout
        self._writer = self._process.stdin
        self._connected = True
        self._mode = "subprocess"
        self._recv_task = asyncio.create_task(self._recv_loop())

    async def connect_tcp(self, host: str, port: int, timeout: float = 10.0) -> None:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout,
        )
        self._reader = reader
        self._writer = writer
        self._connected = True
        self._mode = "tcp"
        self._recv_task = asyncio.create_task(self._recv_loop())

    async def stop(self) -> None:
        self._connected = False
        if self._recv_task and not self._recv_task.done():
            self._recv_task.cancel()
            try:
                await self._recv_task
            except asyncio.CancelledError:
                pass
        if self._mode == "tcp" and self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        if self._process and self._process.returncode is None:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    self._process.kill()
                except ProcessLookupError:
                    pass
        self._process = None
        self._reader = None
        self._writer = None
        self._mode = "subprocess"
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(ConnectionError("DAP adapter stopped"))
        self._pending.clear()

    async def send_request(
        self, command: str, arguments: dict[str, Any] | None = None, timeout: float = 30.0
    ) -> dict[str, Any]:
        if not self._connected:
            raise ConnectionError("DAP adapter not running")

        self._seq += 1
        seq = self._seq
        msg: dict[str, Any] = {
            "seq": seq,
            "type": "request",
            "command": command,
        }
        if arguments is not None:
            msg["arguments"] = arguments

        loop = asyncio.get_running_loop()
        future: asyncio.Future[dict[str, Any]] = loop.create_future()
        self._pending[seq] = future

        await self._send_raw(msg)

        try:
            resp = await asyncio.wait_for(future, timeout=timeout)
            return resp
        except asyncio.TimeoutError:
            self._pending.pop(seq, None)
            raise TimeoutError(f"DAP request '{command}' timed out after {timeout}s")

    def on_event(self, event: str, handler: Callable[[dict[str, Any]], None]) -> None:
        self._event_handlers.setdefault(event, []).append(handler)

    def remove_event_handler(self, event: str, handler: Callable) -> None:
        handlers = self._event_handlers.get(event, [])
        if handler in handlers:
            handlers.remove(handler)

    async def wait_for_event(self, event: str, timeout: float = 30.0) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[dict[str, Any]] = loop.create_future()

        def handler(body: dict[str, Any]) -> None:
            if not future.done():
                future.set_result(body)

        self.on_event(event, handler)
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        finally:
            self.remove_event_handler(event, handler)

    # ── internals ──

    async def _send_raw(self, msg: dict[str, Any]) -> None:
        body = json.dumps(msg, ensure_ascii=False).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        assert self._writer is not None
        self._writer.write(header + body)
        if self._mode == "tcp":
            await self._writer.drain()

    async def _read_message(self) -> dict[str, Any] | None:
        assert self._reader is not None
        headers: dict[str, str] = {}
        while True:
            line = await self._reader.readline()
            if not line:
                return None
            decoded = line.decode("ascii").strip()
            if not decoded:
                break
            if ":" in decoded:
                key, value = decoded.split(":", 1)
                headers[key.strip()] = value.strip()

        content_length_str = headers.get("Content-Length")
        if content_length_str is None:
            return None
        content_length = int(content_length_str)
        body = await self._reader.readexactly(content_length)
        return json.loads(body)

    async def _recv_loop(self) -> None:
        try:
            while self._connected:
                msg = await self._read_message()
                if msg is None:
                    break
                self._dispatch(msg)
        except asyncio.CancelledError:
            pass
        except (ConnectionError, EOFError, asyncio.IncompleteReadError):
            logger.debug("DAP adapter connection lost")
        except Exception:
            logger.exception("DAP recv loop error")
        finally:
            self._connected = False
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(ConnectionError("DAP adapter connection lost"))
            self._pending.clear()

    def _dispatch(self, msg: dict[str, Any]) -> None:
        msg_type = msg.get("type")

        if msg_type == "response":
            request_seq = msg.get("request_seq")
            future = self._pending.pop(request_seq, None)
            if future and not future.done():
                if msg.get("success", True):
                    future.set_result(msg.get("body") or {})
                else:
                    future.set_exception(
                        DapError(msg.get("message", "Unknown DAP error"), msg.get("body"))
                    )

        elif msg_type == "event":
            event_name = msg.get("event", "")
            event_body = msg.get("body") or {}
            logger.debug("DAP event: %s %s", event_name, event_body)
            for handler in list(self._event_handlers.get(event_name, [])):
                try:
                    handler(event_body)
                except Exception:
                    logger.exception("Error in event handler for '%s'", event_name)
