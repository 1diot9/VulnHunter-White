#!/usr/bin/env python3
"""Append a child process (or stdin) to data/logs/{prefix}-YYYY-MM-DD.log.

Switches files at local midnight so a long-running backend/frontend does not
keep growing a single log.
"""
from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
from datetime import date
from pathlib import Path
from typing import Callable, IO, Sequence


class DailyWriter:
    def __init__(
        self,
        logdir: Path,
        prefix: str,
        today: Callable[[], date] = date.today,
    ) -> None:
        self.logdir = Path(logdir)
        self.prefix = prefix
        self._today = today
        self._day: date | None = None
        self._fh: IO[bytes] | None = None
        self.logdir.mkdir(parents=True, exist_ok=True)

    def path_for(self, day: date) -> Path:
        return self.logdir / f"{self.prefix}-{day.isoformat()}.log"

    def write(self, data: bytes) -> None:
        if not data:
            return
        day = self._today()
        if self._fh is None or self._day != day:
            if self._fh is not None:
                self._fh.close()
            self._day = day
            self._fh = open(self.path_for(day), "ab")
        self._fh.write(data)
        self._fh.flush()

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None


def pump(src: IO[bytes], writer: DailyWriter, chunk_size: int = 8192) -> None:
    while True:
        chunk = src.read(chunk_size)
        if not chunk:
            return
        writer.write(chunk)


def _resolve_command(command: Sequence[str]) -> list[str]:
    cmd = list(command)
    if not cmd:
        return cmd
    exe = cmd[0]
    if os.path.sep in exe or (os.path.altsep and os.path.altsep in exe):
        return cmd
    found = shutil.which(exe)
    if found:
        cmd[0] = found
    return cmd


def _run_command(command: Sequence[str], writer: DailyWriter) -> int:
    cmd = _resolve_command(command)
    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            bufsize=0,
        )
    except OSError as exc:
        msg = f"[VulnHunter] failed to start {' '.join(command)}: {exc}\n"
        writer.write(msg.encode("utf-8", errors="replace"))
        return 1

    def _forward(signum: int, _frame: object) -> None:
        if proc.poll() is None:
            try:
                proc.send_signal(signum)
            except OSError:
                pass

    signal.signal(signal.SIGINT, _forward)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _forward)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, _forward)

    assert proc.stdout is not None
    try:
        pump(proc.stdout, writer)
        return int(proc.wait())
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write process logs to daily files.")
    parser.add_argument("--dir", required=True, help="Log directory (e.g. data/logs)")
    parser.add_argument("--prefix", required=True, help="Filename prefix (backend/frontend)")
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command to run; stdout/stderr go to the daily log. Omit to copy stdin.",
    )
    args = parser.parse_args(argv)
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]

    writer = DailyWriter(Path(args.dir), args.prefix)
    try:
        if command:
            return _run_command(command, writer)
        pump(sys.stdin.buffer, writer)
        return 0
    finally:
        writer.close()


if __name__ == "__main__":
    raise SystemExit(main())
