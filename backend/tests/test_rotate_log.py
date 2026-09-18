from __future__ import annotations

import importlib.util
import sys
from datetime import date
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts" / "rotate_log.py"


def load_rotate_log():
    spec = importlib.util.spec_from_file_location("rotate_log", SCRIPTS)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Clock:
    def __init__(self, day: date) -> None:
        self.day = day

    def __call__(self) -> date:
        return self.day


def test_daily_writer_switches_file_on_date_change(tmp_path):
    rotate_log = load_rotate_log()
    clock = Clock(date(2026, 9, 18))
    writer = rotate_log.DailyWriter(tmp_path, "backend", today=clock)
    writer.write(b"day-one\n")
    clock.day = date(2026, 9, 19)
    writer.write(b"day-two\n")
    writer.close()

    first = tmp_path / "backend-2026-09-18.log"
    second = tmp_path / "backend-2026-09-19.log"
    assert first.read_bytes() == b"day-one\n"
    assert second.read_bytes() == b"day-two\n"
    assert not (tmp_path / "backend.log").exists()


def test_rotate_log_runs_command_into_dated_file(tmp_path, monkeypatch):
    rotate_log = load_rotate_log()
    monkeypatch.chdir(tmp_path)
    code = rotate_log.main(
        [
            "--dir",
            str(tmp_path),
            "--prefix",
            "frontend",
            "--",
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('hello-ui\\n'); sys.stderr.write('warn\\n')",
        ]
    )
    assert code == 0
    day = date.today().isoformat()
    text = (tmp_path / f"frontend-{day}.log").read_text(encoding="utf-8")
    assert "hello-ui" in text
    assert "warn" in text


def test_rotate_log_stdin_mode(tmp_path, monkeypatch):
    rotate_log = load_rotate_log()

    class FakeStdin:
        def __init__(self) -> None:
            self._data = b"[VulnHunter] missing backend/.venv\n"
            self._sent = False

        def read(self, _n: int) -> bytes:
            if self._sent:
                return b""
            self._sent = True
            return self._data

    monkeypatch.setattr(rotate_log.sys, "stdin", type("Stdin", (), {"buffer": FakeStdin()})())
    code = rotate_log.main(["--dir", str(tmp_path), "--prefix", "backend"])
    assert code == 0
    day = date.today().isoformat()
    assert (tmp_path / f"backend-{day}.log").read_text(encoding="utf-8").startswith(
        "[VulnHunter] missing backend/.venv"
    )


def test_rotate_log_missing_command_is_logged(tmp_path):
    rotate_log = load_rotate_log()
    code = rotate_log.main(
        [
            "--dir",
            str(tmp_path),
            "--prefix",
            "backend",
            "--",
            "__vulnhunter_no_such_cmd__",
        ]
    )
    assert code == 1
    day = date.today().isoformat()
    text = (tmp_path / f"backend-{day}.log").read_text(encoding="utf-8")
    assert "failed to start" in text
