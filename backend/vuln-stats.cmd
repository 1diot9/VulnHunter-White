@echo off
REM Convenience entry when cwd is backend (venv already activated or not).
if not exist "%~dp0.venv\Scripts\python.exe" (
  echo [VulnHunter] missing backend/.venv — run start.cmd first
  exit /b 1
)
"%~dp0.venv\Scripts\python.exe" "%~dp0..\scripts\vuln_stats.py" %*
