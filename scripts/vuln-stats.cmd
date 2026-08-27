@echo off
if not exist "%~dp0..\backend\.venv\Scripts\python.exe" (
  echo [VulnHunter] missing backend/.venv — run start.cmd first
  exit /b 1
)
"%~dp0..\backend\.venv\Scripts\python.exe" "%~dp0vuln_stats.py" %*
