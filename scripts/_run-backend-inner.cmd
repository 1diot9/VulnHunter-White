@echo off
setlocal EnableExtensions
cd /d "%~dp0.."
set "ROOT=%cd%"
set "LOGDIR=%ROOT%\data\logs"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"
if not defined VULNHUNTER_PORT set "VULNHUNTER_PORT=16780"
if not defined VULNHUNTER_HOST set "VULNHUNTER_HOST=127.0.0.1"

if /I "%~1"=="--reload" set "VULNHUNTER_RELOAD=1"
set "RELOAD_ARGS="
if defined VULNHUNTER_RELOAD set "RELOAD_ARGS=--reload --reload-dir app"

cd /d "%ROOT%\backend"
call ".venv\Scripts\activate.bat"
REM timeout-graceful-shutdown: SSE 长连接否则会让热加载永远停在 Waiting for connections to close
uvicorn app.main:app %RELOAD_ARGS% --timeout-graceful-shutdown 2 --host %VULNHUNTER_HOST% --port %VULNHUNTER_PORT% >> "%LOGDIR%\backend.log" 2>&1
endlocal
