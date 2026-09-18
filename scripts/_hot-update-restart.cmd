@echo off
REM Spawned by the backend after a successful git fast-forward. Waits for the
REM API response to flush, then stop + start with the same listen settings.
setlocal EnableExtensions
cd /d "%~dp0.."
set "ROOT=%cd%"

REM ping delay so the HTTP response can finish before this process kills uvicorn
ping -n 4 127.0.0.1 >nul

call "%ROOT%\stop.cmd" --quiet

set "ARGS="
if defined VULNHUNTER_RELOAD if not "%VULNHUNTER_RELOAD%"=="0" set "ARGS=--reload"
if defined VULNHUNTER_HOST set "ARGS=%ARGS% --host %VULNHUNTER_HOST%"
if defined VULNHUNTER_PORT set "ARGS=%ARGS% --backend-port %VULNHUNTER_PORT%"
if defined VULNHUNTER_FRONTEND_PORT set "ARGS=%ARGS% --frontend-port %VULNHUNTER_FRONTEND_PORT%"

call "%ROOT%\start.cmd" %ARGS%
endlocal
