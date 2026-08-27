@echo off
setlocal EnableExtensions
cd /d "%~dp0.."
set "ROOT=%cd%"
set "LOGDIR=%ROOT%\data\logs"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"
if not defined VULNHUNTER_FRONTEND_PORT set "VULNHUNTER_FRONTEND_PORT=15173"
if not defined VULNHUNTER_PORT set "VULNHUNTER_PORT=16780"
if not defined VULNHUNTER_HOST set "VULNHUNTER_HOST=127.0.0.1"

cd /d "%ROOT%\frontend"
call npm run dev -- --host %VULNHUNTER_HOST% --port %VULNHUNTER_FRONTEND_PORT% --strictPort >> "%LOGDIR%\frontend.log" 2>&1
endlocal
