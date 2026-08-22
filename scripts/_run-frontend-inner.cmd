@echo off
setlocal EnableExtensions
cd /d "%~dp0.."
set "ROOT=%cd%"
set "LOGDIR=%ROOT%\data\logs"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"
if not defined VULNHUNTER_FRONTEND_PORT set "VULNHUNTER_FRONTEND_PORT=15173"
if not defined VULNHUNTER_PORT set "VULNHUNTER_PORT=16780"

cd /d "%ROOT%\frontend"
call npm run dev -- --host 127.0.0.1 --port %VULNHUNTER_FRONTEND_PORT% --strictPort >> "%LOGDIR%\frontend.log" 2>&1
endlocal
