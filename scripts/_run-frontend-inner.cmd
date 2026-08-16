@echo off
setlocal EnableExtensions
cd /d "%~dp0.."
set "ROOT=%cd%"
set "LOGDIR=%ROOT%\data\logs"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"

cd /d "%ROOT%\frontend"
call npm run dev >> "%LOGDIR%\frontend.log" 2>&1
endlocal
