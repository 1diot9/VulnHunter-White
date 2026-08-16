@echo off
REM Kept for manual single-service debug; prefer ..\start.cmd
cd /d "%~dp0.."
call "%~dp0_run-backend-inner.cmd" %*
