@echo off
setlocal EnableExtensions
cd /d "%~dp0"
call "%~dp0scripts\stop.cmd" %*
endlocal
