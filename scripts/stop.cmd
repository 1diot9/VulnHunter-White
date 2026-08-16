@echo off
setlocal EnableExtensions
cd /d "%~dp0.."

set "ROOT=%cd%"
set "PIDDIR=%ROOT%\data\run"
set "QUIET=0"
if /I "%~1"=="--quiet" set "QUIET=1"

if "%QUIET%"=="0" echo [VulnHunter] stopping...

REM Close helper console windows launched by start.cmd
for %%T in (VulnHunter-Backend VulnHunter-Frontend) do (
  taskkill /FI "WINDOWTITLE eq %%T*" /T /F >nul 2>&1
)

REM Kill listeners on 8000 / 5173 (locale-safe via PowerShell)
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ports = 8000,5173; foreach ($p in $ports) {" ^
  "  Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue |" ^
  "    Select-Object -ExpandProperty OwningProcess -Unique |" ^
  "    ForEach-Object {" ^
  "      if ($_ -and $_ -ne 0) {" ^
  "        if ('%QUIET%' -eq '0') { Write-Host ('  kill pid {0} on port {1}' -f $_, $p) };" ^
  "        Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue;" ^
  "        Get-CimInstance Win32_Process -Filter (\"ParentProcessId=\" + $_) -ErrorAction SilentlyContinue |" ^
  "          ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" ^
  "      }" ^
  "    }" ^
  "}"

REM Also kill common leftover node/uvicorn under this repo if still holding ports
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |" ^
  "  Where-Object {" ^
  "    $_.CommandLine -and (" ^
  "      $_.CommandLine -like '*VulnHunter*uvicorn*' -or" ^
  "      ($_.CommandLine -like '*VulnHunter*frontend*' -and $_.Name -match 'node|npm')" ^
  "    )" ^
  "  } |" ^
  "  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"

if exist "%PIDDIR%\backend.pid" del /f /q "%PIDDIR%\backend.pid" >nul 2>&1
if exist "%PIDDIR%\frontend.pid" del /f /q "%PIDDIR%\frontend.pid" >nul 2>&1

if "%QUIET%"=="0" echo [VulnHunter] stopped.
endlocal
