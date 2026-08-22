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

REM Kill listeners on last-used / requested / default ports (locale-safe via PowerShell)
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ports = New-Object 'System.Collections.Generic.HashSet[int]';" ^
  "function Add-Port([string]$raw) {" ^
  "  $n = 0;" ^
  "  if ([int]::TryParse((($raw) -replace '\s',''), [ref]$n) -and $n -ge 1 -and $n -le 65535) { [void]$ports.Add($n) }" ^
  "};" ^
  "Add-Port $env:VULNHUNTER_PORT; Add-Port $env:VULNHUNTER_FRONTEND_PORT;" ^
  "$envFile = Join-Path '%PIDDIR%' 'ports.env';" ^
  "if (Test-Path -LiteralPath $envFile) {" ^
  "  Get-Content -LiteralPath $envFile | ForEach-Object {" ^
  "    if ($_ -match '^\s*VULNHUNTER_PORT\s*=\s*(.+?)\s*$') { Add-Port $Matches[1] }" ^
  "    if ($_ -match '^\s*VULNHUNTER_FRONTEND_PORT\s*=\s*(.+?)\s*$') { Add-Port $Matches[1] }" ^
  "  }" ^
  "};" ^
  "Add-Port 16780; Add-Port 15173;" ^
  "foreach ($p in $ports) {" ^
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

REM Also kill leftover node/uvicorn under this repo if still holding ports
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$root = '%ROOT%';" ^
  "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |" ^
  "  Where-Object {" ^
  "    $_.CommandLine -and (" ^
  "      $_.CommandLine -like ('*' + $root + '*uvicorn*') -or" ^
  "      ($_.CommandLine -like ('*' + $root + '*frontend*') -and $_.Name -match 'node|npm')" ^
  "    )" ^
  "  } |" ^
  "  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"

if exist "%PIDDIR%\backend.pid" del /f /q "%PIDDIR%\backend.pid" >nul 2>&1
if exist "%PIDDIR%\frontend.pid" del /f /q "%PIDDIR%\frontend.pid" >nul 2>&1
if exist "%PIDDIR%\ports.env" del /f /q "%PIDDIR%\ports.env" >nul 2>&1

if "%QUIET%"=="0" echo [VulnHunter] stopped.
endlocal
