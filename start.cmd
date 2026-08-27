@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

set "ROOT=%~dp0"
set "PIDDIR=%ROOT%data\run"
set "LOGDIR=%ROOT%data\logs"
if not exist "%PIDDIR%" mkdir "%PIDDIR%"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"

REM Defaults: 16780 / 15173 avoid the crowded 8000 and Vite 5173.
if not defined VULNHUNTER_PORT set "VULNHUNTER_PORT=16780"
if not defined VULNHUNTER_FRONTEND_PORT set "VULNHUNTER_FRONTEND_PORT=15173"
if not defined VULNHUNTER_HOST set "VULNHUNTER_HOST=127.0.0.1"
set "VULNHUNTER_RELOAD="

:parse_args
if "%~1"=="" goto :args_done
set "ARG=%~1"
if /I "!ARG!"=="--reload" (
  set "VULNHUNTER_RELOAD=1"
  shift
  goto :parse_args
)
if /I "!ARG!"=="--lan" (
  set "VULNHUNTER_HOST=0.0.0.0"
  shift
  goto :parse_args
)
if /I "!ARG!"=="-h" goto :help
if /I "!ARG!"=="--help" goto :help
if /I "!ARG!"=="--host" goto :need_host
if /I "!ARG!"=="--backend-port" goto :need_backend_port
if /I "!ARG!"=="--api-port" goto :need_backend_port
if /I "!ARG!"=="--frontend-port" goto :need_frontend_port
if /I "!ARG!"=="--ui-port" goto :need_frontend_port
if /I "!ARG:~0,7!"=="--host=" (
  set "VULNHUNTER_HOST=!ARG:~7!"
  shift
  goto :parse_args
)
if /I "!ARG:~0,15!"=="--backend-port=" (
  set "VULNHUNTER_PORT=!ARG:~15!"
  shift
  goto :parse_args
)
if /I "!ARG:~0,11!"=="--api-port=" (
  set "VULNHUNTER_PORT=!ARG:~11!"
  shift
  goto :parse_args
)
if /I "!ARG:~0,16!"=="--frontend-port=" (
  set "VULNHUNTER_FRONTEND_PORT=!ARG:~16!"
  shift
  goto :parse_args
)
if /I "!ARG:~0,10!"=="--ui-port=" (
  set "VULNHUNTER_FRONTEND_PORT=!ARG:~10!"
  shift
  goto :parse_args
)
echo [VulnHunter] unknown option: %~1
goto :usage

:need_host
if "%~2"=="" (
  echo [VulnHunter] %~1 needs a listen address ^(e.g. 0.0.0.0^)
  exit /b 1
)
set "VULNHUNTER_HOST=%~2"
shift
shift
goto :parse_args

:need_backend_port
if "%~2"=="" (
  echo [VulnHunter] %~1 needs a port number
  exit /b 1
)
set "VULNHUNTER_PORT=%~2"
shift
shift
goto :parse_args

:need_frontend_port
if "%~2"=="" (
  echo [VulnHunter] %~1 needs a port number
  exit /b 1
)
set "VULNHUNTER_FRONTEND_PORT=%~2"
shift
shift
goto :parse_args

:help
call :print_usage
exit /b 0

:usage
call :print_usage
exit /b 1

:print_usage
echo Usage: start.cmd [--reload] [--lan] [--host ADDR] [--backend-port N] [--frontend-port N]
echo   --reload           uvicorn --reload
echo   --lan              bind 0.0.0.0 ^(reachable on LAN^)
echo   --host ADDR        listen address ^(default 127.0.0.1, or VULNHUNTER_HOST^)
echo   --backend-port N   API port ^(default 16780, or VULNHUNTER_PORT^)
echo   --frontend-port N  UI port  ^(default 15173, or VULNHUNTER_FRONTEND_PORT^)
echo   aliases: --api-port / --ui-port
goto :eof

:args_done

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$bad=$false;" ^
  "foreach ($pair in @(@('VULNHUNTER_PORT',$env:VULNHUNTER_PORT), @('VULNHUNTER_FRONTEND_PORT',$env:VULNHUNTER_FRONTEND_PORT))) {" ^
  "  $n=0; if (-not [int]::TryParse($pair[1], [ref]$n) -or $n -lt 1 -or $n -gt 65535) {" ^
  "    Write-Host ('[VulnHunter] invalid {0}: {1}' -f $pair[0], $pair[1]); $bad=$true" ^
  "  }" ^
  "};" ^
  "if ($env:VULNHUNTER_PORT -eq $env:VULNHUNTER_FRONTEND_PORT) {" ^
  "  Write-Host '[VulnHunter] backend and frontend ports must differ'; $bad=$true" ^
  "};" ^
  "$h=[string]$env:VULNHUNTER_HOST;" ^
  "if ([string]::IsNullOrWhiteSpace($h) -or $h.StartsWith('-') -or $h -match '\s' -or $h.Length -gt 253) {" ^
  "  Write-Host ('[VulnHunter] invalid VULNHUNTER_HOST: {0}' -f $h); $bad=$true" ^
  "};" ^
  "if ($bad) { exit 1 }"
if errorlevel 1 exit /b 1

echo [VulnHunter] starting...

if not exist "%ROOT%backend\.venv\Scripts\python.exe" (
  echo [VulnHunter] creating backend venv...
  python -m venv "%ROOT%backend\.venv"
)

if not exist "%ROOT%backend\.venv\Scripts\uvicorn.exe" (
  echo [VulnHunter] installing backend deps...
  if not defined VULNHUNTER_PIP_INDEX_URL set "VULNHUNTER_PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple"
  call "%ROOT%backend\.venv\Scripts\pip.exe" install -r "%ROOT%backend\requirements.txt" -i "%VULNHUNTER_PIP_INDEX_URL%"
  if errorlevel 1 (
    echo [VulnHunter] pip install failed with %VULNHUNTER_PIP_INDEX_URL%, retrying with the default index...
    call "%ROOT%backend\.venv\Scripts\pip.exe" install -r "%ROOT%backend\requirements.txt"
  )
)

if not exist "%ROOT%frontend\node_modules" (
  echo [VulnHunter] installing frontend deps...
  pushd "%ROOT%frontend"
  call npm install --registry=https://registry.npmmirror.com
  popd
)

call "%ROOT%scripts\stop.cmd" --quiet

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "function Listening([int]$p) { [bool](Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue) };" ^
  "$bp=[int]$env:VULNHUNTER_PORT; $fp=[int]$env:VULNHUNTER_FRONTEND_PORT;" ^
  "$deadline=(Get-Date).AddSeconds(5);" ^
  "while ((Get-Date) -lt $deadline) { if (-not (Listening $bp) -and -not (Listening $fp)) { exit 0 }; Start-Sleep -Milliseconds 400 };" ^
  "if (Listening $bp) { Write-Host ('[VulnHunter] error: backend port {0} is still in use' -f $bp) };" ^
  "if (Listening $fp) { Write-Host ('[VulnHunter] error: frontend port {0} is still in use' -f $fp) };" ^
  "Write-Host '  Pick free ports: start.cmd --backend-port N --frontend-port N';" ^
  "exit 1"
if errorlevel 1 exit /b 1

(
  echo VULNHUNTER_PORT=%VULNHUNTER_PORT%
  echo VULNHUNTER_FRONTEND_PORT=%VULNHUNTER_FRONTEND_PORT%
  echo VULNHUNTER_HOST=%VULNHUNTER_HOST%
) > "%PIDDIR%\ports.env"

set "SHOW_HOST=%VULNHUNTER_HOST%"
if /I "%VULNHUNTER_HOST%"=="0.0.0.0" set "SHOW_HOST=127.0.0.1"
if /I "%VULNHUNTER_HOST%"=="::" set "SHOW_HOST=127.0.0.1"

if defined VULNHUNTER_RELOAD (
  echo [VulnHunter] backend  http://%SHOW_HOST%:%VULNHUNTER_PORT%  ^(reload^)
) else (
  echo [VulnHunter] backend  http://%SHOW_HOST%:%VULNHUNTER_PORT%
)
if /I "%VULNHUNTER_HOST%"=="0.0.0.0" echo [VulnHunter] listen   0.0.0.0 ^(LAN^)
if /I "%VULNHUNTER_HOST%"=="::" echo [VulnHunter] listen   :: ^(LAN^)
start "VulnHunter-Backend" /MIN "%ROOT%scripts\_run-backend-inner.cmd"

echo [VulnHunter] frontend http://%SHOW_HOST%:%VULNHUNTER_FRONTEND_PORT%
start "VulnHunter-Frontend" /MIN "%ROOT%scripts\_run-frontend-inner.cmd"

echo [VulnHunter] waiting for ports...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$bp=[int]$env:VULNHUNTER_PORT; $fp=[int]$env:VULNHUNTER_FRONTEND_PORT;" ^
  "$deadline = (Get-Date).AddSeconds(45);" ^
  "while ((Get-Date) -lt $deadline) {" ^
  "  $b = Get-NetTCPConnection -LocalPort $bp -State Listen -ErrorAction SilentlyContinue;" ^
  "  $f = Get-NetTCPConnection -LocalPort $fp -State Listen -ErrorAction SilentlyContinue;" ^
  "  if ($b -and $f) { exit 0 }; Start-Sleep -Milliseconds 500" ^
  "}; exit 1"
if errorlevel 1 (
  echo [VulnHunter] warn: ports not ready yet — check data\logs\backend.log / frontend.log
) else (
  echo [VulnHunter] ready.
)

echo.
echo   UI:   http://%SHOW_HOST%:%VULNHUNTER_FRONTEND_PORT%
echo   API:  http://%SHOW_HOST%:%VULNHUNTER_PORT%/docs
if /I "%VULNHUNTER_HOST%"=="0.0.0.0" goto :print_lan
if /I "%VULNHUNTER_HOST%"=="::" goto :print_lan
goto :after_lan
:print_lan
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$fp=$env:VULNHUNTER_FRONTEND_PORT; $bp=$env:VULNHUNTER_PORT;" ^
  "try {" ^
  "  Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |" ^
  "    Where-Object { $_.IPAddress -notmatch '^127\.' -and $_.IPAddress -notmatch '^169\.254\.' } |" ^
  "    Select-Object -ExpandProperty IPAddress -Unique |" ^
  "    ForEach-Object { Write-Host ('  LAN UI:  http://{0}:{1}' -f $_, $fp); Write-Host ('  LAN API: http://{0}:{1}/docs' -f $_, $bp) }" ^
  "} catch {}"
echo   Note: reachable on this network. Prefer VULNHUNTER_ACCESS_TOKEN.
:after_lan
echo   Stop: stop.cmd
echo   Dev:  start.cmd --reload
echo   Ports: start.cmd --backend-port N --frontend-port N
echo   LAN:   start.cmd --lan   ^(or --host 0.0.0.0^)
echo   Logs: data\logs\
echo.
endlocal
