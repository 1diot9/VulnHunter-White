@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "ROOT=%~dp0"
set "PIDDIR=%ROOT%data\run"
set "LOGDIR=%ROOT%data\logs"
if not exist "%PIDDIR%" mkdir "%PIDDIR%"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"

set "VULNHUNTER_RELOAD="
:parse_args
if "%~1"=="" goto :args_done
if /I "%~1"=="--reload" (
  set "VULNHUNTER_RELOAD=1"
) else (
  echo [VulnHunter] unknown option: %~1
  echo Usage: start.cmd [--reload]
  exit /b 1
)
shift
goto :parse_args
:args_done

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

if defined VULNHUNTER_RELOAD (
  echo [VulnHunter] backend  http://127.0.0.1:8000  ^(reload^)
) else (
  echo [VulnHunter] backend  http://127.0.0.1:8000
)
start "VulnHunter-Backend" /MIN "%ROOT%scripts\_run-backend-inner.cmd"

echo [VulnHunter] frontend http://127.0.0.1:5173
start "VulnHunter-Frontend" /MIN "%ROOT%scripts\_run-frontend-inner.cmd"

echo [VulnHunter] waiting for ports...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$deadline = (Get-Date).AddSeconds(45);" ^
  "while ((Get-Date) -lt $deadline) {" ^
  "  $b = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue;" ^
  "  $f = Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue;" ^
  "  if ($b -and $f) { exit 0 }; Start-Sleep -Milliseconds 500" ^
  "}; exit 1"
if errorlevel 1 (
  echo [VulnHunter] warn: ports not ready yet — check data\logs\backend.log / frontend.log
) else (
  echo [VulnHunter] ready.
)

echo.
echo   UI:   http://127.0.0.1:5173
echo   API:  http://127.0.0.1:8000/docs
echo   Stop: stop.cmd
echo   Dev:  start.cmd --reload
echo   Logs: data\logs\
echo.
endlocal
