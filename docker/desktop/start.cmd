@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

REM Repo root = docker\desktop\..\..
for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"
set "DATA=%ROOT%\data"
set "COMPOSE=%~dp0compose.yml"

if not exist "%DATA%" mkdir "%DATA%"

where docker >nul 2>&1
if errorlevel 1 (
  echo [VulnHunter] docker not found on PATH. Install Docker Desktop and retry.
  exit /b 1
)

docker version >nul 2>&1
if errorlevel 1 (
  echo [VulnHunter] Docker engine not reachable. Start Docker Desktop ^(WSL2 backend^) and retry.
  exit /b 1
)

if not defined VULNHUNTER_PORT set "VULNHUNTER_PORT=16788"
set "VULNHUNTER_HOST_DATA=%DATA%"

echo [VulnHunter] Docker Desktop edition
echo [VulnHunter] host data: %VULNHUNTER_HOST_DATA%
echo [VulnHunter] UI/API:    http://127.0.0.1:%VULNHUNTER_PORT%
echo [VulnHunter] first start may build sandbox images ^(several minutes^).
echo.

docker compose -f "%COMPOSE%" up --build -d
if errorlevel 1 (
  echo [VulnHunter] compose up failed.
  exit /b 1
)

echo.
echo [VulnHunter] started. Open http://127.0.0.1:%VULNHUNTER_PORT%
echo [VulnHunter] logs: docker compose -f "%COMPOSE%" logs -f
echo [VulnHunter] stop:  "%~dp0stop.cmd"
endlocal
