@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "COMPOSE=%~dp0compose.yml"
docker compose -f "%COMPOSE%" down
if errorlevel 1 (
  echo [VulnHunter] compose down failed.
  exit /b 1
)
echo [VulnHunter] Docker edition stopped.
endlocal
