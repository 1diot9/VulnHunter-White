@echo off
setlocal
cd /d "%~dp0.."
docker build -t vulnhunter/integration-sandbox:latest docker/integration-sandbox
if errorlevel 1 (
  echo 构建失败。请确认 Docker Desktop 已启动。
  exit /b 1
)
echo 已构建 vulnhunter/integration-sandbox:latest
endlocal
