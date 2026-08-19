@echo off
setlocal
cd /d "%~dp0.."
docker build -t vulnhunter/sandbox:latest docker/sandbox
if errorlevel 1 (
  echo 构建失败。请确认 Docker Desktop 已启动。
  exit /b 1
)
echo 已构建 vulnhunter/sandbox:latest
endlocal
