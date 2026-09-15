@echo off
setlocal
cd /d "%~dp0.."
docker pull returntocorp/semgrep:latest
if errorlevel 1 (
  echo 拉取失败。请确认 Docker Desktop 已启动，且能访问镜像仓库。
  exit /b 1
)
echo 已拉取 returntocorp/semgrep:latest
endlocal
