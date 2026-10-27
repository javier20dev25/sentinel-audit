@echo off
setlocal
where node >nul 2>&1
if errorlevel 1 (
  echo Sentinel Audit requires Node.js 20 or newer on PATH.
  exit /b 1
)
node "%~dp0audit-runner.js" %*
