@echo off
setlocal
title Workstation Monitor Setup
echo Workstation Monitor Setup
echo Extract the whole ZIP before installing. An administrator approval will be requested.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0agent\windows\setup.ps1"
set "MONITOR_SETUP_RESULT=%ERRORLEVEL%"
if not "%MONITOR_SETUP_RESULT%"=="0" (
  echo.
  echo Setup did not complete. Check the message above or ask your administrator.
  pause
)
exit /b %MONITOR_SETUP_RESULT%
