@echo off
:: Batch script to run the Follow Me printer setup script
set "scriptPath=%~dp0FollowMe.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%scriptPath%"
pause
