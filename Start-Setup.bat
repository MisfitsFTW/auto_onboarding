@echo off
:: Batch script to launch the PowerShell onboarding script with admin rights
set "scriptPath=%~dp0Setup-PC.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%scriptPath%\"' -Verb RunAs"
pause
