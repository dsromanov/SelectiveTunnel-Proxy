@echo off
"%~dp0SelectiveTunnel.exe" --diagnose
if errorlevel 1 pause
