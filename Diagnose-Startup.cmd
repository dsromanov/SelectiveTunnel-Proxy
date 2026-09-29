@echo off
"%~dp0SelectiveTunnel.exe" --diagnose-startup
if errorlevel 1 pause
