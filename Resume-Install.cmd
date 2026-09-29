@echo off
"%~dp0SelectiveTunnel.exe" --install --resume
if errorlevel 1 pause
