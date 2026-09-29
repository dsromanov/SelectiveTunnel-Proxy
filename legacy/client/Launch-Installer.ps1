param([switch]$Resume)
$ErrorActionPreference='Stop'
$installer=Join-Path $PSScriptRoot 'Install.ps1'
$exe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
# The elevated installer contains an interactive settings form.
$arguments='-NoProfile -NoExit -ExecutionPolicy Bypass -File "'+$installer+'"'
if ($Resume) { $arguments += ' -Resume' }
Start-Process -FilePath $exe -Verb RunAs -ArgumentList $arguments
