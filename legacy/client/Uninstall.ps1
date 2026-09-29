#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module "$PSScriptRoot\Core.psm1" -Force
$root = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'SelectiveTunnel'))
$app = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'SelectiveTunnel'))
# Only these two fixed children may be recursively deleted; refuse reparse points.
foreach ($pair in @(@($root,$env:ProgramData),@($app,$env:ProgramFiles))) {
    if ([IO.Path]::GetDirectoryName($pair[0]) -ne [IO.Path]::GetFullPath($pair[1]) -or [IO.Path]::GetFileName($pair[0]) -ne 'SelectiveTunnel') { throw 'Unsafe uninstall path.' }
    if (Test-Path $pair[0]) {
        $items = @((Get-Item -LiteralPath $pair[0])) + @(Get-ChildItem -LiteralPath $pair[0] -Recurse -Force)
        if ($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) { throw 'Refusing to remove a directory containing reparse points.' }
    }
}
if (Test-Path "$root\desired.json") { Write-JsonAtomic "$root\desired.json" @{mode='blocked'} }
$task = Get-ScheduledTask -TaskName 'SelectiveTunnel' -ErrorAction SilentlyContinue
if ($task) { Stop-ScheduledTask -TaskName 'SelectiveTunnel'; Unregister-ScheduledTask -TaskName 'SelectiveTunnel' -Confirm:$false }
$exe = Join-Path $app 'bin\sing-box.exe'
Get-CimInstance Win32_Process -Filter "Name='sing-box.exe'" | Where-Object { $_.ExecutablePath -eq $exe } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Remove-Guards
$link = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\SelectiveTunnel.lnk'
if (Test-Path $link) { Remove-Item -LiteralPath $link -Force }
foreach ($path in @($app,$root)) { if (Test-Path $path) { Remove-Item -LiteralPath $path -Recurse -Force } }
'Uninstalled. Selected services now use direct access. Restart browsers to discard cached fake addresses.'
