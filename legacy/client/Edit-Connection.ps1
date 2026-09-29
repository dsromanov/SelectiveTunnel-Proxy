#Requires -RunAsAdministrator
Import-Module "$PSScriptRoot\Core.psm1" -Force
Import-Module "$PSScriptRoot\Settings.psm1" -Force
$ErrorActionPreference='Stop'
$current=Read-Connection
$changed=Show-ProxySettings $current
if ($null -ne $changed) {
    $root=Join-Path $env:ProgramData 'SelectiveTunnel'
    Test-EngineConfig (New-EngineConfig $changed (Read-Json "$root\policy.json") $root)
    & "$PSScriptRoot\Control.ps1" -Action Block
    Save-Connection $changed
    [Windows.Forms.MessageBox]::Show('Настройки сохранены. Нажмите «Подключить», чтобы запустить прокси.','SelectiveTunnel') | Out-Null
}
$current=$null; $changed=$null
