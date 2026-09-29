#Requires -RunAsAdministrator
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\Core.psm1" -Force
Add-Type -AssemblyName System.Windows.Forms
$dialog=New-Object Windows.Forms.OpenFileDialog
$dialog.Filter='Domain policy (*.json)|*.json'
try {
    if ($dialog.ShowDialog() -ne 'OK') { return }
    if ((Get-Item -LiteralPath $dialog.FileName).Length -gt 65536) { throw 'Policy is too large.' }
    $root=Join-Path $env:ProgramData 'SelectiveTunnel'
    $candidate=Read-Json $dialog.FileName
    Assert-Policy $candidate
    $old=Read-Json "$root\policy.json"
    if ($candidate.version -le $old.version) { throw 'Increase the policy version before importing.' }
    $candidate.domains=@(@($old.domains)+@($candidate.domains) | Sort-Object -Unique)
    Test-EngineConfig (New-EngineConfig (Read-Connection) $candidate $root)
    & "$PSScriptRoot\Control.ps1" -Action Block
    Set-Guards $candidate
    Write-JsonAtomic "$root\policy.json" $candidate
    [Windows.Forms.MessageBox]::Show('Правила добавлены. Нажмите «Подключить». Ранее защищённые домены сохранены.','SelectiveTunnel') | Out-Null
} finally { $dialog.Dispose() }
