#Requires -RunAsAdministrator
param([Parameter(Mandatory=$true)][string]$ResultPath)
$ErrorActionPreference='Stop'
$root=Join-Path $env:ProgramData 'SelectiveTunnel'
$app=Join-Path $env:ProgramFiles 'SelectiveTunnel'
$report=[ordered]@{stage='validate';success=$false;message=''}
try {
    if ([IO.Path]::GetFullPath($PSScriptRoot) -ne [IO.Path]::GetFullPath($app)) {
        Copy-Item -LiteralPath "$PSScriptRoot\Core.psm1" -Destination "$app\Core.psm1" -Force
    }
    Import-Module "$app\Core.psm1" -Force
    $profile=Read-Connection
    $policy=Read-Json "$root\policy.json"
    Test-EngineConfig (New-EngineConfig $profile $policy $root)
    $profile=$null
    $report.stage='network-rules'
    Set-Guards $policy
    Clear-DnsClientCache
    $report.stage='startup-task'
    $ps="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $action=New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -ExecutionPolicy Bypass -File "'+"$app\Guard.ps1"+'"') -WorkingDirectory $app
    $trigger=New-ScheduledTaskTrigger -AtStartup
    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName 'SelectiveTunnel' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    $report.stage='shortcut'
    $shell=New-Object -ComObject WScript.Shell
    $linkPath=Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\SelectiveTunnel.lnk'
    $link=$shell.CreateShortcut($linkPath)
    $link.TargetPath=$ps
    $link.Arguments='-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+"$app\Gui.ps1"+'"'
    $link.WorkingDirectory=$app
    $link.Save()
    $bytes=[IO.File]::ReadAllBytes($linkPath); $bytes[0x15]=$bytes[0x15] -bor 0x20; [IO.File]::WriteAllBytes($linkPath,$bytes)
    $report.stage='start'
    Write-JsonAtomic "$root\desired.json" @{mode='connected'}
    Start-ScheduledTask -TaskName SelectiveTunnel
    $report.success=$true; $report.stage='complete'
} catch { $report.message=$_.Exception.Message; $report.stack=$_.ScriptStackTrace }
[IO.File]::WriteAllText($ResultPath,($report | ConvertTo-Json),[Text.UTF8Encoding]::new($false))
