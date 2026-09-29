param([switch]$Elevated)
$ErrorActionPreference='Stop'
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    if ($Elevated) { throw 'Administrator rights required.' }
    Start-Process "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -WindowStyle Hidden -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "'+$PSCommandPath+'" -Elevated')
    exit
}
$app=Join-Path $env:ProgramFiles 'SelectiveTunnel'
$root=Join-Path $env:ProgramData 'SelectiveTunnel'
$report=Join-Path ([Environment]::GetFolderPath('Desktop')) 'SelectiveTunnel-Update.txt'
$lines=New-Object 'Collections.Generic.List[string]'
$restart=$false; $changed=$false; $success=$false; $backup=$null
$files=@('Core.psm1','Settings.psm1','Guard.ps1','Control.ps1','Gui.ps1','Edit-Connection.ps1','Import-Rules.ps1')
try {
    foreach ($directory in @($app,$root)) {
        $entries=@(Get-Item -LiteralPath $directory) + @(Get-ChildItem -LiteralPath $directory -Recurse -Force)
        if ($entries | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) { throw 'Unexpected reparse point. Update cancelled.' }
    }
    if ([IO.Path]::GetFullPath($PSScriptRoot) -eq [IO.Path]::GetFullPath($app)) { throw 'Run Update.cmd from the extracted release folder.' }
    foreach ($file in $files) {
        if (-not (Test-Path "$app\$file") -or -not (Test-Path "$PSScriptRoot\$file")) { throw "Required file missing: $file" }
    }
    Import-Module "$PSScriptRoot\Core.psm1" -Force
    $profile=Read-Connection
    $policy=Read-Json "$root\policy.json"
    $desired=Read-Json "$root\desired.json"
    if ($desired.mode -notin @('connected','blocked')) { throw 'Invalid desired mode.' }
    Get-ScheduledTask -TaskName SelectiveTunnel | Out-Null
    $backup=Join-Path $root ('updates\'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $backup -Force | Out-Null
    $hadFlag=Test-Path "$root\tun-ipv4-only.flag"
    [IO.File]::WriteAllText("$backup\tun-ipv4-only.flag",'1')
    Test-EngineConfig (New-EngineConfig $profile $policy $backup) "$app\bin\sing-box.exe"
    $profile=$null
    foreach ($file in $files) { Copy-Item -LiteralPath "$app\$file" -Destination "$backup\$file" }
    $restart=$true
    Stop-ScheduledTask -TaskName SelectiveTunnel
    for ($i=0;$i -lt 20;$i++) {
        if ((Get-ScheduledTask -TaskName SelectiveTunnel).State -ne 'Running') { break }
        Start-Sleep -Milliseconds 500
    }
    if ((Get-ScheduledTask -TaskName SelectiveTunnel).State -eq 'Running') { throw 'Supervisor did not stop. Update cancelled.' }
    Get-CimInstance Win32_Process -Filter "Name='sing-box.exe'" |
        Where-Object { $_.ExecutablePath -eq "$app\bin\sing-box.exe" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    $changed=$true
    foreach ($file in $files) { Copy-Item -LiteralPath "$PSScriptRoot\$file" -Destination "$app\$file" -Force }
    [IO.File]::WriteAllText("$root\tun-ipv4-only.flag",'1')
    Clear-DnsClientCache
    Start-ScheduledTask -TaskName SelectiveTunnel
    $started=[DateTime]::UtcNow
    for ($i=0;$i -lt 25;$i++) {
        Start-Sleep -Seconds 1
        $s=Read-Json "$root\status.json"
        $expected=if ($desired.mode -eq 'blocked') { 'blocked' } else { 'running' }
        if ([DateTime]::Parse($s.updated_utc).ToUniversalTime() -ge $started -and $s.state -eq $expected) { $success=$true; break }
    }
    if (-not $success) { throw 'Updated supervisor did not become ready.' }
    $lines.Add('SelectiveTunnel 1.1.0 updated successfully. Proxy credentials, domain rules and connection mode preserved.')
    $lines.Add('IPv4 tunnel mode enabled. Global Windows IPv6 settings unchanged.')
    if ($desired.mode -eq 'connected') {
        try { $lines.Add((& "$app\Control.ps1" -Action Verify | Out-String)) }
        catch { $lines.Add('Client started, but IP verification failed. Run Diagnose.cmd.') }
    } else { $lines.Add('Client remains blocked as before the update. Press Connect when ready.') }
} catch {
    $lines.Add('Update failed: '+$_.Exception.Message)
    if ($changed -and -not $success) {
        try {
            Stop-ScheduledTask -TaskName SelectiveTunnel
            for ($i=0;$i -lt 20;$i++) {
                if ((Get-ScheduledTask -TaskName SelectiveTunnel).State -ne 'Running') { break }
                Start-Sleep -Milliseconds 500
            }
            if ((Get-ScheduledTask -TaskName SelectiveTunnel).State -eq 'Running') { throw 'Supervisor still running; rollback files retained for recovery.' }
            Get-CimInstance Win32_Process -Filter "Name='sing-box.exe'" |
                Where-Object { $_.ExecutablePath -eq "$app\bin\sing-box.exe" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
            foreach ($file in $files) { Copy-Item -LiteralPath "$backup\$file" -Destination "$app\$file" -Force }
            if (-not $hadFlag) { Remove-Item -LiteralPath "$root\tun-ipv4-only.flag" -Force -ErrorAction SilentlyContinue }
            $lines.Add('Previous program files restored.')
        } catch { $lines.Add('Rollback incomplete. Backup retained in the protected ProgramData/SelectiveTunnel/updates directory.') }
    }
} finally {
    if ($restart -and -not $success) {
        try { Start-ScheduledTask -TaskName SelectiveTunnel }
        catch { $lines.Add('Supervisor restart failed. Open the app and press Connect.') }
    }
    [IO.File]::WriteAllLines($report,$lines,[Text.UTF8Encoding]::new($true))
    Start-Process notepad.exe -ArgumentList ('"'+$report+'"')
}
