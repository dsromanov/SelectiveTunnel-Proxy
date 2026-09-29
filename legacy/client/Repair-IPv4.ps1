param([switch]$Elevated)
$ErrorActionPreference='Stop'
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    if ($Elevated) { throw 'Administrator rights required.' }
    Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "'+$PSCommandPath+'" -Elevated')
    exit
}
$app=Join-Path $env:ProgramFiles 'SelectiveTunnel'
$root=Join-Path $env:ProgramData 'SelectiveTunnel'
$report=Join-Path ([Environment]::GetFolderPath('Desktop')) 'SelectiveTunnel-Repair.txt'
$lines=New-Object 'Collections.Generic.List[string]'
$restart=$false
try {
    Import-Module "$PSScriptRoot\Core.psm1" -Force
    $profile=Read-Connection
    $policy=Read-Json "$root\policy.json"
    Get-ScheduledTask -TaskName SelectiveTunnel | Out-Null
    # Validate the exact IPv4 candidate before stopping the installed client.
    $scratch=Join-Path $env:TEMP ('SelectiveTunnel-IPv4-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $scratch | Out-Null
    [IO.File]::WriteAllText((Join-Path $scratch 'tun-ipv4-only.flag'),'1')
    Test-EngineConfig (New-EngineConfig $profile $policy $scratch) "$app\bin\sing-box.exe"
    $profile=$null
    $restart=$true
    Stop-ScheduledTask -TaskName SelectiveTunnel
    for ($i=0;$i -lt 20;$i++) {
        if ((Get-ScheduledTask -TaskName SelectiveTunnel).State -ne 'Running') { break }
        Start-Sleep -Milliseconds 500
    }
    if ((Get-ScheduledTask -TaskName SelectiveTunnel).State -eq 'Running') { throw 'Supervisor could not stop. No update applied.' }
    Get-CimInstance Win32_Process -Filter "Name='sing-box.exe'" |
        Where-Object { $_.ExecutablePath -eq "$app\bin\sing-box.exe" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    if (-not (Test-Path "$app\Core.before-ipv4.psm1")) { Copy-Item "$app\Core.psm1" "$app\Core.before-ipv4.psm1" }
    Copy-Item "$PSScriptRoot\Core.psm1" "$app\Core.psm1" -Force
    [IO.File]::WriteAllText("$root\tun-ipv4-only.flag",'1')
    Write-JsonAtomic "$root\desired.json" @{mode='connected'}
    Clear-DnsClientCache
    $lines.Add('IPv4 tunnel compatibility enabled. Credentials preserved. System IPv6 unchanged.')
} catch { $lines.Add('Repair failed: '+$_.Exception.Message) }
finally {
    if ($restart) {
        try {
            Start-ScheduledTask -TaskName SelectiveTunnel
            Start-Sleep -Seconds 8
            $s=Read-Json "$root\status.json"
            $lines.Add("Supervisor: $($s.state); updated=$($s.updated_utc)")
            if ($s.state -eq 'running') {
                try { $lines.Add((& "$app\Control.ps1" -Action Verify | Out-String)) }
                catch { $lines.Add('IP verification failed. Run Diagnose-Startup.cmd and send its report.') }
            } else { $lines.Add('Run Diagnose-Startup.cmd and send its report if the error persists.') }
        } catch { $lines.Add('Restart failed. Press Connect in SelectiveTunnel.') }
    }
    [IO.File]::WriteAllLines($report,$lines,[Text.UTF8Encoding]::new($true))
    Start-Process notepad.exe -ArgumentList ('"'+$report+'"')
}
