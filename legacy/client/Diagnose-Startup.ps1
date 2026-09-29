param([switch]$Elevated)
$ErrorActionPreference='Stop'
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    if ($Elevated) { throw 'Administrator rights are required.' }
    Start-Process "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -WindowStyle Hidden -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "'+$PSCommandPath+'" -Elevated')
    exit
}
$app=Join-Path $env:ProgramFiles 'SelectiveTunnel'
$root=Join-Path $env:ProgramData 'SelectiveTunnel'
$exe=Join-Path $app 'bin\sing-box.exe'
$output=Join-Path ([Environment]::GetFolderPath('Desktop')) 'SelectiveTunnel-Startup.txt'
$lines=New-Object 'Collections.Generic.List[string]'
$profile=$null; $handle=$null; $restart=$false
$lines.Add('SelectiveTunnel startup probe '+[DateTime]::UtcNow.ToString('o'))
try {
    Import-Module "$app\Core.psm1" -Force
    $profile=Read-Connection
    $policy=Read-Json "$root\policy.json"
    $config=New-EngineConfig $profile $policy $root
    Test-EngineConfig $config
    $lines.Add('Configuration check: OK')
    $task=Get-ScheduledTask -TaskName SelectiveTunnel
    if ($task.State -ne 'Running') { throw 'Supervisor is not running; use Connect before running this probe.' }
    $restart=$true
    Stop-ScheduledTask -TaskName SelectiveTunnel
    for ($i=0;$i -lt 15;$i++) {
        if ((Get-ScheduledTask -TaskName SelectiveTunnel).State -ne 'Running') { break }
        Start-Sleep -Milliseconds 500
    }
    if ((Get-ScheduledTask -TaskName SelectiveTunnel).State -eq 'Running') { throw 'Supervisor did not stop; probe cancelled.' }
    Get-CimInstance Win32_Process -Filter "Name='sing-box.exe'" |
        Where-Object { $_.ExecutablePath -eq $exe } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    Start-Sleep -Seconds 2
    # Errors are held only in memory, then credentials are removed before saving.
    $config.log=@{level='error';timestamp=$false}
    $handle=Start-EngineMemory $config $exe
    $config=$null
    Start-Sleep -Seconds 6
    if ($handle.Process.HasExited) { $lines.Add('Engine exited during startup. Exit code: '+$handle.Process.ExitCode) }
    else { $lines.Add('Engine stayed running for 6 seconds. Startup works in the administrator probe; SYSTEM supervisor may fail at a different stage.') }
} catch { $lines.Add('Probe exception: '+$_.Exception.Message) }
finally {
    if ($null -ne $handle) {
        try {
            if (-not $handle.Process.HasExited) { $handle.Process.Kill() }
            if ($handle.Process.WaitForExit(5000)) {
                if ($handle.Errors.Wait(3000)) { $lines.Add('Engine stderr: '+$handle.Errors.Result) }
                if ($handle.Output.Wait(3000)) { $lines.Add('Engine stdout: '+$handle.Output.Result) }
            }
            $handle.Process.Dispose()
        } catch { $lines.Add('Probe process cleanup failed; check the client status.') }
    }
    if ($restart) {
        try { Start-ScheduledTask -TaskName SelectiveTunnel; $lines.Add('Supervisor restart requested.'); Start-Sleep -Seconds 5 }
        catch { $lines.Add('Supervisor restart FAILED. Press Connect in the application.') }
    }
    try {
        $s=Get-Content "$root\status.json" -Raw | ConvertFrom-Json
        $lines.Add("Supervisor state: $($s.state); updated=$($s.updated_utc)")
    } catch { $lines.Add('Supervisor status unavailable.') }
    $text=$lines -join "`r`n"
    if ($null -ne $profile) {
        foreach ($property in $profile.PSObject.Properties) {
            if ($property.Name -in @('username','password','policy_url','policy_public_key')) {
                $secret=[string]$property.Value
                if ($secret) {
                    $text=$text.Replace($secret,'[REDACTED]').Replace([Uri]::EscapeDataString($secret),'[REDACTED]')
                    $escaped=ConvertTo-Json -InputObject $secret -Compress
                    if ($escaped.Length -gt 2) { $text=$text.Replace($escaped.Substring(1,$escaped.Length-2),'[REDACTED]') }
                }
            }
        }
    }
    $text=[regex]::Replace($text,'\x1B\[[0-9;]*[A-Za-z]','')
    [IO.File]::WriteAllText($output,$text,[Text.UTF8Encoding]::new($true))
    $profile=$null
    Start-Process notepad.exe -ArgumentList ('"'+$output+'"')
}
