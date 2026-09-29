#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module "$PSScriptRoot\Core.psm1" -Force
$root = Join-Path $env:ProgramData 'SelectiveTunnel'
$exe = Join-Path $PSScriptRoot 'bin\sing-box.exe'
$lock = $null
$engine = $null
$lastMaintenance = [DateTime]::MinValue
$nextUpdate = [DateTime]::UtcNow
$updateError = ''
function Stop-Engine {
    Stop-EngineMemory $script:engine
    $script:engine = $null
}
function Write-State($State, $Detail) {
    Write-JsonAtomic "$root\status.json" @{
        state=$State; detail=$Detail; updated_utc=[DateTime]::UtcNow.ToString('o');
        policy_version=$policy.version; update_error=$updateError;
        engine_pid=$(if ($engine -and -not $engine.Process.HasExited) {$engine.Process.Id} else {$null})
    }
}
try {
    $lock = [IO.File]::Open("$root\guard.lock",'OpenOrCreate','ReadWrite','None')
    $profile = Read-Connection
    $policy = Read-Json "$root\policy.json"
    Assert-Policy $policy
    Get-CimInstance Win32_Process -Filter "Name='sing-box.exe'" |
        Where-Object { $_.ExecutablePath -eq $exe } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    Set-Guards $policy
    while ($true) {
        try {
            $desired = Read-Json "$root\desired.json"
            if ($desired.mode -notin @('connected','blocked')) { throw 'Invalid desired state.' }
            if ($desired.mode -eq 'blocked') {
                Stop-Engine
                Write-State 'blocked' 'Selected domains blocked. Other traffic stays direct.'
                Start-Sleep -Seconds 2
                continue
            }
            if ([DateTime]::UtcNow - $lastMaintenance -gt [TimeSpan]::FromSeconds(30)) {
                Set-Guards $policy
                $lastMaintenance = [DateTime]::UtcNow
            }
            if (-not $engine -or $engine.Process.HasExited) {
                Stop-Engine
                # Re-read changed credentials only from the atomic encrypted connection.
                $profile = Read-Connection
                $policy = Read-Json "$root\policy.json"
                $config = New-EngineConfig $profile $policy $root
                Test-EngineConfig $config
                $engine = Start-EngineMemory $config $exe
                $config = $null
                Start-Sleep -Seconds 2
                if ($engine.Process.HasExited) { throw 'Proxy engine could not start. Check local ports and network configuration.' }
                Clear-DnsClientCache
            }
            Write-State 'running' 'Engine running. Verify egress checks proxy access and the external IP.'
            $refresh = Test-Path "$root\refresh.request"
            if ($refresh -or [DateTime]::UtcNow -ge $nextUpdate) {
                if ($refresh) { Remove-Item "$root\refresh.request" -Force }
                $nextUpdate = [DateTime]::UtcNow.AddHours(6)
                try {
                    if (-not $profile.policy_url) {
                        $updateError = 'No signed feed. DNS IPs refresh automatically; import domain rules locally.'
                    } else {
                        $candidate = Receive-Policy $profile $policy
                        if ($null -ne $candidate) {
                            Test-EngineConfig (New-EngineConfig $profile $candidate $root)
                            Stop-Engine
                            Set-Guards $candidate
                            Write-JsonAtomic "$root\policy.json" $candidate
                            $policy = $candidate
                        }
                        $updateError = ''
                    }
                } catch { $updateError = 'Rule update rejected or unavailable; previous policy retained.'; $nextUpdate = [DateTime]::UtcNow.AddMinutes(15) }
            }
        } catch {
            Stop-Engine
            Write-State 'error' 'Engine stopped safely. Check settings, local DNS port, Windows Firewall and routes.'
            Start-Sleep -Seconds 5
        }
        Start-Sleep -Seconds 2
    }
} catch {
    [IO.File]::WriteAllText("$root\guard-error.txt",'Supervisor startup failed. Check encrypted connection, installation and system network rules.')
    exit 1
} finally {
    Stop-Engine
    if ($lock) { $lock.Dispose() }
}
