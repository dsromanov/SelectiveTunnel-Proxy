#Requires -RunAsAdministrator
param([ValidateSet('Connect','Block','Refresh','Status','Verify')][string]$Action = 'Status')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module "$PSScriptRoot\Core.psm1" -Force
$root = Join-Path $env:ProgramData 'SelectiveTunnel'
switch ($Action) {
    'Connect' {
        Set-Guards (Read-Json "$root\policy.json")
        Write-JsonAtomic "$root\desired.json" @{mode='connected'}
        Start-ScheduledTask -TaskName 'SelectiveTunnel'
    }
    'Block' {
        # Reapply barriers before terminating the engine, including if the guard is stuck.
        Set-Guards (Read-Json "$root\policy.json")
        Write-JsonAtomic "$root\desired.json" @{mode='blocked'}
        $exe = Join-Path $PSScriptRoot 'bin\sing-box.exe'
        Get-CimInstance Win32_Process -Filter "Name='sing-box.exe'" |
            Where-Object { $_.ExecutablePath -eq $exe } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
        Clear-DnsClientCache
    }
    'Refresh' { [IO.File]::WriteAllText("$root\refresh.request",'1') }
    'Status' { if (Test-Path "$root\status.json") { Get-Content "$root\status.json" } else { 'No supervisor status yet.' } }
    'Verify' {
        $profile = Read-Connection
        $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
        $result = & $curl --silent --show-error --fail --max-time 12 --noproxy 'no-bypass.invalid' --socks5-hostname 127.0.0.1:17891 https://api.ipify.org 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Tunnel probe failed: $result" }
        $observed = ("$result").Trim()
        $parsed=$null
        if (-not [Net.IPAddress]::TryParse($observed,[ref]$parsed)) { throw 'Proxy probe returned an invalid IP.' }
        if ($profile.expected_exit_ip -and $observed -ne $profile.expected_exit_ip) { throw "Unexpected proxy egress: $observed; expected $($profile.expected_exit_ip)." }
        "Proxy egress: $observed"
        $direct = & $curl --silent --show-error --fail --max-time 12 --noproxy '*' https://api.ipify.org 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Direct probe failed: $direct" }
        "Ordinary direct egress: $direct"
    }
}
