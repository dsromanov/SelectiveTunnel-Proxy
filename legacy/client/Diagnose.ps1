param([switch]$Elevated,[string]$OutputPath)
$ErrorActionPreference='Stop'
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin -and -not $Elevated) {
    $arguments='-NoProfile -ExecutionPolicy Bypass -File "'+$PSCommandPath+'" -Elevated'
    Start-Process "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -WindowStyle Hidden -ArgumentList $arguments
    exit
}
if (-not $OutputPath) { $OutputPath=Join-Path ([Environment]::GetFolderPath('Desktop')) 'SelectiveTunnel-Diagnostics.txt' }
$app=Join-Path $env:ProgramFiles 'SelectiveTunnel'
$root=Join-Path $env:ProgramData 'SelectiveTunnel'
$lines=New-Object 'Collections.Generic.List[string]'
function Line($Text) { $lines.Add([string]$Text) }
function Section($Name,[scriptblock]$Action) {
    Line "`r`n[$Name]"
    try { & $Action } catch { Line ('CHECK_FAILED: '+$_.Exception.GetType().Name) }
}
Line 'SelectiveTunnel diagnostics - read only; no passwords, profile contents or process command lines included.'
Line ([DateTime]::UtcNow.ToString('o'))
Line "Administrator: $admin"
Section 'Windows' {
    $os=Get-CimInstance Win32_OperatingSystem
    Line "$($os.Caption); version=$($os.Version); architecture=$($os.OSArchitecture)"
}
Section 'Installed files' {
    foreach ($name in @('Core.psm1','Guard.ps1','bin\sing-box.exe','bin\wintun.dll')) {
        $path=Join-Path $app $name
        if (Test-Path -LiteralPath $path) { Line "$name : present; SHA256=$((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash)" }
        else { Line "$name : MISSING" }
    }
}
Section 'Supervisor' {
    $s=Get-Content "$root\status.json" -Raw | ConvertFrom-Json
    Line "State=$($s.state); updated=$($s.updated_utc); engine_pid=$($s.engine_pid); policy_version=$($s.policy_version)"
    $task=Get-ScheduledTask -TaskName SelectiveTunnel
    $info=$task | Get-ScheduledTaskInfo
    Line "Task=$($task.State); last_result=$($info.LastTaskResult)"
}
Section 'Windows Firewall' {
    Get-NetFirewallProfile | ForEach-Object { Line "$($_.Name): enabled=$($_.Enabled)" }
    Line "Owned rules: $(@(Get-NetFirewallRule -Group SelectiveTunnel -ErrorAction SilentlyContinue).Count)"
}
Section 'Local port owners' {
    $listeners=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object LocalPort -in @(53,17891))
    $listeners+=@(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object LocalPort -eq 53)
    foreach ($item in $listeners) {
        $owner=Get-Process -Id $item.OwningProcess -ErrorAction SilentlyContinue
        Line "$($item.LocalAddress):$($item.LocalPort); pid=$($item.OwningProcess); process=$($owner.ProcessName)"
    }
    if (-not $listeners.Count) { Line 'No listeners on 53/17891.' }
}
Section 'Adapters' {
    Get-NetAdapter | ForEach-Object { Line "$($_.Name): status=$($_.Status); interface=$($_.ifIndex)" }
}
Section 'Selective DNS and routes' {
    $nrpt=@(Get-DnsClientNrptRule)
    Line "Owned NRPT rules: $(@($nrpt | Where-Object Comment -eq SelectiveTunnel).Count)"
    Line "Other NRPT rules: $(@($nrpt | Where-Object Comment -ne SelectiveTunnel).Count)"
    Get-NetRoute | Where-Object { $_.DestinationPrefix -match '^(198\.(18|19)\.|fd71:5e1e:c710)' } |
        ForEach-Object { Line "$($_.DestinationPrefix): interface=$($_.InterfaceIndex); metric=$($_.RouteMetric)" }
}
Section 'Encrypted profile and engine config' {
    Import-Module "$app\Core.psm1" -Force
    $profile=$null
    try { $profile=Read-Connection; Line 'Profile decrypt/validation: OK' }
    catch { Line 'Profile decrypt/validation: FAILED. Enter proxy credentials in Settings on THIS PC; do not copy connection.dpapi between PCs.' }
    if ($null -ne $profile) {
        try {
            $policy=Read-Json "$root\policy.json"
            Test-EngineConfig (New-EngineConfig $profile $policy $root)
            Line 'Engine config check: OK'
        } catch { Line 'Engine config check: FAILED (raw error withheld to protect credentials).' }
        finally { $profile=$null; $policy=$null }
    }
}
[IO.File]::WriteAllLines($OutputPath,$lines,[Text.UTF8Encoding]::new($true))
if ($Elevated) { Start-Process notepad.exe -ArgumentList ('"'+$OutputPath+'"') }
else { Write-Output $OutputPath }
