#Requires -RunAsAdministrator
param([string]$Policy = "$PSScriptRoot\..\policy\domains.json", [switch]$Resume)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module "$PSScriptRoot\Core.psm1" -Force
Import-Module "$PSScriptRoot\Settings.psm1" -Force
$root = Join-Path $env:ProgramData 'SelectiveTunnel'
$app = Join-Path $env:ProgramFiles 'SelectiveTunnel'
if (-not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw 'Use 64-bit Windows PowerShell on x64 Windows 10/11.' }
if ((Test-Path $root) -or (Test-Path $app)) {
    if (-not $Resume) { throw 'Partial/previous installation found. Use Resume-Install.cmd for a download-only interruption.' }
    # Resume only an interrupted dependency download. Never overwrite a configured client.
    if ((Test-Path "$root\connection.dpapi") -or (Test-Path "$root\policy.json") -or
        (Get-ScheduledTask -TaskName SelectiveTunnel -ErrorAction SilentlyContinue)) {
        throw 'A configured client already exists. Resume refuses to overwrite it.'
    }
    foreach ($directory in @($app,$root)) {
        if (Test-Path -LiteralPath $directory) {
            $entries=@(Get-Item -LiteralPath $directory) + @(Get-ChildItem -LiteralPath $directory -Recurse -Force)
            if ($entries | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) { throw 'Unexpected reparse point in partial installation.' }
        }
    }
    if (@(Get-ChildItem -LiteralPath $app -Recurse -File -ErrorAction SilentlyContinue).Count) { throw 'Application files already exist; inspect the earlier installation error first.' }
}
$rules = Read-Json $Policy
Assert-Policy $rules
if (@($rules.cidrs).Count) { throw 'Proxy edition requires an empty cidrs list.' }
if (@(Get-DnsClientNrptRule).Count) { throw 'Existing NRPT policy detected. Resolve policy conflicts before installing.' }
if ((Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue) -or (Get-NetTCPConnection -LocalPort 53 -State Listen -ErrorAction SilentlyContinue)) {
    throw 'Port 53 is already in use. Local DNS software must be reconfigured first.'
}
if (Get-NetTCPConnection -LocalPort 17891 -State Listen -ErrorAction SilentlyContinue) { throw 'Diagnostic port 17891 is already in use.' }
foreach ($prefix in @('198.18.0.0/15','198.18.0.0/16','198.19.0.0/16','fd71:5e1e:c710::/48','fd71:5e1e:c710::/49','fd71:5e1e:c710:8000::/49')) {
    if (Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue) { throw "Reserved address range already has a route: $prefix" }
}
function Protect-Directory($Path) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    & "$env:SystemRoot\System32\icacls.exe" $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to restrict directory permissions.' }
}
function Get-VerifiedArchive($Url,$Hash,$Target,[string]$Bundled='') {
    if ((Test-Path -LiteralPath $Target) -and (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash -eq $Hash) { return }
    if ($Bundled -and (Test-Path -LiteralPath $Bundled)) {
        if ((Get-FileHash -LiteralPath $Bundled -Algorithm SHA256).Hash -ne $Hash) { throw 'Bundled dependency SHA256 mismatch.' }
        Copy-Item -LiteralPath $Bundled -Destination $Target -Force
        return
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $part="$Target.part"
    for ($attempt=1;$attempt -le 3;$attempt++) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $part -TimeoutSec 180
            if ((Get-FileHash -LiteralPath $part -Algorithm SHA256).Hash -ne $Hash) { throw 'Downloaded dependency SHA256 mismatch.' }
            Move-Item -LiteralPath $part -Destination $Target -Force
            return
        } catch {
            if ($attempt -eq 3) { throw "Dependency download failed. Retry with Resume-Install.cmd. File: $([IO.Path]::GetFileName($Target))" }
            Start-Sleep -Seconds 2
        }
    }
}
$committed = $false
try {
    Protect-Directory $root; Protect-Directory $app
    New-Item -ItemType Directory "$app\bin","$root\download" -Force | Out-Null
    Get-VerifiedArchive 'https://github.com/SagerNet/sing-box/releases/download/v1.14.0/sing-box-1.14.0-windows-amd64.zip' '3FFB56267DA14E287BE48BD10CF7E6505260125BAD940B75101FBB4D5D58E5D6' "$root\download\engine.zip" "$PSScriptRoot\..\dependencies\sing-box-1.14.0-windows-amd64.zip"
    Get-VerifiedArchive 'https://www.wintun.net/builds/wintun-0.14.1.zip' '07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51' "$root\download\wintun.zip" "$PSScriptRoot\..\dependencies\wintun-0.14.1.zip"
    $p = Show-ProxySettings
    if ($null -eq $p) { 'Setup cancelled. Cached downloads retained; use Resume-Install.cmd to continue.'; return }
    Expand-Archive "$root\download\engine.zip" "$root\download\engine" -Force
    Expand-Archive "$root\download\wintun.zip" "$root\download\wintun" -Force
    Copy-Item "$root\download\engine\sing-box-1.14.0-windows-amd64\sing-box.exe" "$app\bin\sing-box.exe"
    Copy-Item "$root\download\engine\sing-box-1.14.0-windows-amd64\LICENSE" "$app\bin\sing-box-LICENSE"
    Copy-Item "$root\download\wintun\wintun\bin\amd64\wintun.dll" "$app\bin\wintun.dll"
    Copy-Item "$root\download\wintun\wintun\LICENSE.txt" "$app\bin\wintun-LICENSE.txt"
    Copy-Item "$PSScriptRoot\*.ps1","$PSScriptRoot\*.psm1" $app
    Save-Connection $p
    Write-JsonAtomic "$root\policy.json" $rules
    Write-JsonAtomic "$root\desired.json" @{mode='connected'}
    # The proven compatibility mode avoids IPv6 adapter initialization failures.
    [IO.File]::WriteAllText("$root\tun-ipv4-only.flag",'1')
    Test-EngineConfig (New-EngineConfig $p $rules $root)
    $p=$null
    Set-Guards $rules
    Clear-DnsClientCache
    $powershell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $action = New-ScheduledTaskAction -Execute $powershell -Argument ('-NoProfile -ExecutionPolicy Bypass -File "'+"$app\Guard.ps1"+'"') -WorkingDirectory $app
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName 'SelectiveTunnel' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Selective authenticated proxy; persistent guards remain when stopped.' | Out-Null
    # Shortcut explicitly requests elevation. All writable control files are admin-only.
    $shell = New-Object -ComObject WScript.Shell
    $linkPath = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\SelectiveTunnel.lnk'
    $link = $shell.CreateShortcut($linkPath)
    $link.TargetPath = $powershell
    $link.Arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+"$app\Gui.ps1"+'"'
    $link.WorkingDirectory = $app
    $link.Save()
    $bytes = [IO.File]::ReadAllBytes($linkPath); $bytes[0x15] = $bytes[0x15] -bor 0x20; [IO.File]::WriteAllBytes($linkPath,$bytes)
    Start-ScheduledTask -TaskName 'SelectiveTunnel'
    $committed = $true
    'Installed. Reboot before opening browsers and service apps to clear old connections and app DNS caches.'
    'Then open SelectiveTunnel from Start and run Verify egress.'
} finally {
    if (-not $committed) {
        # Keep the directory, profile and guards for diagnosis; never silently fail open.
        Write-Warning "Installation did not finish. Inspect $root; run client\Uninstall.ps1 to explicitly restore direct access."
    }
}
