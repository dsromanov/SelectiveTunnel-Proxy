Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Root = Join-Path $env:ProgramData 'SelectiveTunnel'
$script:App = Join-Path $env:ProgramFiles 'SelectiveTunnel'
$script:Name = 'SelectiveTunnel'
$script:Tun = 'SelectiveTunnel-TUN'
$script:Fake = @('198.18.0.0/15','fd71:5e1e:c710::/48')

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run Windows PowerShell as administrator.'
    }
}
function Write-JsonAtomic($Path, $Value) {
    $temp = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText($temp, ($Value | ConvertTo-Json -Depth 40), [Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temp, $Path, [NullString]::Value) }
    else { [IO.File]::Move($temp, $Path) }
}
function Read-Json($Path) { Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
function Assert-Profile($P) {
    if ($P.schema -ne 2) { throw 'A proxy connection (schema 2) is required.' }
    if ($P.protocol -notin @('socks5','http','https')) { throw 'Unsupported proxy protocol.' }
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($P.server_ip,[ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'Enter the numeric IPv4 address of the proxy.'
    }
    if ([int]$P.server_port -lt 1 -or [int]$P.server_port -gt 65535) { throw 'Invalid server port.' }
    foreach ($name in @('username','password')) {
        $value = $P.$name
        if ($value -isnot [string] -or [string]::IsNullOrEmpty($value) -or $value -match '[\x00-\x1f\x7f]' -or
            [Text.Encoding]::UTF8.GetByteCount($value) -gt 255) { throw "Invalid proxy $name (1..255 UTF-8 bytes; no control characters)." }
    }
    if ($P.protocol -ne 'socks5' -and $P.username.Contains(':')) { throw 'HTTP proxy username cannot contain a colon.' }
    if ($P.expected_exit_ip -and -not [Net.IPAddress]::TryParse($P.expected_exit_ip,[ref]$ip)) { throw 'Invalid expected exit IP.' }
    if ($P.protocol -eq 'https' -and $P.tls_server_name -notmatch '^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$') {
        throw 'HTTPS proxy requires the hostname on its TLS certificate. HTTP(S) marketing alone does not imply TLS to the proxy.'
    }
    if ([bool]$P.policy_url -ne [bool]$P.policy_public_key) { throw 'Policy URL and public signing key must be configured together.' }
    if ($P.policy_url) {
        $uri = [Uri]$P.policy_url
        if ($uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Port -ne 443 -or $uri.Query -or $uri.Fragment) {
            throw 'Policy URL must be HTTPS on port 443, without credentials or query.'
        }
        $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider
        try {
            $rsa.FromXmlString($P.policy_public_key)
            if ($rsa.KeySize -lt 3072 -or -not $rsa.PublicOnly) { throw 'A public RSA key of at least 3072 bits is required.' }
        } finally { $rsa.Dispose() }
    }
}
function Save-Connection($Profile, [string]$Path = (Join-Path $script:Root 'connection.dpapi')) {
    Assert-Profile $Profile
    Add-Type -AssemblyName System.Security
    $plain = [Text.Encoding]::UTF8.GetBytes(($Profile | ConvertTo-Json -Depth 10 -Compress))
    try {
        # SYSTEM must read the blob at startup. Machine scope therefore requires admin-only file ACLs.
        $sealed = [Security.Cryptography.ProtectedData]::Protect($plain,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
        $temp = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
        [IO.File]::WriteAllBytes($temp,$sealed)
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temp,$Path,[NullString]::Value) }
        else { [IO.File]::Move($temp,$Path) }
    } finally { [Array]::Clear($plain,0,$plain.Length) }
}
function Read-Connection([string]$Path = (Join-Path $script:Root 'connection.dpapi')) {
    Add-Type -AssemblyName System.Security
    try { $plain = [Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($Path),$null,[Security.Cryptography.DataProtectionScope]::LocalMachine) }
    catch { throw 'Cannot decrypt the connection on this Windows machine. Re-enter proxy settings.' }
    try {
        $p = [Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
        Assert-Profile $p
        return $p
    } finally { [Array]::Clear($plain,0,$plain.Length) }
}
function Assert-Policy($P) {
    if ($P.version -isnot [long] -and $P.version -isnot [int]) { throw 'Policy version must be an integer.' }
    if ($P.version -lt 1 -or $P.version -gt 2147483647) { throw 'Invalid policy version.' }
    if (@($P.domains).Count -lt 1 -or @($P.domains).Count -gt 200) { throw 'Expected 1..200 domain suffixes.' }
    foreach ($d in $P.domains) {
        if ($d -isnot [string] -or $d.Length -gt 253 -or $d -cne $d.ToLowerInvariant() -or
            $d -notmatch '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$') {
            throw "Invalid domain suffix: $d"
        }
        if ($d -in @('com','net','org','co.uk','com.au','cloudflare.com','cloudfront.net','amazonaws.com','azureedge.net','google.com','jsdelivr.net')) {
            throw "Shared infrastructure suffix is too broad: $d"
        }
    }
    if (@($P.domains | Select-Object -Unique).Count -ne @($P.domains).Count) { throw 'Duplicate domains.' }
    if (@($P.cidrs).Count -gt 100) { throw 'Too many IP ranges.' }
    foreach ($c in $P.cidrs) {
        if ($c -notmatch '^([0-9.]+)/([0-9]+)$') { throw 'Only explicit IPv4 CIDRs are supported.' }
        $ip = [Net.IPAddress]::Parse($Matches[1]); $prefix = [int]$Matches[2]
        if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $prefix -lt 24 -or $prefix -gt 32) {
            throw 'CIDRs must be IPv4 /24 through /32; do not route whole CDN networks.'
        }
        $b = $ip.GetAddressBytes()
        if ($b[0] -in @(0,10,127) -or $b[0] -ge 224 -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
            ($b[0] -eq 192 -and $b[1] -eq 168) -or ($b[0] -eq 169 -and $b[1] -eq 254) -or
            ($b[0] -eq 198 -and $b[1] -in @(18,19))) { throw 'Non-public CIDR is forbidden.' }
        $hostMask = (1 -shl (32 - $prefix)) - 1
        if (($b[3] -band $hostMask) -ne 0) { throw 'CIDR must be a network address.' }
    }
}
function New-EngineConfig($Profile, $Policy, [string]$DataRoot = $script:Root) {
    Assert-Profile $Profile; Assert-Policy $Policy
    $rules = @(
        @{ inbound=@('dns-in'); action='hijack-dns' },
        # UDP support is not established for this provider. Reject it only in selected traffic.
        @{ inbound=@('diagnostic'); network='udp'; action='reject' },
        @{ domain_suffix=@($Policy.domains); network='udp'; action='reject' },
        @{ inbound=@('diagnostic'); action='route'; outbound='proxy' },
        @{ domain_suffix=@($Policy.domains); action='route'; outbound='proxy' }
    )
    if (@($Policy.cidrs).Count) {
        throw 'The proxy edition uses domain rules only. Leave cidrs empty to avoid shared-CDN and adapter-change leaks.'
    }
    # Unmapped/stale fake addresses must never fall through to direct.
    $rules += @{ ip_cidr=$script:Fake; action='reject' }
    $proxy = @{type='socks';tag='proxy';server=$Profile.server_ip;server_port=[int]$Profile.server_port;
        version='5';username=$Profile.username;password=$Profile.password;network='tcp'}
    if ($Profile.protocol -ne 'socks5') {
        $proxy = @{type='http';tag='proxy';server=$Profile.server_ip;server_port=[int]$Profile.server_port;
            username=$Profile.username;password=$Profile.password}
        if ($Profile.protocol -eq 'https') { $proxy.tls = @{enabled=$true;server_name=$Profile.tls_server_name} }
    }
    $config = @{
        # No persistent engine output containing authentication details or URLs.
        log=@{disabled=$true}
        dns=@{
            servers=@(
                @{type='fakeip';tag='fake';inet4_range=$script:Fake[0];inet6_range=$script:Fake[1]},
                @{type='https';tag='remote';server='1.1.1.1';server_port=443;path='/dns-query';
                    tls=@{enabled=$true;server_name='cloudflare-dns.com'};detour='proxy'}
            )
            rules=@(
                @{domain_suffix=@($Policy.domains);query_type=@('A','AAAA');action='route';server='fake';rewrite_ttl=60},
                @{domain_suffix=@($Policy.domains);query_type=@('HTTPS','SVCB');action='predefined';rcode='NOERROR'},
                @{domain_suffix=@($Policy.domains);action='route';server='remote'},
                @{action='reject'}
            )
            final='remote'
        }
        inbounds=@(
            @{type='direct';tag='dns-in';listen='127.0.0.1';listen_port=53},
            @{type='mixed';tag='diagnostic';listen='127.0.0.1';listen_port=17891},
            @{type='tun';tag='tun';interface_name=$script:Tun;address=@('172.31.255.1/30','fd71:5e1e:c711::1/126');mtu=1380;
              auto_route=$true;strict_route=$false;dns_mode='disabled';stack='gvisor';
              route_address=@('198.18.0.0/16','198.19.0.0/16','fd71:5e1e:c710::/49','fd71:5e1e:c710:8000::/49') + @($Policy.cidrs)}
        )
        outbounds=@($proxy,@{type='direct';tag='direct'})
        route=@{auto_detect_interface=$true;default_domain_resolver=@{server='remote';strategy='ipv4_only'};rules=$rules;final='direct'}
        experimental=@{cache_file=@{enabled=$true;path=(Join-Path $DataRoot 'cache.db');store_fakeip=$true}}
    }
    if (Test-Path -LiteralPath (Join-Path $DataRoot 'tun-ipv4-only.flag')) {
        $tun = $config.inbounds | Where-Object tag -eq 'tun'
        $tun.address = @('172.31.255.1/30')
        $tun.route_address = @('198.18.0.0/16','198.19.0.0/16')
        $config.dns.servers[0].Remove('inet6_range')
        $config.dns.rules[0].query_type = @('A')
        # Do not expose real IPv6 destinations when no IPv6 TUN exists.
        $config.dns.rules[1].query_type = @('AAAA','HTTPS','SVCB')
        # Keep the dual-stack cache separate from this compatibility mode.
        $config.experimental.cache_file.path = Join-Path $DataRoot 'cache-ipv4.db'
    }
    return $config
}
function Start-EngineMemory($Config,[string]$Engine = (Join-Path $script:App 'bin\sing-box.exe'),[ValidateSet('run','check')][string]$Mode='run') {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Engine
    $info.Arguments = "$Mode -c stdin"
    $info.WorkingDirectory = [IO.Path]::GetDirectoryName($Engine)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    $started = $false
    try {
        $process.Start() | Out-Null
        $started = $true
        $outTask = $process.StandardOutput.ReadToEndAsync()
        $errTask = $process.StandardError.ReadToEndAsync()
        $inputBytes = [Text.Encoding]::UTF8.GetBytes(($Config | ConvertTo-Json -Depth 40 -Compress))
        try {
            $process.StandardInput.BaseStream.Write($inputBytes,0,$inputBytes.Length)
            $process.StandardInput.BaseStream.Close()
        } finally { [Array]::Clear($inputBytes,0,$inputBytes.Length) }
        return [pscustomobject]@{Process=$process;Output=$outTask;Errors=$errTask}
    } catch {
        if ($started -and -not $process.HasExited) { $process.Kill() }
        $process.Dispose()
        throw 'Could not start the proxy engine. No credentials were written to disk.'
    }
}
function Stop-EngineMemory($Handle) {
    if ($null -ne $Handle) {
        if (-not $Handle.Process.HasExited) { $Handle.Process.Kill(); $Handle.Process.WaitForExit(5000) | Out-Null }
        $Handle.Process.Dispose()
    }
}
function Test-EngineConfig($Config,[string]$Engine = (Join-Path $script:App 'bin\sing-box.exe')) {
    $h = Start-EngineMemory $Config $Engine 'check'
    try {
        if (-not $h.Process.WaitForExit(15000)) { throw 'Engine configuration check timed out.' }
        if ($h.Process.ExitCode -ne 0) { throw 'Engine rejected proxy settings. Check host, port, protocol and credentials format.' }
    } finally { Stop-EngineMemory $h }
}
function Set-Guards($Policy) {
    Assert-Admin; Assert-Policy $Policy
    if (@(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count) { throw 'Windows Firewall must be enabled for every profile.' }
    # These low-priority routes persist without the engine. TUN installs more-specific routes.
    # They sink stale FakeIP destinations into loopback even on a newly attached adapter.
    $loop = Get-NetIPAddress -IPAddress '127.0.0.1' | Select-Object -First 1
    foreach ($prefix in $script:Fake) {
        $hop = if ($prefix -like '*:*') { '::' } else { '0.0.0.0' }
        if (-not (Get-NetRoute -PolicyStore PersistentStore -DestinationPrefix $prefix -InterfaceIndex $loop.InterfaceIndex -ErrorAction SilentlyContinue)) {
            # New-NetRoute saves to ActiveStore + PersistentStore by default.
            # Explicit -PolicyStore PersistentStore is not accepted by Windows.
            try { New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $loop.InterfaceIndex -NextHop $hop -RouteMetric 9999 | Out-Null }
            catch { throw "Persistent guard route $prefix on interface $($loop.InterfaceIndex): $($_.Exception.Message)" }
        }
        if (-not (Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix $prefix -InterfaceIndex $loop.InterfaceIndex -ErrorAction SilentlyContinue)) {
            New-NetRoute -PolicyStore ActiveStore -DestinationPrefix $prefix -InterfaceIndex $loop.InterfaceIndex -NextHop $hop -RouteMetric 9999 | Out-Null
        }
    }
    # Firewall provides a second barrier on all currently known non-TUN adapters.
    # Additions are installed before old filters are removed; unrelated destinations are untouched.
    # Hidden WAN miniports can exist in NetAdapter without an IP/firewall interface.
    # FakeIP sink routes remain in force while a new physical adapter comes up.
    $adapters = @(Get-NetAdapter | Where-Object { $_.Name -ne $script:Tun -and $_.Status -eq 'Up' })
    $addresses = @($script:Fake) + @($Policy.cidrs)
    foreach ($adapter in $adapters) {
        $id = 'SelectiveTunnel-' + $adapter.InterfaceGuid.ToString().Trim('{}')
        $existing = Get-NetFirewallRule -Name $id -ErrorAction SilentlyContinue
        if (-not $existing) {
            try { New-NetFirewallRule -Name $id -DisplayName $id -Group $script:Name -Direction Outbound -Action Block -Profile Any -InterfaceAlias $adapter.Name -RemoteAddress $addresses | Out-Null }
            catch { throw "Firewall guard for interface $($adapter.Name): $($_.Exception.Message)" }
        } else {
            $existing | Set-NetFirewallRule -InterfaceAlias $adapter.Name -RemoteAddress $addresses -Enabled True | Out-Null
        }
    }
    # Own exact and suffix rules. Never remove other software's NRPT entries.
    $owned = @(Get-DnsClientNrptRule | Where-Object Comment -eq $script:Name)
    foreach ($domain in $Policy.domains) {
        foreach ($ns in @($domain, ".$domain")) {
            if (-not ($owned | Where-Object { $_.Namespace -contains $ns })) {
                Add-DnsClientNrptRule -Namespace $ns -NameServers '127.0.0.1' -Comment $script:Name | Out-Null
            }
        }
    }
}
function Remove-Guards {
    Assert-Admin
    Get-DnsClientNrptRule | Where-Object Comment -eq $script:Name | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }
    Get-NetFirewallRule -Group $script:Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $loop = Get-NetIPAddress -IPAddress '127.0.0.1' | Select-Object -First 1
    foreach ($store in @('PersistentStore','ActiveStore')) {
        foreach ($prefix in $script:Fake) {
            Get-NetRoute -PolicyStore $store -DestinationPrefix $prefix -InterfaceIndex $loop.InterfaceIndex -ErrorAction SilentlyContinue |
                Where-Object RouteMetric -eq 9999 | Remove-NetRoute -Confirm:$false
        }
    }
    Clear-DnsClientCache
}
function ConvertFrom-SignedPolicy($Envelope, $Profile, $Current) {
    Assert-Profile $Profile
    if (-not $Profile.policy_public_key) { throw 'No trusted policy signing key configured.' }
    $payload = [Convert]::FromBase64String($Envelope.payload)
    if ($payload.Length -gt 65536) { throw 'Decoded policy is too large.' }
    $signature = [Convert]::FromBase64String($Envelope.signature)
    $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider
    try {
        $rsa.FromXmlString($Profile.policy_public_key)
        if (-not $rsa.VerifyData($payload,'SHA256',$signature)) { throw 'Invalid policy signature.' }
    } finally { $rsa.Dispose() }
    $candidate = [Text.Encoding]::UTF8.GetString($payload) | ConvertFrom-Json
    Assert-Policy $candidate
    if ($candidate.version -le $Current.version) { return $null }
    # Updates are additive so a remote deletion cannot silently open a direct path.
    $candidate.domains = @(@($Current.domains) + @($candidate.domains) | Sort-Object -Unique)
    $candidate.cidrs = @(@($Current.cidrs) + @($candidate.cidrs) | Sort-Object -Unique)
    Assert-Policy $candidate
    return $candidate
}
function Receive-Policy($Profile, $Current) {
    Assert-Profile $Profile
    if (-not $Profile.policy_url) { return $null }
    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $client = New-Object Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(20)
    try {
        $response = $client.GetAsync($Profile.policy_url, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        $response.EnsureSuccessStatusCode() | Out-Null
        $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $memory = New-Object IO.MemoryStream
        try {
            $buffer = New-Object byte[] 8192
            $deadline = [DateTime]::UtcNow.AddSeconds(20)
            while ($true) {
                $remaining = [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds
                if ($remaining -le 0) { throw 'Policy body download timed out.' }
                $pending = $stream.ReadAsync($buffer,0,$buffer.Length)
                if (-not $pending.Wait($remaining)) { throw 'Policy body download timed out.' }
                $n = $pending.GetAwaiter().GetResult()
                if ($n -eq 0) { break }
                if ($memory.Length + $n -gt 131072) { throw 'Policy response is too large.' }
                $memory.Write($buffer,0,$n)
            }
            $envelope = [Text.Encoding]::UTF8.GetString($memory.ToArray()) | ConvertFrom-Json
        } finally { $memory.Dispose(); $stream.Dispose(); $response.Dispose() }
        return ConvertFrom-SignedPolicy $envelope $Profile $Current
    } finally { $client.Dispose(); $handler.Dispose() }
}
Export-ModuleMember -Function *
