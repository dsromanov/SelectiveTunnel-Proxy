param([Parameter(Mandatory=$true)][string]$Engine,
      [string]$Python='python',
      [string]$Scratch=(Join-Path $env:TEMP ('SelectiveProxy-' + [guid]::NewGuid().ToString('N'))))
# Legacy 1.1.0 fixture. Prefer: SelectiveTunnel.exe --self-test --engine <sing-box.exe>
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\..\legacy\client\Core.psm1" -Force
New-Item -ItemType Directory -Path $Scratch -Force | Out-Null
$script:passed=0
function Check($Name,[scriptblock]$Test) { & $Test; $script:passed++; "PASS $Name" }
function Require($Value,$Message) { if (-not $Value) { throw $Message } }
function Must-Fail([scriptblock]$Test) { $failed=$false; try { & $Test } catch { $failed=$true }; Require $failed 'Expected rejection' }
function Clone($Value) { $Value | ConvertTo-Json -Depth 40 | ConvertFrom-Json }
function Free-Port {
    $listener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0)
    $listener.Start(); $port=$listener.LocalEndpoint.Port; $listener.Stop(); return $port
}
$profile=[pscustomobject]@{schema=2;protocol='socks5';server_ip='127.0.0.1';server_port=1080;
    username='fixture-user';password='fixture-password';expected_exit_ip='';tls_server_name='';policy_url='';policy_public_key=''}
$policy=Read-Json "$PSScriptRoot\..\policy\domains.json"
$fixture=$null; $script:handle=$null
$curl="$env:SystemRoot\System32\curl.exe"
try {
    Check 'SOCKS5 HTTP and TLS proxy configurations accepted via stdin' {
        foreach ($proto in @('socks5','http','https')) {
            $p=Clone $profile; $p.protocol=$proto
            if ($proto -eq 'https') { $p.tls_server_name='proxy.example.org' }
            Test-EngineConfig (New-EngineConfig $p $policy $Scratch) $Engine
        }
    }
    Check 'Other services remain direct and selected UDP is rejected' {
        $c=New-EngineConfig $profile $policy $Scratch
        Require ($c.route.final -eq 'direct') 'Direct default required'
        Require ($c.inbounds[2].route_address.Count -eq 4) 'Unexpected TUN ranges'
        Require ($c.inbounds[2].route_address -notcontains '0.0.0.0/0' -and $c.inbounds[2].route_address -notcontains '::/0') 'Full tunnel not permitted'
        Require ($c.inbounds[2].dns_mode -eq 'disabled') 'Other adapter DNS must remain unchanged'
        Require ($c.route.rules[2].network -eq 'udp' -and $c.route.rules[2].action -eq 'reject') 'Selected UDP must not fall through'
        Require ($c.outbounds[0].network -eq 'tcp') 'Unsupported upstream UDP enabled'
        Require ($c.dns.servers[1].type -eq 'https' -and $c.dns.servers[1].detour -eq 'proxy') 'DNS must use TCP through proxy'
        Require ($c.route.rules[-1].action -eq 'reject') 'Stale FakeIPs must fail closed'
    }
    Check 'Empty credentials invalid ports and broad CIDRs rejected' {
        $p=Clone $profile; $p.password=''; Must-Fail { Assert-Profile $p }
        $p=Clone $profile; $p.username="a`nb"; Must-Fail { Assert-Profile $p }
        $p=Clone $profile; $p.server_port=65536; Must-Fail { Assert-Profile $p }
        $p=Clone $profile; $p.protocol='https'; Must-Fail { Assert-Profile $p }
        $rules=Clone $policy; $rules.cidrs=@('1.1.1.0/24'); Must-Fail { New-EngineConfig $profile $rules $Scratch }
    }
    Check 'DPAPI roundtrip stores no cleartext username or password' {
        $path=Join-Path $Scratch 'connection.dpapi'
        Save-Connection $profile $path
        $read=Read-Connection $path
        Require ($read.password -eq $profile.password -and $read.username -eq $profile.username) 'Credential roundtrip failed'
        $bytes=[IO.File]::ReadAllBytes($path)
        Require (-not [Text.Encoding]::UTF8.GetString($bytes).Contains($profile.password)) 'Cleartext password persisted'
        Require (-not [Text.Encoding]::UTF8.GetString($bytes).Contains($profile.username)) 'Cleartext login persisted'
        $p=Clone $profile; $p.password='new-fixture-password'; Save-Connection $p $path
        Require ((Read-Connection $path).password -eq $p.password) 'Encrypted atomic replacement failed'
        $bytes[20]=$bytes[20] -bxor 1; [IO.File]::WriteAllBytes($path,$bytes)
        Must-Fail { Read-Connection $path }
    }
    Check 'No domain feed required for standalone proxy mode' {
        Require ($null -eq (Receive-Policy $profile $policy)) 'Missing feed should not make an HTTP call'
    }
    Check 'Signed updates reject tampering replay and preserve existing domains' {
        $rsa=New-Object Security.Cryptography.RSACryptoServiceProvider 3072
        try {
            $p=Clone $profile; $p.policy_url='https://policy.example.org/policy.json'; $p.policy_public_key=$rsa.ToXmlString($false)
            $next=Clone $policy; $next.version=2; $next.domains=@('test.figma.com')
            $bytes=[Text.Encoding]::UTF8.GetBytes(($next | ConvertTo-Json -Depth 10))
            $envlp=[pscustomobject]@{payload=[Convert]::ToBase64String($bytes);signature=[Convert]::ToBase64String($rsa.SignData($bytes,'SHA256'))}
            $merged=ConvertFrom-SignedPolicy $envlp $p $policy
            Require ($merged.domains -contains 'chatgpt.com' -and $merged.domains -contains 'test.figma.com') 'Unsafe policy removal'
            Require ($null -eq (ConvertFrom-SignedPolicy $envlp $p $merged)) 'Replay accepted'
            $bytes[1]=$bytes[1] -bxor 1; $envlp.payload=[Convert]::ToBase64String($bytes)
            Must-Fail { ConvertFrom-SignedPolicy $envlp $p $policy }
        } finally { $rsa.Dispose() }
    }
    $ready=Join-Path $Scratch 'mock-ready.json'; $events=Join-Path $Scratch 'mock-events.txt'
    if (Test-Path $ready) { Remove-Item -LiteralPath $ready }
    if (Test-Path $events) { Remove-Item -LiteralPath $events }
    $pythonPath=(Get-Command $Python -ErrorAction Stop).Source
    $fixture=Start-Process $pythonPath -ArgumentList @(('"'+"$PSScriptRoot\MockProxy.py"+'"'),'--ready',('"'+$ready+'"'),'--events',('"'+$events+'"')) -WindowStyle Hidden -PassThru -RedirectStandardError (Join-Path $Scratch 'mock-error.txt') -RedirectStandardOutput (Join-Path $Scratch 'mock-out.txt')
    for ($i=0;$i -lt 50 -and -not (Test-Path $ready);$i++) { Start-Sleep -Milliseconds 100 }
    Require (Test-Path $ready) 'Mock proxy did not start'
    $ports=Read-Json $ready
    foreach ($protocol in @('socks5','http')) {
        Check "$protocol authentication and non-selected direct traffic (real sockets)" {
            $p=Clone $profile; $p.protocol=$protocol
            $p.server_port=if ($protocol -eq 'socks5') { $ports.socks } else { $ports.http }
            $c=New-EngineConfig $p $policy $Scratch
            $diag=Free-Port; $normal=Free-Port
            # No TUN/NRPT/firewall: loopback-only proxy inbounds exercise production route rules.
            $c.inbounds=@(@{type='mixed';tag='diagnostic';listen='127.0.0.1';listen_port=$diag},@{type='mixed';tag='normal';listen='127.0.0.1';listen_port=$normal})
            $script:handle=Start-EngineMemory $c $Engine
            Start-Sleep -Milliseconds 800
            Require (-not $handle.Process.HasExited) 'Engine did not start'
            $body=& $curl --silent --fail --max-time 5 --noproxy 'no-bypass.invalid' --socks5-hostname "127.0.0.1:$diag" "http://127.0.0.1:$($ports.origin)/"
            Require ($LASTEXITCODE -eq 0 -and "$body" -eq 'MOCK_PROXY_OK') 'Proxy authentication/forwarding failed'
            $body=& $curl --silent --fail --max-time 5 --noproxy 'no-bypass.invalid' --socks5-hostname "127.0.0.1:$normal" 'http://chatgpt.com/'
            Require ($LASTEXITCODE -eq 0 -and "$body" -eq 'MOCK_PROXY_OK') 'Selected domain did not use upstream proxy'
            $body=& $curl --silent --fail --max-time 5 --noproxy 'no-bypass.invalid' --socks5-hostname "127.0.0.1:$normal" "http://127.0.0.1:$($ports.origin)/"
            Require ($LASTEXITCODE -eq 0 -and "$body" -eq 'DIRECT_ORIGIN') 'Non-selected traffic failed direct route'
            Stop-EngineMemory $handle; $script:handle=$null
        }
        Check "$protocol wrong password has no direct fallback" {
            $p=Clone $profile; $p.protocol=$protocol
            $p.server_port=if ($protocol -eq 'socks5') { $ports.socks } else { $ports.http }
            $p.password='incorrect-fixture-password'
            $c=New-EngineConfig $p $policy $Scratch
            $diag=Free-Port; $c.inbounds=@(@{type='mixed';tag='diagnostic';listen='127.0.0.1';listen_port=$diag})
            $script:handle=Start-EngineMemory $c $Engine
            Start-Sleep -Milliseconds 800
            $before=@(Get-Content $events | Where-Object { $_ -eq 'direct_origin' }).Count
            $body=& $curl --silent --fail --max-time 4 --noproxy 'no-bypass.invalid' --socks5-hostname "127.0.0.1:$diag" "http://127.0.0.1:$($ports.origin)/"
            Require ($LASTEXITCODE -ne 0) 'Bad authentication unexpectedly succeeded'
            $after=@(Get-Content $events | Where-Object { $_ -eq 'direct_origin' }).Count
            Require ($before -eq $after) 'Authentication failure reached direct origin'
            Stop-EngineMemory $handle; $script:handle=$null
        }
    }
    foreach ($ipv4Only in @($false,$true)) {
    Check ("Real DNS mode ipv4Only=$ipv4Only") {
        if ($ipv4Only) { [IO.File]::WriteAllText((Join-Path $Scratch 'tun-ipv4-only.flag'),'1') }
        $c=New-EngineConfig $profile $policy $Scratch
        Test-EngineConfig $c $Engine
        if ($ipv4Only) { Require (@($c.inbounds[2].address | Where-Object { $_ -like '*:*' }).Count -eq 0) 'IPv6 TUN address remains'; Require (@($c.inbounds[2].route_address | Where-Object { $_ -like '*:*' }).Count -eq 0) 'IPv6 route remains'; Require ($c.route.final -eq 'direct') 'Default route changed' }
        $dns=Free-Port; $c.inbounds=@(@{type='direct';tag='dns-in';listen='127.0.0.1';listen_port=$dns})
        $script:handle=Start-EngineMemory $c $Engine
        Start-Sleep -Milliseconds 800
        foreach ($type in @(1,28,65)) {
            $packet=New-Object 'System.Collections.Generic.List[byte]'
            $packet.AddRange([byte[]]@(0x12,0x34,1,0,0,1,0,0,0,0,0,0))
            foreach ($label in 'chatgpt.com'.Split('.')) { $packet.Add([byte]$label.Length); $packet.AddRange([Text.Encoding]::ASCII.GetBytes($label)) }
            $packet.AddRange([byte[]]@(0,0,$type,0,1))
            $udp=New-Object Net.Sockets.UdpClient
            try {
                $udp.Client.ReceiveTimeout=3000; $udp.Connect('127.0.0.1',$dns)
                $data=$packet.ToArray(); $udp.Send($data,$data.Length) | Out-Null
                $remote=New-Object Net.IPEndPoint([Net.IPAddress]::Loopback,0)
                $answer=$udp.Receive([ref]$remote)
                Require (($answer[3] -band 15) -eq 0) 'DNS error'
                if ($type -eq 65 -or ($ipv4Only -and $type -eq 28)) { Require ($answer[7] -eq 0) 'HTTPS hint leaked' }
                elseif ($type -eq 1) { Require ($answer[-4] -eq 198 -and $answer[-3] -in @(18,19)) 'Wrong fake IPv4' }
                else { Require ($answer[-16] -eq 0xfd -and $answer[-15] -eq 0x71) 'Wrong fake IPv6' }
            } finally { $udp.Dispose() }
        }
        Stop-EngineMemory $handle; $script:handle=$null
    }
    }
    "$script:passed checks passed. No system network settings changed; no real proxy credentials used."
} finally {
    Stop-EngineMemory $handle
    if ($fixture) { if (-not $fixture.HasExited) { $fixture.Kill(); $fixture.WaitForExit() }; $fixture.Dispose() }
}
