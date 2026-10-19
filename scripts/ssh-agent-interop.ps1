# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$container = 'scoplen-ssh-agent-interop-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$started = $false
$variables = @(
    'SCOPLEN_AGENT_HOST_KEY', 'SCOPLEN_AGENT_USER_KEY', 'SCOPLEN_AGENT_PORT',
    'SCOPLEN_AGENT_SSH_PORT', 'SCOPLEN_AGENT_USER_CERT', 'SCOPLEN_AGENT_USER_CA_KEY'
)
foreach ($name in $variables) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }

function Read-PublicFile {
    param([string]$path)

    $line = docker exec $container cat $path
    if ($LASTEXITCODE -ne 0 -or -not $line) { throw "Could not read disposable public file $path" }
    return $line.Trim()
}

function Invoke-Case {
    param(
        [string]$name,
        [string]$mode,
        [string]$userKey,
        [string]$certificate = '',
        [string]$caKey = '',
        [string]$expectedError = ''
    )

    $env:SCOPLEN_AGENT_USER_KEY = $userKey
    if ($certificate) { $env:SCOPLEN_AGENT_USER_CERT = $certificate }
    else { Remove-Item Env:SCOPLEN_AGENT_USER_CERT -ErrorAction SilentlyContinue }
    if ($caKey) { $env:SCOPLEN_AGENT_USER_CA_KEY = $caKey }
    else { Remove-Item Env:SCOPLEN_AGENT_USER_CA_KEY -ErrorAction SilentlyContinue }

    $output = & cargo run --quiet --locked -p scoplen-ssh --example openssh_agent_interop -- $mode 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    if ($expectedError) {
        if ($exitCode -eq 0 -or $output -notmatch [regex]::Escape($expectedError)) {
            throw "${name}: expected '$expectedError', got exit $exitCode and '$output'"
        }
        Write-Output "${name}: rejected ($expectedError)"
    }
    else {
        $expected = "openssh agent $mode command ok"
        if ($exitCode -ne 0 -or $output.Trim() -ne $expected) {
            throw "${name}: expected '$expected', got exit $exitCode and '$output'"
        }
        Write-Output "${name}: $expected"
    }
}

try {
    $setup = @'
set -eu
apk add --no-cache openssh-server openssh-client socat
adduser -D scoplen
printf 'scoplen:disposable-test-password\n' | chpasswd
mkdir -p /run/sshd /home/scoplen/.ssh
ssh-keygen -q -t ed25519 -N '' -f /tmp/host_key
ssh-keygen -q -t ed25519 -N '' -f /tmp/user_key
ssh-keygen -q -t ed25519 -N '' -f /tmp/other_key
ssh-keygen -q -t ed25519 -N '' -f /tmp/ca_trusted
ssh-keygen -q -t ed25519 -N '' -f /tmp/ca_other
ssh-keygen -q -s /tmp/ca_trusted -I valid -n scoplen -V -1m:+10m /tmp/user_key.pub
mv /tmp/user_key-cert.pub /tmp/user_valid-cert.pub
ssh-keygen -q -s /tmp/ca_trusted -I wrong-subject -n scoplen -V -1m:+10m /tmp/other_key.pub
mv /tmp/other_key-cert.pub /tmp/user_wrong-subject-cert.pub
ssh-keygen -q -s /tmp/ca_trusted -I wrong-principal -n other -V -1m:+10m /tmp/user_key.pub
mv /tmp/user_key-cert.pub /tmp/user_wrong-principal-cert.pub
ssh-keygen -q -s /tmp/ca_other -I untrusted-ca -n scoplen -V -1m:+10m /tmp/user_key.pub
mv /tmp/user_key-cert.pub /tmp/user_untrusted-ca-cert.pub
cp /tmp/user_key.pub /home/scoplen/.ssh/authorized_keys
cp /tmp/ca_trusted.pub /tmp/trusted_user_cas.pub
chown -R scoplen:scoplen /home/scoplen/.ssh
chmod 700 /home/scoplen/.ssh
chmod 600 /home/scoplen/.ssh/authorized_keys
eval "$(ssh-agent -s -a /tmp/agent.sock)" >/dev/null
ssh-add /tmp/user_key >/dev/null 2>&1
cat > /tmp/sshd_config <<'SSHD'
Port 2222
ListenAddress 0.0.0.0
HostKey /tmp/host_key
PasswordAuthentication no
PubkeyAuthentication yes
TrustedUserCAKeys /tmp/trusted_user_cas.pub
PerSourcePenalties no
SSHD
/usr/sbin/sshd -t -f /tmp/sshd_config
/usr/sbin/sshd -D -e -f /tmp/sshd_config &
exec socat TCP-LISTEN:2223,bind=0.0.0.0,reuseaddr,fork UNIX-CONNECT:/tmp/agent.sock
'@
    $setup = $setup.Replace("`r", '')
    docker run -d --name $container -p '127.0.0.1::2222' -p '127.0.0.1::2223' alpine:3.21 sh -c $setup | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not start disposable OpenSSH agent container' }
    $started = $true

    $ports = @{}
    foreach ($serverPort in @(2222, 2223)) {
        $published = docker port $container "$serverPort/tcp"
        if ($LASTEXITCODE -ne 0 -or $published -notmatch '^127\.0\.0\.1:(\d+)$') {
            throw "OpenSSH agent test port $serverPort was not published on loopback"
        }
        $ports[$serverPort] = [int]$Matches[1]
    }
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $hostKey = docker exec $container cat /tmp/host_key.pub 2>$null
        if ($LASTEXITCODE -eq 0 -and $hostKey -match '^ssh-ed25519 ') {
            $ready = $true
            foreach ($port in $ports.Values) {
                $socket = [System.Net.Sockets.TcpClient]::new()
                try { $socket.Connect('127.0.0.1', $port) }
                catch { $ready = $false }
                finally { $socket.Dispose() }
            }
            if ($ready) { break }
        }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw 'OpenSSH agent and server did not become ready within 60 seconds' }

    $env:SCOPLEN_AGENT_HOST_KEY = Read-PublicFile /tmp/host_key.pub
    $env:SCOPLEN_AGENT_SSH_PORT = $ports[2222].ToString()
    $env:SCOPLEN_AGENT_PORT = $ports[2223].ToString()
    $userKey = Read-PublicFile /tmp/user_key.pub
    $otherKey = Read-PublicFile /tmp/other_key.pub
    $trustedCa = Read-PublicFile /tmp/ca_trusted.pub
    $otherCa = Read-PublicFile /tmp/ca_other.pub
    $valid = Read-PublicFile /tmp/user_valid-cert.pub
    $wrongSubject = Read-PublicFile /tmp/user_wrong-subject-cert.pub
    $wrongPrincipal = Read-PublicFile /tmp/user_wrong-principal-cert.pub
    $untrustedCa = Read-PublicFile /tmp/user_untrusted-ca-cert.pub

    Invoke-Case 'raw' 'raw' $userKey
    Invoke-Case 'certificate' 'certificate' $userKey $valid $trustedCa
    foreach ($case in @(
        @{ Name = 'missing identity'; Mode = 'raw'; UserKey = $otherKey; Certificate = ''; CaKey = ''; Expected = 'requested identity is absent from OpenSSH agent' },
        @{ Name = 'wrong subject'; Mode = 'certificate'; UserKey = $userKey; Certificate = $wrongSubject; CaKey = $trustedCa; Expected = 'PublicKey(KeyMismatch)' },
        @{ Name = 'wrong principal'; Mode = 'certificate'; UserKey = $userKey; Certificate = $wrongPrincipal; CaKey = $trustedCa; Expected = 'PrincipalMismatch' },
        @{ Name = 'wrong local CA pin'; Mode = 'certificate'; UserKey = $userKey; Certificate = $valid; CaKey = $otherCa; Expected = 'user certificate CA is not trusted' },
        @{ Name = 'server-untrusted CA'; Mode = 'certificate'; UserKey = $userKey; Certificate = $untrustedCa; CaKey = $otherCa; Expected = 'AuthenticationRejected' }
    )) {
        Invoke-Case $case.Name $case.Mode $case.UserKey $case.Certificate $case.CaKey $case.Expected
        Invoke-Case "raw control after $($case.Name)" 'raw' $userKey
        Invoke-Case "certificate control after $($case.Name)" 'certificate' $userKey $valid $trustedCa
    }
}
catch {
    if ($started) {
        $logs = docker logs --tail 40 $container 2>&1
        if ($logs) { Write-Warning "Disposable OpenSSH log:`n$($logs | Out-String)" }
    }
    throw
}
finally {
    if ($started) { docker rm -f $container 2>$null | Out-Null }
    foreach ($name in $variables) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
}
