# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$container = 'scoplen-algorithm-interop-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$started = $false
$testVariables = @(
    'SCOPLEN_ALGORITHM_MODERN_PORT', 'SCOPLEN_ALGORITHM_LEGACY_PORT',
    'SCOPLEN_ALGORITHM_HOST_KEY', 'SCOPLEN_ALGORITHM_USER', 'SCOPLEN_ALGORITHM_PASSWORD'
)

try {
    $setup = @'
set -eu
apk add --no-cache openssh-server
adduser -D scoplen
printf 'scoplen:scoplen-test-password\n' | chpasswd
ssh-keygen -q -t ed25519 -N '' -f /tmp/host_key
mkdir -p /run/sshd
cat > /tmp/modern.conf <<'SSHD'
Port 2222
ListenAddress 0.0.0.0
HostKey /tmp/host_key
PasswordAuthentication yes
KexAlgorithms curve25519-sha256
HostKeyAlgorithms ssh-ed25519
Ciphers aes256-ctr
MACs hmac-sha2-256-etm@openssh.com
Compression no
SSHD
cat > /tmp/legacy.conf <<'SSHD'
Port 2223
ListenAddress 0.0.0.0
HostKey /tmp/host_key
PasswordAuthentication yes
KexAlgorithms diffie-hellman-group14-sha256
HostKeyAlgorithms ssh-ed25519
Ciphers aes256-cbc
MACs hmac-sha1
Compression no
SSHD
/usr/sbin/sshd -t -f /tmp/modern.conf
/usr/sbin/sshd -t -f /tmp/legacy.conf
/usr/sbin/sshd -D -e -f /tmp/modern.conf &
exec /usr/sbin/sshd -D -e -f /tmp/legacy.conf
'@
    docker run -d --rm --name $container -p '127.0.0.1::2222' -p '127.0.0.1::2223' alpine:3.21 sh -c $setup | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to start disposable OpenSSH algorithm container' }
    $started = $true

    $ports = @{}
    foreach ($serverPort in @(2222, 2223)) {
        $published = docker port $container "$serverPort/tcp"
        if ($LASTEXITCODE -ne 0 -or $published -notmatch '^127\.0\.0\.1:(\d+)$') {
            throw "Disposable OpenSSH port $serverPort was not published on loopback"
        }
        $ports[$serverPort] = [int]$Matches[1]
    }

    $ready = $false
    $hostKey = $null
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $hostKey = docker exec $container cat /tmp/host_key.pub 2>$null
        if ($LASTEXITCODE -ne 0 -or $hostKey -notmatch '^ssh-ed25519 ') {
            Start-Sleep -Seconds 1
            continue
        }
        $ready = $true
        foreach ($port in $ports.Values) {
            $socket = [System.Net.Sockets.TcpClient]::new()
            try { $socket.Connect('127.0.0.1', $port) }
            catch { $ready = $false }
            finally { $socket.Dispose() }
        }
        if ($ready) { break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw 'Constrained OpenSSH listeners did not become ready within 60 seconds' }

    $env:SCOPLEN_ALGORITHM_MODERN_PORT = $ports[2222].ToString()
    $env:SCOPLEN_ALGORITHM_LEGACY_PORT = $ports[2223].ToString()
    $env:SCOPLEN_ALGORITHM_HOST_KEY = $hostKey
    $env:SCOPLEN_ALGORITHM_USER = 'scoplen'
    $env:SCOPLEN_ALGORITHM_PASSWORD = 'scoplen-test-password'
    cargo run --quiet --locked -p scoplen-ssh --example algorithm_interop
    if ($LASTEXITCODE -ne 0) { throw 'Constrained OpenSSH algorithm interop failed' }
}
finally {
    if ($started) { docker stop $container | Out-Null }
    foreach ($name in $testVariables) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
}
