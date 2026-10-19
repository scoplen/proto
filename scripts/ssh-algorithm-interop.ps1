# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$container = 'scoplen-algorithm-interop-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$started = $false
$testVariables = @(
    'SCOPLEN_ALGORITHM_MODERN_PORT', 'SCOPLEN_ALGORITHM_LEGACY_PORT',
    'SCOPLEN_ALGORITHM_HOST_KEY', 'SCOPLEN_ALGORITHM_USER', 'SCOPLEN_ALGORITHM_PASSWORD',
    'SCOPLEN_REKEY_CLIENT_PORT', 'SCOPLEN_REKEY_SERVER_PORT', 'SCOPLEN_REKEY_CONTROL_PORT'
)

function Assert-RekeyLog {
    param([string]$mode, [string]$firstDirection)

    $log = docker exec $container cat "/tmp/rekey-$mode.log" | Out-String
    if ($LASTEXITCODE -ne 0) { throw "Could not read OpenSSH $mode rekey log" }
    $accepted = [regex]::Match($log, '(?m)^.*Accepted password for scoplen.*\n')
    if (-not $accepted.Success) { throw "OpenSSH $mode log has no authenticated session" }
    $postAuth = $log.Substring($accepted.Index + $accepted.Length)
    $kex = @([regex]::Matches($postAuth, '\b(send|receive) packet: type 20\b'))
    $newKeys = @([regex]::Matches($postAuth, '\b(send|receive) packet: type 21\b'))
    $sentKex = @($kex | Where-Object { $_.Groups[1].Value -eq 'send' }).Count
    $receivedKex = @($kex | Where-Object { $_.Groups[1].Value -eq 'receive' }).Count
    $sentNewKeys = @($newKeys | Where-Object { $_.Groups[1].Value -eq 'send' }).Count
    $receivedNewKeys = @($newKeys | Where-Object { $_.Groups[1].Value -eq 'receive' }).Count
    if ($firstDirection -eq 'none') {
        if ($kex.Count -ne 0 -or $newKeys.Count -ne 0) {
            throw "OpenSSH $mode unexpectedly rekeyed after authentication"
        }
        Write-Output "OpenSSH ${mode}: no post-auth KEXINIT or NEWKEYS"
        return
    }
    if ($kex.Count -lt 2 -or $kex[0].Groups[1].Value -ne $firstDirection -or
        $sentKex -eq 0 -or $receivedKex -eq 0 -or
        $sentKex -ne $receivedKex -or $sentKex -ne $sentNewKeys -or
        $sentKex -ne $receivedNewKeys) {
        throw "OpenSSH $mode did not complete the expected $firstDirection-first rekey"
    }
    Write-Output "OpenSSH ${mode}: first post-auth KEXINIT=$firstDirection, KEXINIT send=$sentKex receive=$receivedKex, NEWKEYS send=$sentNewKeys receive=$receivedNewKeys"
}

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
for mode in client server control; do
    case "$mode" in
        client) port=2224; limit='1G 1h' ;;
        server) port=2225; limit='32K 1h' ;;
        control) port=2226; limit='1G 1h' ;;
    esac
    cat > "/tmp/rekey-$mode.conf" <<SSHD
Port $port
ListenAddress 0.0.0.0
HostKey /tmp/host_key
PasswordAuthentication yes
KexAlgorithms curve25519-sha256
HostKeyAlgorithms ssh-ed25519
Ciphers aes256-ctr
MACs hmac-sha2-256-etm@openssh.com
Compression no
LogLevel DEBUG3
RekeyLimit $limit
SSHD
    /usr/sbin/sshd -t -f "/tmp/rekey-$mode.conf"
    /usr/sbin/sshd -D -E "/tmp/rekey-$mode.log" -f "/tmp/rekey-$mode.conf" &
done
/usr/sbin/sshd -t -f /tmp/modern.conf
/usr/sbin/sshd -t -f /tmp/legacy.conf
/usr/sbin/sshd -D -e -f /tmp/modern.conf &
exec /usr/sbin/sshd -D -e -f /tmp/legacy.conf
'@
    # A CRLF checkout leaves carriage returns in PowerShell here-strings; Alpine sh rejects them.
    $setup = $setup.Replace("`r", '')
    docker run -d --name $container -p '127.0.0.1::2222' -p '127.0.0.1::2223' -p '127.0.0.1::2224' -p '127.0.0.1::2225' -p '127.0.0.1::2226' alpine:3.21 sh -c $setup | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to start disposable OpenSSH algorithm container' }
    $started = $true

    $ports = @{}
    foreach ($serverPort in @(2222, 2223, 2224, 2225, 2226)) {
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
    $env:SCOPLEN_REKEY_CLIENT_PORT = $ports[2224].ToString()
    $env:SCOPLEN_REKEY_SERVER_PORT = $ports[2225].ToString()
    $env:SCOPLEN_REKEY_CONTROL_PORT = $ports[2226].ToString()
    cargo run --quiet --locked -p scoplen-ssh --example algorithm_interop
    if ($LASTEXITCODE -ne 0) { throw 'Constrained OpenSSH algorithm interop failed' }
    cargo run --quiet --locked -p scoplen-ssh --example strict_kex_interop
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSH strict KEX interop failed' }
    foreach ($mode in @('client', 'server', 'control')) {
        docker exec $container sh -c ": > /tmp/rekey-$mode.log" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not clear OpenSSH $mode rekey log" }
    }
    cargo run --quiet --locked -p scoplen-ssh --example rekey_interop
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSH rekey interop failed' }
    Assert-RekeyLog 'client' 'receive'
    Assert-RekeyLog 'server' 'send'
    Assert-RekeyLog 'control' 'none'
    Write-Output 'OpenSSH client-initiated, server-initiated, and no-rekey control passed'
}
catch {
    if ($started) {
        $state = docker inspect --format '{{.State.Status}} exit={{.State.ExitCode}}' $container 2>$null
        if ($LASTEXITCODE -eq 0) { Write-Warning "Disposable OpenSSH state: $state" }
        $logs = docker logs --tail 30 $container 2>&1
        if ($LASTEXITCODE -eq 0 -and $logs) { Write-Warning "Disposable OpenSSH log:`n$($logs | Out-String)" }
        foreach ($mode in @('client', 'server', 'control')) {
            $rekeyLog = docker exec $container tail -n 35 "/tmp/rekey-$mode.log" 2>$null
            if ($LASTEXITCODE -eq 0 -and $rekeyLog) {
                Write-Warning "OpenSSH $mode rekey log:`n$($rekeyLog | Out-String)"
            }
        }
    }
    throw
}
finally {
    if ($started) { docker rm -f $container 2>$null | Out-Null }
    foreach ($name in $testVariables) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
}
