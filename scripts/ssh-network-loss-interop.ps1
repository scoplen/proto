# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$container = 'scoplen-network-loss-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$variables = @('SCOPLEN_NETWORK_LOSS_HOST_KEY', 'SCOPLEN_NETWORK_LOSS_PORT')
$saved = @{}
foreach ($name in $variables) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
$started = $false

try {
    $setup = @'
set -eu
apk add --no-cache openssh-server >/dev/null
adduser -D scoplen
printf 'scoplen:fixture-network-loss-password\n' | chpasswd
ssh-keygen -q -t ed25519 -N '' -f /tmp/host_key
mkdir -p /run/sshd
cat > /tmp/sshd.conf <<'SSHD'
Port 2222
ListenAddress 0.0.0.0
HostKey /tmp/host_key
PasswordAuthentication yes
PubkeyAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PerSourcePenalties no
SSHD
/usr/sbin/sshd -t -f /tmp/sshd.conf
exec /usr/sbin/sshd -D -e -f /tmp/sshd.conf
'@
    docker run -d --name $container --label "scoplen.fixture.owner=$container" -p '127.0.0.1::2222' alpine:3.21 sh -c ($setup.Replace("`r", '')) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not start disposable OpenSSH listener' }
    $started = $true

    $published = docker port $container '2222/tcp'
    if ($LASTEXITCODE -ne 0 -or $published -notmatch '^127\.0\.0\.1:(\d+)$') {
        throw 'Disposable OpenSSH port was not published on loopback'
    }
    $port = [int]$Matches[1]
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $hostKey = docker exec $container cat /tmp/host_key.pub 2>$null
        if ($LASTEXITCODE -ne 0 -or $hostKey -notmatch '^ssh-ed25519 ') {
            Start-Sleep -Seconds 1
            continue
        }
        $socket = [System.Net.Sockets.TcpClient]::new()
        try {
            $socket.Connect('127.0.0.1', $port)
            $ready = $true
        }
        catch { Start-Sleep -Seconds 1 }
        finally { $socket.Dispose() }
        if ($ready) { break }
    }
    if (-not $ready) { throw 'OpenSSH did not become ready within 60 seconds' }

    $env:SCOPLEN_NETWORK_LOSS_HOST_KEY = $hostKey
    $env:SCOPLEN_NETWORK_LOSS_PORT = $port.ToString()
    & cargo run --quiet --locked --manifest-path (Join-Path $repository 'Cargo.toml') -p scoplen-ssh --example network_loss_interop
    if ($LASTEXITCODE -ne 0) { throw "OpenSSH network-loss interop failed (exit $LASTEXITCODE)" }
}
catch {
    if ($started) { docker logs --tail 35 $container 2>&1 | Write-Warning }
    throw
}
finally {
    if ($started) {
        $owner = docker inspect --format '{{index .Config.Labels "scoplen.fixture.owner"}}' $container 2>$null
        if ($LASTEXITCODE -eq 0 -and $owner -eq $container) { docker rm -f $container 2>$null | Out-Null }
    }
    foreach ($name in $variables) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
}
