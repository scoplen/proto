# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$container = 'scoplen-remote-forward-interop-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$variables = @('SCOPLEN_FORWARD_HOST_KEY', 'SCOPLEN_FORWARD_PORT', 'SCOPLEN_FORWARD_DENIED_PORT')
$saved = @{}
foreach ($name in $variables) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
$started = $false

try {
    $setup = @'
set -eu
apk add --no-cache openssh-server python3 >/dev/null
adduser -D scoplen
printf 'scoplen:fixture-forward-password\n' | chpasswd
ssh-keygen -q -t ed25519 -N '' -f /tmp/host_key
mkdir -p /run/sshd
install -d -o scoplen -g scoplen /tmp/scoplen-forward-fixture
cat > /tmp/unix-echo.py <<'PY'
import socketserver

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)

with socketserver.UnixStreamServer('/tmp/scoplen-forward-fixture/echo.sock', Echo) as server:
    server.serve_forever()
PY
su scoplen -s /bin/sh -c 'exec python3 /tmp/unix-echo.py' &
cat > /tmp/allowed.conf <<'SSHD'
Port 2222
ListenAddress 0.0.0.0
HostKey /tmp/host_key
PasswordAuthentication yes
PubkeyAuthentication no
AllowTcpForwarding yes
AllowStreamLocalForwarding yes
StreamLocalBindUnlink yes
SSHD
cat > /tmp/denied.conf <<'SSHD'
Port 2223
ListenAddress 0.0.0.0
HostKey /tmp/host_key
PasswordAuthentication yes
PubkeyAuthentication no
DisableForwarding yes
SSHD
/usr/sbin/sshd -t -f /tmp/allowed.conf
/usr/sbin/sshd -t -f /tmp/denied.conf
/usr/sbin/sshd -D -e -f /tmp/allowed.conf &
allowed=$!
/usr/sbin/sshd -D -e -f /tmp/denied.conf &
denied=$!
trap 'kill "$allowed" "$denied" 2>/dev/null || true' EXIT
wait "$allowed" "$denied"
'@
    docker run -d --name $container -p '127.0.0.1::2222' -p '127.0.0.1::2223' alpine:3.21 sh -c ($setup.Replace("`r", '')) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not start disposable forwarding fixture' }
    $started = $true
    $ports = @()
    foreach ($internal in @('2222/tcp', '2223/tcp')) {
        $published = docker port $container $internal
        if ($LASTEXITCODE -ne 0 -or $published -notmatch '^127\.0\.0\.1:(\d+)$') {
            throw "Fixture port $internal was not published on loopback"
        }
        $ports += [int]$Matches[1]
    }
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        docker exec $container sh -c 'test -S /tmp/scoplen-forward-fixture/echo.sock && test "$(pidof sshd | wc -w)" -eq 2' 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw 'Forwarding fixture did not become ready within 60 seconds' }
    $env:SCOPLEN_FORWARD_HOST_KEY = docker exec $container cat /tmp/host_key.pub
    if ($LASTEXITCODE -ne 0) { throw 'Could not read fixture public host key' }
    $env:SCOPLEN_FORWARD_PORT = $ports[0].ToString()
    $env:SCOPLEN_FORWARD_DENIED_PORT = $ports[1].ToString()
    & cargo run --quiet --locked --manifest-path (Join-Path $repository 'Cargo.toml') -p scoplen-ssh --example remote_forwarding_interop
    if ($LASTEXITCODE -ne 0) { throw "OpenSSH remote forwarding failed (exit $LASTEXITCODE)" }
}
catch {
    if ($started) { docker logs --tail 35 $container 2>&1 | Write-Warning }
    throw
}
finally {
    if ($started) { docker rm -f $container 2>$null | Out-Null }
    foreach ($name in $variables) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
}
