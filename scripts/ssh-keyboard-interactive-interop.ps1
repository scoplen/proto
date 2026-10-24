# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$container = 'scoplen-interactive-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$variables = @('SCOPLEN_INTERACTIVE_PORT', 'SCOPLEN_INTERACTIVE_HOST_KEY', 'SCOPLEN_INTERACTIVE_PASSWORD')
$saved = @{}
foreach ($name in $variables) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
$started = $false

try {
    $setup = @'
set -eu
apk add --no-cache openssh-server-pam=9.9_p2-r0 linux-pam=1.6.1-r1 >/dev/null
apk info -v | grep -Fx 'openssh-server-pam-9.9_p2-r0'
apk info -v | grep -Fx 'linux-pam-1.6.1-r1'
adduser -D scoplen
printf 'scoplen:fixture-interactive-password\n' | chpasswd
ssh-keygen -q -t ed25519 -N '' -f /tmp/host_key
mkdir -p /run/sshd
cat > /etc/pam.d/sshd <<'PAM'
auth required pam_unix.so
account required pam_unix.so
session required pam_unix.so
PAM
cat > /tmp/sshd.conf <<'SSHD'
Port 2222
ListenAddress 0.0.0.0
HostKey /tmp/host_key
UsePAM yes
KbdInteractiveAuthentication yes
PasswordAuthentication no
PubkeyAuthentication no
AuthenticationMethods keyboard-interactive
PermitEmptyPasswords no
PerSourcePenalties no
SSHD
/usr/sbin/sshd.pam -t -f /tmp/sshd.conf
/usr/sbin/sshd.pam -T -f /tmp/sshd.conf > /tmp/effective.conf
grep -Fx 'usepam yes' /tmp/effective.conf
grep -Fx 'kbdinteractiveauthentication yes' /tmp/effective.conf
grep -Fx 'passwordauthentication no' /tmp/effective.conf
grep -Fx 'pubkeyauthentication no' /tmp/effective.conf
grep -Fx 'authenticationmethods keyboard-interactive' /tmp/effective.conf
exec /usr/sbin/sshd.pam -D -e -f /tmp/sshd.conf
'@
    docker run -d --name $container --label "scoplen.fixture.owner=$container" -p '127.0.0.1::2222' alpine:3.21 sh -c ($setup.Replace("`r", '')) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not start disposable OpenSSH/PAM listener' }
    $started = $true
    $published = docker port $container '2222/tcp'
    if ($LASTEXITCODE -ne 0 -or $published -notmatch '^127\.0\.0\.1:(\d+)$') {
        throw 'Disposable OpenSSH/PAM port was not published on loopback'
    }
    $port = [int]$Matches[1]
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $state = docker inspect --format '{{.State.Status}}' $container 2>$null
        if ($LASTEXITCODE -eq 0 -and $state -in @('exited', 'dead')) {
            throw 'Disposable OpenSSH/PAM exited before readiness'
        }
        $hostKey = docker exec $container cat /tmp/host_key.pub 2>$null
        if ($LASTEXITCODE -ne 0 -or $hostKey -notmatch '^ssh-ed25519 ') {
            Start-Sleep -Seconds 1
            continue
        }
        $socket = [System.Net.Sockets.TcpClient]::new()
        try {
            $socket.ReceiveTimeout = 1000
            $socket.Connect('127.0.0.1', $port)
            $reader = [System.IO.StreamReader]::new($socket.GetStream())
            $banner = $reader.ReadLine()
            if ($banner -notmatch '^SSH-2\.0-OpenSSH_9\.9$') { throw 'Unexpected OpenSSH/PAM banner' }
            $ready = $true
        }
        catch { Start-Sleep -Seconds 1 }
        finally { $socket.Dispose() }
        if ($ready) { break }
    }
    if (-not $ready) { throw 'Pinned OpenSSH/PAM did not become ready within 60 seconds' }
    $env:SCOPLEN_INTERACTIVE_PORT = $port.ToString()
    $env:SCOPLEN_INTERACTIVE_HOST_KEY = $hostKey
    $env:SCOPLEN_INTERACTIVE_PASSWORD = 'fixture-interactive-password'
    & cargo run --quiet --locked --manifest-path (Join-Path $repository 'Cargo.toml') -p scoplen-ssh --example keyboard_interactive_interop
    if ($LASTEXITCODE -ne 0) { throw "OpenSSH/PAM keyboard-interactive interop failed (exit $LASTEXITCODE)" }
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
