# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$owner = [guid]::NewGuid().ToString('N')
$container = 'scoplen-dropbear-interop-' + $owner.Substring(0, 12)
$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$started = $false
$completed = $false
$testVariables = @(
    'SCOPLEN_OPENSSH_HOST', 'SCOPLEN_OPENSSH_PORT', 'SCOPLEN_OPENSSH_USER',
    'SCOPLEN_OPENSSH_PASSWORD', 'SCOPLEN_OPENSSH_HOST_KEY', 'SCOPLEN_OPENSSH_HOST_CA_KEY',
    'SCOPLEN_OPENSSH_RSA_KEY', 'SCOPLEN_OPENSSH_RSA_HASH',
    'SCOPLEN_OPENSSH_ED25519_KEY', 'SCOPLEN_OPENSSH_P256_KEY', 'SCOPLEN_OPENSSH_ECDSA_KEY',
    'SCOPLEN_OPENSSH_USER_CERT', 'SCOPLEN_OPENSSH_USER_CA_KEY',
    'SCOPLEN_OPENSSH_SFTP', 'SCOPLEN_OPENSSH_SFTP_PROFILE', 'SCOPLEN_OPENSSH_FORWARD',
    'SCOPLEN_OPENSSH_SHARED_CONNECTION', 'SCOPLEN_DROPBEAR_FORWARD_DENIED_PORT'
)
$savedVariables = @{}
foreach ($name in $testVariables) {
    $savedVariables[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    Remove-Item "Env:$name" -ErrorAction SilentlyContinue
}

try {
    $setup = @'
set -eu
apk add --no-cache dropbear=2024.86-r0 openssh-sftp-server=9.9_p2-r0 python3
test -x /usr/lib/ssh/sftp-server
adduser -D scoplen
printf 'scoplen:scoplen-test-password\n' | chpasswd
dropbearkey -t ed25519 -f /tmp/host_key
cat > /tmp/forward-echo.py <<'PY'
import socketserver
import threading

barrier = threading.Barrier(2, timeout=10)

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        total = 0
        first = True
        while True:
            data = self.request.recv(32768)
            if not data:
                self.request.sendall(b'\0scoplen-forward-eof\xff')
                return
            total += len(data)
            if total > 262144:
                raise ValueError('fixture payload limit exceeded')
            if first:
                barrier.wait()
                first = False
            self.request.sendall(data)

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

with Server(('127.0.0.1', 2444), Echo) as server:
    open('/tmp/forward-echo-ready', 'x').close()
    server.serve_forever()
PY
python3 /tmp/forward-echo.py &
echo_server=$!
dropbear -F -E -p 2222 -r /tmp/host_key &
allowed=$!
dropbear -F -E -j -p 2223 -r /tmp/host_key &
denied=$!
trap 'kill "$echo_server" "$allowed" "$denied" 2>/dev/null || true' EXIT
wait "$echo_server" "$allowed" "$denied"
'@
    docker run -d --name $container --label "scoplen.fixture.owner=$owner" -p '127.0.0.1::2222' -p '127.0.0.1::2223' alpine:3.21 sh -c ($setup.Replace("`r", '')) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to start disposable Dropbear container' }
    $started = $true

    $hostKey = $null
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        docker exec $container sh -c 'test -f /tmp/forward-echo-ready && test "$(pidof dropbear | wc -w)" -eq 2' 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { Start-Sleep -Seconds 1; continue }
        $lines = docker exec $container dropbearkey -y -f /tmp/host_key 2>$null
        if ($LASTEXITCODE -eq 0) {
            $hostKey = $lines | Where-Object { $_ -match '^ssh-ed25519 ' } | Select-Object -First 1
            if ($hostKey) { break }
        }
        Start-Sleep -Seconds 1
    }
    if (-not $hostKey) { throw 'Dropbear did not become ready within 120 seconds' }

    $packages = docker exec $container apk info -v
    if ($LASTEXITCODE -ne 0 -or $packages -notcontains 'dropbear-2024.86-r0' -or
        $packages -notcontains 'openssh-sftp-server-9.9_p2-r0') {
        throw 'Disposable Dropbear or SFTP server package version differed from the pinned fixture'
    }

    $port = docker port $container '2222/tcp'
    if ($LASTEXITCODE -ne 0 -or $port -notmatch '^127\.0\.0\.1:(\d+)$') {
        throw 'Disposable Dropbear port was not published on loopback'
    }
    $env:SCOPLEN_OPENSSH_HOST = '127.0.0.1'
    $env:SCOPLEN_OPENSSH_PORT = $Matches[1]
    $deniedPort = docker port $container '2223/tcp'
    if ($LASTEXITCODE -ne 0 -or $deniedPort -notmatch '^127\.0\.0\.1:(\d+)$') {
        throw 'Forwarding-denied Dropbear port was not published on loopback'
    }
    $env:SCOPLEN_DROPBEAR_FORWARD_DENIED_PORT = $Matches[1]
    $env:SCOPLEN_OPENSSH_USER = 'scoplen'
    $env:SCOPLEN_OPENSSH_PASSWORD = 'scoplen-test-password'
    $env:SCOPLEN_OPENSSH_HOST_KEY = $hostKey
    $env:SCOPLEN_OPENSSH_SFTP = '1'
    $env:SCOPLEN_OPENSSH_SFTP_PROFILE = 'dropbear-2024.86'
    $env:SCOPLEN_OPENSSH_FORWARD = '1'

    $output = & cargo run --quiet --locked --manifest-path (Join-Path $repository 'Cargo.toml') -p scoplen-ssh --example openssh_interop 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or $output -notmatch '(?m)^dropbear sftp interop ok\s*$' -or
        $output -notmatch '(?m)^dropbear forwarding interop ok\s*$' -or
        $output -notmatch '(?m)^openssh interop ok\s*$') {
        throw "Dropbear password, SFTP or forwarding workflow failed: $output"
    }
    $output = & cargo run --quiet --locked --manifest-path (Join-Path $repository 'Cargo.toml') -p scoplen-ssh --example dynamic_socks_interop 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or $output -notmatch '(?m)^dropbear dynamic SOCKS interop ok\s*$') {
        throw "Dropbear dynamic SOCKS workflow failed: $output"
    }

    $env:SCOPLEN_OPENSSH_PASSWORD = 'wrong-password'
    $output = & cargo run --quiet --locked --manifest-path (Join-Path $repository 'Cargo.toml') -p scoplen-ssh --example openssh_interop 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0 -or $output -notmatch 'AuthenticationRejected') {
        throw "Dropbear incorrect-password control did not report authentication rejection: $output"
    }

    docker exec $container dropbearkey -t ed25519 -f /tmp/wrong_host_key 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to generate an unrelated host key' }
    $wrongHostKey = docker exec $container dropbearkey -y -f /tmp/wrong_host_key 2>$null |
        Where-Object { $_ -match '^ssh-ed25519 ' } | Select-Object -First 1
    if ($LASTEXITCODE -ne 0 -or -not $wrongHostKey) { throw 'Failed to read unrelated host key' }
    $env:SCOPLEN_OPENSSH_HOST_KEY = $wrongHostKey
    $env:SCOPLEN_OPENSSH_PASSWORD = 'scoplen-test-password'
    $output = & cargo run --quiet --locked --manifest-path (Join-Path $repository 'Cargo.toml') -p scoplen-ssh --example openssh_interop 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0 -or $output -notmatch 'HostKey\(Rejected') {
        throw "Unrelated Dropbear host-key control did not report host verification rejection: $output"
    }

    $completed = $true
    Write-Output 'Dropbear password, SFTP, direct TCP, SOCKS4a/5, half-close, forwarding denial and rejection controls passed'
}
catch {
    if ($started) { docker logs --tail 35 $container 2>&1 | Write-Warning }
    throw
}
finally {
    foreach ($name in $testVariables) {
        [Environment]::SetEnvironmentVariable($name, $savedVariables[$name], 'Process')
    }
    if ($started) {
        $actualOwner = docker inspect --format '{{index .Config.Labels "scoplen.fixture.owner"}}' $container 2>$null
        if ($LASTEXITCODE -ne 0 -or $actualOwner -ne $owner) {
            throw 'Fixture ownership could not be confirmed; cleanup was not attempted'
        }
        if ($completed) {
            docker rm -f $container 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Successful fixture container removal failed' }
        } else {
            docker stop $container 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Warning "Failed fixture retained in stopped container $container"
            } else {
                Write-Warning "Failed fixture $container retained; its stop could not be confirmed"
            }
        }
    }
}
