# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$container = 'scoplen-openssh-interop-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$started = $false
$testVariables = @(
    'SCOPLEN_OPENSSH_HOST', 'SCOPLEN_OPENSSH_PORT', 'SCOPLEN_OPENSSH_USER',
    'SCOPLEN_OPENSSH_PASSWORD', 'SCOPLEN_OPENSSH_HOST_KEY', 'SCOPLEN_OPENSSH_HOST_CA_KEY',
    'SCOPLEN_OPENSSH_RSA_KEY', 'SCOPLEN_OPENSSH_ED25519_KEY', 'SCOPLEN_OPENSSH_P256_KEY',
    'SCOPLEN_OPENSSH_USER_CERT', 'SCOPLEN_OPENSSH_USER_CA_KEY',
    'SCOPLEN_OPENSSH_SFTP', 'SCOPLEN_OPENSSH_FORWARD'
)
foreach ($name in $testVariables) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }

try {
    $setup = "apk add --no-cache openssh-server && adduser -D scoplen && printf 'scoplen:scoplen-test-password\n' | chpasswd && ssh-keygen -q -t ed25519 -N '' -f /tmp/host_key && mkdir -p /run/sshd && printf 'Port 2222\nListenAddress 0.0.0.0\nHostKey /tmp/host_key\nPasswordAuthentication yes\nAllowTcpForwarding yes\nSubsystem sftp internal-sftp\n' > /tmp/sshd_config && exec /usr/sbin/sshd -D -e -f /tmp/sshd_config"
    docker run -d --rm --name $container -p '127.0.0.1::2222' alpine:3.21 sh -c $setup | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to start disposable OpenSSH container' }
    $started = $true

    $port = docker port $container '2222/tcp'
    if ($LASTEXITCODE -ne 0 -or $port -notmatch '^127\.0\.0\.1:(\d+)$') {
        throw 'Disposable OpenSSH port was not published on loopback'
    }
    $port = [int]$Matches[1]
    $ready = $false
    $hostKey = $null
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $hostKey = docker exec $container cat /tmp/host_key.pub 2>$null
        if ($LASTEXITCODE -ne 0 -or $hostKey -notmatch '^ssh-ed25519 ') {
            Start-Sleep -Seconds 1
            continue
        }
        docker exec $container pidof sshd 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
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
    $env:SCOPLEN_OPENSSH_HOST = '127.0.0.1'
    $env:SCOPLEN_OPENSSH_PORT = $port.ToString()
    $env:SCOPLEN_OPENSSH_USER = 'scoplen'
    $env:SCOPLEN_OPENSSH_PASSWORD = 'scoplen-test-password'
    $env:SCOPLEN_OPENSSH_HOST_KEY = $hostKey
    $env:SCOPLEN_OPENSSH_SFTP = '1'
    $env:SCOPLEN_OPENSSH_FORWARD = '1'

    cargo run --quiet --locked -p scoplen-ssh --example openssh_interop
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSH SFTP or forwarding interop failed' }
    cargo run --quiet --locked -p scoplen-ssh --example proxy_command_interop
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSH ProxyCommand interop failed' }

    $env:SCOPLEN_OPENSSH_PASSWORD = 'wrong-password'
    cargo run --quiet --locked -p scoplen-ssh --example openssh_interop 2>$null
    if ($LASTEXITCODE -eq 0) { throw 'OpenSSH accepted an incorrect password' }
    Write-Output 'OpenSSH SFTP, forwarding, ProxyCommand, and wrong-password interop passed'
}
finally {
    if ($started) { docker stop $container | Out-Null }
    foreach ($name in $testVariables) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
}
