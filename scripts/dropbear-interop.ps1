# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$container = 'scoplen-dropbear-interop-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$started = $false
$testVariables = @(
    'SCOPLEN_OPENSSH_HOST', 'SCOPLEN_OPENSSH_PORT', 'SCOPLEN_OPENSSH_USER',
    'SCOPLEN_OPENSSH_PASSWORD', 'SCOPLEN_OPENSSH_HOST_KEY', 'SCOPLEN_OPENSSH_HOST_CA_KEY',
    'SCOPLEN_OPENSSH_RSA_KEY', 'SCOPLEN_OPENSSH_ED25519_KEY', 'SCOPLEN_OPENSSH_P256_KEY',
    'SCOPLEN_OPENSSH_USER_CERT', 'SCOPLEN_OPENSSH_USER_CA_KEY',
    'SCOPLEN_OPENSSH_SFTP', 'SCOPLEN_OPENSSH_SFTP_PROFILE', 'SCOPLEN_OPENSSH_FORWARD'
)
foreach ($name in $testVariables) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }

try {
    $setup = "set -eu; apk add --no-cache dropbear=2024.86-r0 openssh-sftp-server=9.9_p2-r0; test -x /usr/lib/ssh/sftp-server; adduser -D scoplen; printf 'scoplen:scoplen-test-password\n' | chpasswd; dropbearkey -t ed25519 -f /tmp/host_key; exec dropbear -F -E -p 2222 -r /tmp/host_key"
    docker run -d --rm --name $container -p '127.0.0.1::2222' alpine:3.21 sh -c $setup | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to start disposable Dropbear container' }
    $started = $true

    $hostKey = $null
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $lines = docker exec $container dropbearkey -y -f /tmp/host_key 2>$null
        if ($LASTEXITCODE -eq 0) {
            $hostKey = $lines | Where-Object { $_ -match '^ssh-ed25519 ' } | Select-Object -First 1
            if ($hostKey) { break }
        }
        Start-Sleep -Seconds 1
    }
    if (-not $hostKey) { throw 'Dropbear did not become ready within 60 seconds' }

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
    $env:SCOPLEN_OPENSSH_USER = 'scoplen'
    $env:SCOPLEN_OPENSSH_PASSWORD = 'scoplen-test-password'
    $env:SCOPLEN_OPENSSH_HOST_KEY = $hostKey
    $env:SCOPLEN_OPENSSH_SFTP = '1'
    $env:SCOPLEN_OPENSSH_SFTP_PROFILE = 'dropbear-2024.86'

    $output = & cargo run --quiet --locked -p scoplen-ssh --example openssh_interop 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or $output -notmatch '(?m)^dropbear sftp interop ok\s*$' -or
        $output -notmatch '(?m)^openssh interop ok\s*$') {
        throw "Dropbear password and SFTP workflow failed: $output"
    }

    $env:SCOPLEN_OPENSSH_PASSWORD = 'wrong-password'
    cargo run --quiet --locked -p scoplen-ssh --example openssh_interop 2>$null
    if ($LASTEXITCODE -eq 0) { throw 'Dropbear accepted an incorrect password' }

    docker exec $container dropbearkey -t ed25519 -f /tmp/wrong_host_key 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to generate an unrelated host key' }
    $wrongHostKey = docker exec $container dropbearkey -y -f /tmp/wrong_host_key 2>$null |
        Where-Object { $_ -match '^ssh-ed25519 ' } | Select-Object -First 1
    if ($LASTEXITCODE -ne 0 -or -not $wrongHostKey) { throw 'Failed to read unrelated host key' }
    $env:SCOPLEN_OPENSSH_HOST_KEY = $wrongHostKey
    $env:SCOPLEN_OPENSSH_PASSWORD = 'scoplen-test-password'
    cargo run --quiet --locked -p scoplen-ssh --example openssh_interop 2>$null
    if ($LASTEXITCODE -eq 0) { throw 'Client accepted an unrelated Dropbear host key' }

    Write-Output 'Dropbear password, SFTP, wrong-password, and wrong-host-key interop passed'
}
finally {
    if ($started) { docker stop $container | Out-Null }
    foreach ($name in $testVariables) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
}
