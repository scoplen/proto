# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$container = 'scoplen-openssh-8-interop-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/')
$tempRoot = [System.IO.Path]::GetFullPath((Join-Path $tempBase ('scoplen-openssh-8-keys-' + [guid]::NewGuid().ToString('N'))))
$started = $false
$testVariables = @(
    'SCOPLEN_OPENSSH_HOST', 'SCOPLEN_OPENSSH_PORT', 'SCOPLEN_OPENSSH_USER',
    'SCOPLEN_OPENSSH_PASSWORD', 'SCOPLEN_OPENSSH_HOST_KEY', 'SCOPLEN_OPENSSH_HOST_CA_KEY',
    'SCOPLEN_OPENSSH_RSA_KEY', 'SCOPLEN_OPENSSH_RSA_HASH', 'SCOPLEN_OPENSSH_ED25519_KEY',
    'SCOPLEN_OPENSSH_P256_KEY', 'SCOPLEN_OPENSSH_ECDSA_KEY', 'SCOPLEN_OPENSSH_USER_CERT',
    'SCOPLEN_OPENSSH_USER_CA_KEY', 'SCOPLEN_OPENSSH_SFTP', 'SCOPLEN_OPENSSH_FORWARD',
    'SCOPLEN_OPENSSH_JUMP_TARGET_PORT'
)
foreach ($name in $testVariables) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }

function Invoke-Interop {
    param([string]$caseName, [string]$expectedError = '')

    $output = & cargo run --quiet --locked -p scoplen-ssh --example openssh_interop 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    if ($expectedError) {
        if ($exitCode -eq 0 -or $output -notmatch [regex]::Escape($expectedError)) {
            throw "OpenSSH 8.8p1 $caseName did not reject as expected (exit $exitCode)"
        }
    }
    elseif ($exitCode -ne 0 -or $output -notmatch '(?m)^openssh interop ok\s*$') {
        throw "OpenSSH 8.8p1 $caseName failed (exit $exitCode)"
    }
    Write-Output "OpenSSH 8.8p1 ${caseName}: passed"
}

try {
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    $setup = @'
set -eu
apk add --no-cache openssh-server=8.8_p1-r1
adduser -D scoplen
printf 'scoplen:scoplen-test-password\n' | chpasswd
ssh-keygen -q -t ed25519 -N '' -f /tmp/host_key
ssh-keygen -q -t ed25519 -N '' -f /tmp/other_host_key
ssh-keygen -q -t ed25519 -N '' -f /tmp/user_ed
ssh-keygen -q -t ed25519 -N '' -f /tmp/other_user_ed
ssh-keygen -q -t rsa -b 3072 -N '' -f /tmp/user_rsa
ssh-keygen -q -t rsa -b 3072 -N '' -f /tmp/other_user_rsa
mkdir -p /home/scoplen/.ssh /run/sshd
cat /tmp/user_ed.pub /tmp/user_rsa.pub > /home/scoplen/.ssh/authorized_keys
chown -R scoplen:scoplen /home/scoplen/.ssh
chmod 700 /home/scoplen/.ssh
chmod 600 /home/scoplen/.ssh/authorized_keys
cat > /tmp/sshd_config <<'SSHD'
Port 2222
ListenAddress 0.0.0.0
HostKey /tmp/host_key
PasswordAuthentication yes
PubkeyAuthentication yes
LogLevel VERBOSE
SSHD
/usr/sbin/sshd -t -f /tmp/sshd_config
exec /usr/sbin/sshd -D -e -f /tmp/sshd_config
'@
    $setup = $setup.Replace("`r", '')
    docker run -d --name $container -p '127.0.0.1::2222' alpine:3.15 sh -c $setup | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not start disposable OpenSSH 8.8p1 container' }
    $started = $true

    $published = docker port $container '2222/tcp'
    if ($LASTEXITCODE -ne 0 -or $published -notmatch '^127\.0\.0\.1:(\d+)$') {
        throw 'OpenSSH 8.8p1 was not published on loopback'
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
            $socket.ReceiveTimeout = 2000
            $reader = [System.IO.StreamReader]::new($socket.GetStream())
            $banner = $reader.ReadLine()
            $ready = $true
        }
        catch { Start-Sleep -Seconds 1 }
        finally { $socket.Dispose() }
        if ($ready) { break }
    }
    if (-not $ready) { throw 'OpenSSH 8.8p1 did not become ready within 60 seconds' }
    $package = docker exec $container apk list --installed openssh-server
    if ($LASTEXITCODE -ne 0 -or ($package | Out-String).Trim() -notmatch '^openssh-server-8\.8_p1-r1 ' -or
        $banner -notmatch '^SSH-2\.0-OpenSSH_8\.8(?:\r)?$') {
        throw "Unexpected OpenSSH 8.8p1 package or SSH banner: $package; $banner"
    }
    Write-Output "OpenSSH package $package; banner $banner"

    foreach ($name in @('user_ed', 'other_user_ed', 'user_rsa', 'other_user_rsa')) {
        docker cp "${container}:/tmp/$name" (Join-Path $tempRoot $name) | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not copy disposable $name identity" }
    }
    $otherHostKey = docker exec $container cat /tmp/other_host_key.pub
    if ($LASTEXITCODE -ne 0 -or $otherHostKey -notmatch '^ssh-ed25519 ') {
        throw 'Could not read unrelated OpenSSH host key'
    }

    $env:SCOPLEN_OPENSSH_HOST = '127.0.0.1'
    $env:SCOPLEN_OPENSSH_PORT = $port.ToString()
    $env:SCOPLEN_OPENSSH_USER = 'scoplen'
    $env:SCOPLEN_OPENSSH_HOST_KEY = $hostKey
    $env:SCOPLEN_OPENSSH_PASSWORD = 'scoplen-test-password'
    Invoke-Interop 'password and command'

    $env:SCOPLEN_OPENSSH_PASSWORD = 'wrong-password'
    Invoke-Interop 'wrong password' 'AuthenticationRejected'
    Remove-Item Env:SCOPLEN_OPENSSH_PASSWORD

    $env:SCOPLEN_OPENSSH_ED25519_KEY = Join-Path $tempRoot 'user_ed'
    Invoke-Interop 'Ed25519 key and command'
    $env:SCOPLEN_OPENSSH_ED25519_KEY = Join-Path $tempRoot 'other_user_ed'
    Invoke-Interop 'unauthorized Ed25519 key' 'AuthenticationRejected'
    Remove-Item Env:SCOPLEN_OPENSSH_ED25519_KEY

    $env:SCOPLEN_OPENSSH_RSA_KEY = Join-Path $tempRoot 'user_rsa'
    foreach ($hash in @('256', '512')) {
        $env:SCOPLEN_OPENSSH_RSA_HASH = $hash
        Invoke-Interop "RSA-SHA2-$hash key and command"
    }
    $env:SCOPLEN_OPENSSH_RSA_KEY = Join-Path $tempRoot 'other_user_rsa'
    Invoke-Interop 'unauthorized RSA key' 'AuthenticationRejected'
    Remove-Item Env:SCOPLEN_OPENSSH_RSA_KEY, Env:SCOPLEN_OPENSSH_RSA_HASH

    $env:SCOPLEN_OPENSSH_PASSWORD = 'scoplen-test-password'
    $env:SCOPLEN_OPENSSH_HOST_KEY = $otherHostKey
    Invoke-Interop 'untrusted host key' 'unexpected server key'
    Write-Output 'OpenSSH 8.8p1 public client authentication and command interoperability passed'
}
catch {
    if ($started) {
        $state = docker inspect --format '{{.State.Status}} exit={{.State.ExitCode}}' $container 2>$null
        if ($LASTEXITCODE -eq 0) { Write-Warning "Disposable OpenSSH state: $state" }
        $logs = docker logs --tail 30 $container 2>&1
        if ($LASTEXITCODE -eq 0 -and $logs) { Write-Warning "Disposable OpenSSH log:`n$($logs | Out-String)" }
    }
    throw
}
finally {
    if ($started) { docker rm -f $container 2>$null | Out-Null }
    if ([System.IO.Path]::GetDirectoryName($tempRoot) -eq $tempBase -and
        [System.IO.Path]::GetFileName($tempRoot).StartsWith('scoplen-openssh-8-keys-', [System.StringComparison]::Ordinal) -and
        (Test-Path -LiteralPath $tempRoot)) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
    foreach ($name in $testVariables) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
}
