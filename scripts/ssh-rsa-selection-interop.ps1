# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$container = 'scoplen-rsa-selection-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$tempRoot = [System.IO.Path]::GetFullPath((Join-Path $tempBase $container))
$variables = @(
    'SCOPLEN_RSA_SELECTION_HOST_KEY', 'SCOPLEN_RSA_SELECTION_USER_KEY',
    'SCOPLEN_RSA_SELECTION_USER', 'SCOPLEN_RSA_SELECTION_SHA256_PORT',
    'SCOPLEN_RSA_SELECTION_DUAL_PORT', 'SCOPLEN_RSA_SELECTION_SHA1_PORT'
)
$previous = @{}
foreach ($name in $variables) {
    $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$started = $false
$locationPushed = $false

try {
    Push-Location (Join-Path $PSScriptRoot '..')
    $locationPushed = $true
    New-Item -ItemType Directory -Path $tempRoot -ErrorAction Stop | Out-Null
    $setup = @'
set -eu
apk add --no-cache openssh-server
adduser -D scoplen
printf 'scoplen:scoplen-test-password\n' | chpasswd
ssh-keygen -q -t ed25519 -N '' -f /tmp/host_key
ssh-keygen -q -t rsa -b 3072 -N '' -f /tmp/user_rsa
mkdir -p /home/scoplen/.ssh /run/sshd
cp /tmp/user_rsa.pub /home/scoplen/.ssh/authorized_keys
chown -R scoplen:scoplen /home/scoplen/.ssh
chmod 700 /home/scoplen/.ssh
chmod 600 /home/scoplen/.ssh/authorized_keys
for mode in sha256 dual sha1; do
    case "$mode" in
        sha256) port=2222; algorithms='rsa-sha2-256' ;;
        dual) port=2223; algorithms='rsa-sha2-512,rsa-sha2-256' ;;
        sha1) port=2224; algorithms='ssh-rsa' ;;
    esac
    cat > "/tmp/$mode.conf" <<SSHD
Port $port
ListenAddress 0.0.0.0
HostKey /tmp/host_key
PubkeyAuthentication yes
PubkeyAcceptedAlgorithms $algorithms
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PerSourcePenalties no
LogLevel VERBOSE
SSHD
    /usr/sbin/sshd -t -f "/tmp/$mode.conf"
done
touch /tmp/rsa-selection-configured
/usr/sbin/sshd -D -e -f /tmp/sha256.conf &
/usr/sbin/sshd -D -e -f /tmp/dual.conf &
exec /usr/sbin/sshd -D -e -f /tmp/sha1.conf
'@
    docker run -d --rm --name $container --label "scoplen.fixture.owner=$container" -p '127.0.0.1::2222' -p '127.0.0.1::2223' -p '127.0.0.1::2224' alpine:3.21 sh -c ($setup.Replace("`r", '')) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not start disposable OpenSSH listeners' }
    $started = $true

    $ports = @{}
    foreach ($serverPort in @(2222, 2223, 2224)) {
        $published = docker port $container "$serverPort/tcp"
        if ($LASTEXITCODE -ne 0 -or $published -notmatch '^127\.0\.0\.1:(\d+)$') {
            throw "OpenSSH listener $serverPort was not published on loopback"
        }
        $ports[$serverPort] = [int]$Matches[1]
    }
    $ready = $false
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while ([DateTime]::UtcNow -lt $deadline) {
        $hostKey = docker exec $container sh -c 'test -f /tmp/rsa-selection-configured && cat /tmp/host_key.pub' 2>$null
        if ($LASTEXITCODE -ne 0 -or $hostKey -notmatch '^ssh-ed25519 ') {
            Start-Sleep -Seconds 1
            continue
        }
        $ready = $true
        foreach ($port in $ports.Values) {
            $socket = [System.Net.Sockets.TcpClient]::new()
            try {
                $socket.Connect('127.0.0.1', $port)
                $socket.ReceiveTimeout = 1000
                $stream = $socket.GetStream()
                $banner = [System.Text.StringBuilder]::new()
                while ($banner.Length -lt 256) {
                    $value = $stream.ReadByte()
                    if ($value -lt 0 -or $value -eq 10) { break }
                    [void]$banner.Append([char]$value)
                }
                if ($banner.ToString() -notmatch '^SSH-2\.0-OpenSSH_[^\r\n]+\r?$') {
                    $ready = $false
                }
            }
            catch { $ready = $false }
            finally { $socket.Dispose() }
        }
        if ($ready) { break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) {
        docker logs --tail 20 $container
        throw 'OpenSSH listeners did not become ready within 60 seconds'
    }

    $userKey = Join-Path $tempRoot 'user_rsa'
    docker cp "${container}:/tmp/user_rsa" $userKey | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not copy disposable RSA key' }
    $env:SCOPLEN_RSA_SELECTION_HOST_KEY = $hostKey
    $env:SCOPLEN_RSA_SELECTION_USER_KEY = $userKey
    $env:SCOPLEN_RSA_SELECTION_USER = 'scoplen'
    $env:SCOPLEN_RSA_SELECTION_SHA256_PORT = $ports[2222].ToString()
    $env:SCOPLEN_RSA_SELECTION_DUAL_PORT = $ports[2223].ToString()
    $env:SCOPLEN_RSA_SELECTION_SHA1_PORT = $ports[2224].ToString()
    cargo run --quiet --locked -p scoplen-ssh --example rsa_selection_interop
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSH RSA selection interop failed' }
}
finally {
    if ($started) {
        $owner = docker inspect --format '{{index .Config.Labels "scoplen.fixture.owner"}}' $container 2>$null
        if ($LASTEXITCODE -eq 0 -and $owner -eq $container) { docker stop $container | Out-Null }
    }
    if (Test-Path -LiteralPath $tempRoot) {
        $resolved = (Resolve-Path -LiteralPath $tempRoot).Path
        if ($resolved -eq $tempRoot -and
            $resolved.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force
        }
    }
    foreach ($name in $variables) {
        [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process')
    }
    if ($locationPushed) { Pop-Location }
}
