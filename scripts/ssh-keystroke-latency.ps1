# SPDX-License-Identifier: Apache-2.0

param([string]$Image = 'alpine:3.21')

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$repo = Split-Path -Parent $PSScriptRoot
$temporaryRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$temporary = Join-Path $temporaryRoot ('scoplen-ssh-latency-' + [guid]::NewGuid().ToString('N'))
$key = Join-Path $temporary 'user_key'
$knownHosts = Join-Path $temporary 'known_hosts'
$sshConfig = Join-Path $temporary 'ssh_config'
$names = @(
    'SCOPLEN_BENCH_HOST', 'SCOPLEN_BENCH_PORT', 'SCOPLEN_BENCH_USER',
    'SCOPLEN_BENCH_KEY', 'SCOPLEN_BENCH_HOST_KEY', 'SCOPLEN_BENCH_KNOWN_HOSTS',
    'SCOPLEN_BENCH_SSH_CONFIG', 'SCOPLEN_BENCH_CIPHER', 'SCOPLEN_BENCH_SSH'
)
$previous = @{}
foreach ($name in $names) {
    $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

function Remove-DisposableContainer {
    param([string]$Name, [bool]$WasStarted)

    $owner = (docker inspect --format '{{ index .Config.Labels "com.scoplen.latency-run" }}' $Name 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        if ($WasStarted) { throw "Could not inspect disposable container before cleanup: $Name" }
        return
    }
    if ($owner -ne $Name) { throw "Refusing to remove an unowned container: $Name" }
    docker rm -f $Name | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to remove disposable container: $Name" }
}

foreach ($program in @('docker', 'ssh', 'ssh-keygen', 'cargo')) {
    if (-not (Get-Command $program -ErrorAction SilentlyContinue)) {
        throw "Required program is missing: $program"
    }
}
$container = $null
$containerStarted = $false
try {
    New-Item -ItemType Directory -Path $temporary | Out-Null
    [System.IO.File]::WriteAllText($sshConfig, '')
    ssh-keygen -q -t ed25519 -N '' -f $key
    if ($LASTEXITCODE -ne 0) { throw 'Failed to create disposable Ed25519 user key' }

    Push-Location $repo
    try {
        cargo build --release --locked -p scoplen-ssh --example keystroke_latency
        if ($LASTEXITCODE -ne 0) { throw 'Failed to build release keystroke comparison' }
    }
    finally {
        Pop-Location
    }

    $binary = Join-Path $repo 'target/release/examples/keystroke_latency'
    if ($IsWindows) { $binary += '.exe' }
    $ssh = (Get-Command ssh).Source
    $sshVersion = (& $ssh -V 2>&1 | Out-String).Trim()
    $cpu = if ($IsWindows) {
        (Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name).Trim()
    }
    elseif (Get-Command lscpu -ErrorAction SilentlyContinue) {
        (& lscpu | Select-String '^Model name:' | Select-Object -First 1).ToString().Trim()
    }
    else {
        'unavailable'
    }
    Write-Output "host_os=$($PSVersionTable.OS)"
    Write-Output "host_cpu=$cpu"
    Write-Output "openssh_client=$sshVersion"
    $revision = (git -C $repo rev-parse --short HEAD | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Failed to read benchmark source revision' }
    $worktreeChanges = @(git -C $repo status --porcelain)
    if ($LASTEXITCODE -ne 0) { throw 'Failed to read benchmark worktree status' }
    Write-Output "scoplen_revision=$revision"
    Write-Output "scoplen_worktree_dirty=$(($worktreeChanges.Count -ne 0).ToString().ToLowerInvariant())"

    foreach ($cipher in @('chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com')) {
        $container = 'scoplen-ssh-latency-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
        $setup = @"
set -eu
apk add --no-cache openssh-server=9.9_p2-r0 >/dev/null
adduser -D scoplen
passwd -d scoplen >/dev/null
mkdir -p /home/scoplen/.ssh /run/sshd
chmod 700 /home/scoplen/.ssh
ssh-keygen -q -t ed25519 -N '' -f /tmp/host_key
cat > /tmp/sshd_config <<'SSHD'
Port 2222
ListenAddress 0.0.0.0
HostKey /tmp/host_key
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin no
PermitTTY no
AllowTcpForwarding no
Compression no
Ciphers $cipher
Subsystem sftp internal-sftp
SSHD
exec /usr/sbin/sshd -D -e -f /tmp/sshd_config
"@
        $setup = $setup.Replace("`r", '')
        try {
            docker run -d --name $container --label "com.scoplen.latency-run=$container" -p '127.0.0.1::2222' $Image sh -c $setup | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Failed to start disposable OpenSSH server' }
            $containerStarted = $true
            $port = $null
            for ($attempt = 0; $attempt -lt 60; $attempt++) {
                $published = docker port $container '2222/tcp' 2>$null
                if ($LASTEXITCODE -eq 0 -and $published -match '^127\.0\.0\.1:(\d+)$') {
                    $port = [int]$Matches[1]
                    break
                }
                $running = (docker inspect --format '{{.State.Running}}' $container | Out-String).Trim()
                if ($running -ne 'true') {
                    $startupLog = (docker logs $container 2>&1 | Out-String).Trim()
                    throw "Disposable OpenSSH exited before publishing its port: $startupLog"
                }
                Start-Sleep -Seconds 1
            }
            if (-not $port) { throw 'Disposable OpenSSH port was not published within 60 seconds' }
            $hostKey = $null
            for ($attempt = 0; $attempt -lt 60; $attempt++) {
                $hostKey = (docker exec $container cat /tmp/host_key.pub 2>$null | Out-String).Trim()
                if ($LASTEXITCODE -eq 0 -and $hostKey -match '^ssh-ed25519 ') { break }
                Start-Sleep -Seconds 1
            }
            if ($hostKey -notmatch '^ssh-ed25519 ') {
                throw 'Disposable OpenSSH server did not become ready within 60 seconds'
            }
            docker cp "$key.pub" ('{0}:/tmp/user_key.pub' -f $container) | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Failed to copy disposable public key' }
            docker exec $container sh -c 'cat /tmp/user_key.pub > /home/scoplen/.ssh/authorized_keys && chown -R scoplen:scoplen /home/scoplen/.ssh && chmod 600 /home/scoplen/.ssh/authorized_keys' | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Failed to authorize disposable public key' }
            $keyFields = $hostKey -split '\s+'
            [System.IO.File]::WriteAllText(
                $knownHosts,
                ('[127.0.0.1]:{0} {1} {2}' -f $port, $keyFields[0], $keyFields[1]) + "`n"
            )

            $env:SCOPLEN_BENCH_HOST = '127.0.0.1'
            $env:SCOPLEN_BENCH_PORT = $port.ToString()
            $env:SCOPLEN_BENCH_USER = 'scoplen'
            $env:SCOPLEN_BENCH_KEY = $key
            $env:SCOPLEN_BENCH_HOST_KEY = $hostKey
            $env:SCOPLEN_BENCH_KNOWN_HOSTS = $knownHosts
            $env:SCOPLEN_BENCH_SSH_CONFIG = $sshConfig
            $env:SCOPLEN_BENCH_CIPHER = $cipher
            $env:SCOPLEN_BENCH_SSH = $ssh

            $imageId = (docker inspect --format '{{.Image}}' $container | Out-String).Trim()
            $serverVersion = (docker exec $container /usr/sbin/sshd -V 2>&1 | Out-String).Trim()
            Write-Output "server_cipher=$cipher container_image=$imageId server=$serverVersion"
            & $binary --openssh
            if ($LASTEXITCODE -ne 0) { throw "Keystroke comparison failed for $cipher" }
        }
        finally {
            Remove-DisposableContainer -Name $container -WasStarted $containerStarted
            $containerStarted = $false
            $container = $null
        }
    }
}
finally {
    try {
        if ($container) { Remove-DisposableContainer -Name $container -WasStarted $containerStarted }
    }
    finally {
        foreach ($name in $names) {
            [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process')
        }
        if (Test-Path -LiteralPath $temporary) {
            $resolved = [System.IO.Path]::GetFullPath($temporary)
            if (-not $resolved.StartsWith($temporaryRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
                -not (Split-Path -Leaf $resolved).StartsWith('scoplen-ssh-latency-')) {
                throw 'Refusing to remove a temporary path outside the expected directory'
            }
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
    }
}
