# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$container = 'scoplen-modern-algorithms-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$started = $false
$testVariables = @(
    'SCOPLEN_ALGORITHM_MATRIX', 'SCOPLEN_ALGORITHM_HOST_KEY',
    'SCOPLEN_ALGORITHM_USER', 'SCOPLEN_ALGORITHM_PASSWORD'
)
$etm256 = 'hmac-sha2-256-etm@openssh.com'
$etm512 = 'hmac-sha2-512-etm@openssh.com'
$cases = @(
    @{ Name = 'curve25519'; Kex = 'curve25519-sha256'; Cipher = 'aes256-ctr'; Mac = $etm256; Compression = 'no'; Expected = 'none'; Policy = 'default' },
    @{ Name = 'mlkem'; Kex = 'mlkem768x25519-sha256'; Cipher = 'aes256-ctr'; Mac = $etm256; Compression = 'no'; Expected = 'none'; Policy = 'default' },
    @{ Name = 'ecdh-p256'; Kex = 'ecdh-sha2-nistp256'; Cipher = 'aes256-ctr'; Mac = $etm256; Compression = 'no'; Expected = 'none'; Policy = 'default' },
    @{ Name = 'ecdh-p384'; Kex = 'ecdh-sha2-nistp384'; Cipher = 'aes256-ctr'; Mac = $etm256; Compression = 'no'; Expected = 'none'; Policy = 'default' },
    @{ Name = 'ecdh-p521'; Kex = 'ecdh-sha2-nistp521'; Cipher = 'aes256-ctr'; Mac = $etm256; Compression = 'no'; Expected = 'none'; Policy = 'default' },
    @{ Name = 'dh-group16'; Kex = 'diffie-hellman-group16-sha512'; Cipher = 'aes256-ctr'; Mac = $etm256; Compression = 'no'; Expected = 'none'; Policy = 'default' },
    @{ Name = 'dh-group18'; Kex = 'diffie-hellman-group18-sha512'; Cipher = 'aes256-ctr'; Mac = $etm256; Compression = 'no'; Expected = 'none'; Policy = 'default' },
    @{ Name = 'chacha20'; Kex = 'curve25519-sha256'; Cipher = 'chacha20-poly1305@openssh.com'; Mac = $etm256; Compression = 'no'; Expected = 'none'; Policy = 'default' },
    @{ Name = 'aes256-gcm'; Kex = 'curve25519-sha256'; Cipher = 'aes256-gcm@openssh.com'; Mac = $etm256; Compression = 'no'; Expected = 'none'; Policy = 'default' },
    @{ Name = 'aes128-gcm'; Kex = 'curve25519-sha256'; Cipher = 'aes128-gcm@openssh.com'; Mac = $etm256; Compression = 'no'; Expected = 'none'; Policy = 'default' },
    @{ Name = 'aes192-ctr'; Kex = 'curve25519-sha256'; Cipher = 'aes192-ctr'; Mac = $etm256; Compression = 'no'; Expected = 'none'; Policy = 'default' },
    @{ Name = 'aes128-ctr'; Kex = 'curve25519-sha256'; Cipher = 'aes128-ctr'; Mac = $etm256; Compression = 'no'; Expected = 'none'; Policy = 'default' },
    @{ Name = 'etm512'; Kex = 'curve25519-sha256'; Cipher = 'aes256-ctr'; Mac = $etm512; Compression = 'no'; Expected = 'none'; Policy = 'default' },
    @{ Name = 'zlib-default'; Kex = 'curve25519-sha256'; Cipher = 'aes256-ctr'; Mac = $etm256; Compression = 'yes'; Expected = 'none'; Policy = 'default' },
    @{ Name = 'zlib-selected'; Kex = 'curve25519-sha256'; Cipher = 'aes256-ctr'; Mac = $etm256; Compression = 'yes'; Expected = 'zlib@openssh.com'; Policy = 'zlib' }
)

try {
    $portArguments = @()
    $serverRows = @()
    for ($index = 0; $index -lt $cases.Count; $index++) {
        $case = $cases[$index]
        $case.ServerPort = 2300 + $index
        $portArguments += @('-p', "127.0.0.1::$($case.ServerPort)")
        $serverRows += "$($case.Name)|$($case.ServerPort)|$($case.Kex)|$($case.Cipher)|$($case.Mac)|$($case.Compression)"
    }
    $setup = @'
set -eu
apk add --no-cache openssh-server
adduser -D scoplen
printf 'scoplen:scoplen-test-password\n' | chpasswd
ssh-keygen -q -t ed25519 -N '' -f /tmp/host_key
mkdir -p /run/sshd
cat > /tmp/cases <<'CASES'
__CASES__
CASES
while IFS='|' read -r name port kex cipher mac compression; do
    cat > "/tmp/$name.conf" <<SSHD
Port $port
ListenAddress 0.0.0.0
HostKey /tmp/host_key
PasswordAuthentication yes
PubkeyAuthentication no
KexAlgorithms $kex
HostKeyAlgorithms ssh-ed25519
Ciphers $cipher
MACs $mac
Compression $compression
LogLevel DEBUG3
SSHD
    /usr/sbin/sshd -t -f "/tmp/$name.conf"
    /usr/sbin/sshd -D -E "/tmp/$name.log" -f "/tmp/$name.conf" &
done < /tmp/cases
wait
'@
    $setup = $setup.Replace("`r", '').Replace('__CASES__', ($serverRows -join "`n"))
    docker run -d --name $container @portArguments alpine:3.21 sh -c $setup | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to start disposable modern-algorithm OpenSSH container' }
    $started = $true

    $ports = @{}
    foreach ($case in $cases) {
        $published = docker port $container "$($case.ServerPort)/tcp"
        if ($LASTEXITCODE -ne 0 -or $published -notmatch '^127\.0\.0\.1:(\d+)$') {
            throw "Disposable OpenSSH port $($case.ServerPort) was not published on loopback"
        }
        $ports[$case.Name] = [int]$Matches[1]
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
    if (-not $ready) { throw 'Constrained modern OpenSSH listeners did not become ready within 60 seconds' }

    $env:SCOPLEN_ALGORITHM_HOST_KEY = $hostKey
    $env:SCOPLEN_ALGORITHM_USER = 'scoplen'
    $env:SCOPLEN_ALGORITHM_PASSWORD = 'scoplen-test-password'
    $env:SCOPLEN_ALGORITHM_MATRIX = ($cases | ForEach-Object {
        "$($_.Name)|$($ports[$_.Name])|$($_.Expected)|$($_.Policy)"
    }) -join ';'
    cargo run --quiet --locked -p scoplen-ssh --example algorithm_interop
    if ($LASTEXITCODE -ne 0) { throw 'Constrained modern OpenSSH algorithm interop failed' }

    foreach ($case in $cases) {
        $log = docker exec $container cat "/tmp/$($case.Name).log" | Out-String
        if ($LASTEXITCODE -ne 0) { throw "Could not read OpenSSH $($case.Name) negotiation log" }
        $mac = if ($case.Cipher -match '(?:gcm@openssh\.com|poly1305@openssh\.com)$') { '<implicit>' } else { $case.Mac }
        foreach ($expected in @(
            'Accepted password for scoplen',
            "kex: algorithm: $($case.Kex)",
            'kex: host key algorithm: ssh-ed25519',
            "kex: client->server cipher: $($case.Cipher) MAC: $mac compression: $($case.Expected)",
            "kex: server->client cipher: $($case.Cipher) MAC: $mac compression: $($case.Expected)"
        )) {
            if ($log -notmatch [regex]::Escape($expected)) {
                throw "OpenSSH $($case.Name) did not record expected negotiation: $expected"
            }
        }
        Write-Output "OpenSSH $($case.Name): $($case.Kex), $($case.Cipher), $mac, $($case.Expected)"
    }
    Write-Output 'Modern OpenSSH algorithm matrix and default compression isolation passed'
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
    foreach ($name in $testVariables) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
}
