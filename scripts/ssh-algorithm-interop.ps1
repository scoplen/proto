# SPDX-License-Identifier: Apache-2.0

param([ValidateSet('aes256-cbc', '3des-cbc')][string]$LegacyCipher = 'aes256-cbc')

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$container = 'scoplen-algorithm-interop-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$started = $false
$testVariables = @(
    'SCOPLEN_ALGORITHM_MODERN_PORT', 'SCOPLEN_ALGORITHM_MLKEM_PORT',
    'SCOPLEN_ALGORITHM_LEGACY_PORT',
    'SCOPLEN_ALGORITHM_HOST_KEY', 'SCOPLEN_ALGORITHM_USER', 'SCOPLEN_ALGORITHM_PASSWORD',
    'SCOPLEN_ALGORITHM_LEGACY_CIPHER',
    'SCOPLEN_REKEY_CLIENT_PORT', 'SCOPLEN_REKEY_SERVER_PORT', 'SCOPLEN_REKEY_CONTROL_PORT'
)
$rekeyModes = @(
    @{ Name = 'client'; Offset = 0; Limit = '1G 1h'; FirstDirection = 'receive' },
    @{ Name = 'server'; Offset = 1; Limit = '32K 1h'; FirstDirection = 'send' },
    @{ Name = 'control'; Offset = 2; Limit = '1G 1h'; FirstDirection = 'none' }
)
$rekeyCiphers = @(
    @{ Name = 'aes256-ctr'; Cipher = 'aes256-ctr'; FirstPort = 2224 },
    @{ Name = 'chacha20'; Cipher = 'chacha20-poly1305@openssh.com'; FirstPort = 2228 },
    @{ Name = 'aes256-gcm'; Cipher = 'aes256-gcm@openssh.com'; FirstPort = 2231 }
)
$rekeyCases = @(
    foreach ($cipher in $rekeyCiphers) {
        foreach ($mode in $rekeyModes) {
            @{
                Name = "$($cipher.Name)-$($mode.Name)"
                Port = $cipher.FirstPort + $mode.Offset
                Cipher = $cipher.Cipher
                Limit = $mode.Limit
                FirstDirection = $mode.FirstDirection
            }
        }
    }
)

function Assert-RekeyLog {
    param([string]$name, [string]$firstDirection, [string]$cipher)

    $log = docker exec $container cat "/tmp/rekey-$name.log" | Out-String
    if ($LASTEXITCODE -ne 0) { throw "Could not read OpenSSH $name rekey log" }
    $mac = if ($cipher -match '(?:gcm@openssh\.com|poly1305@openssh\.com)$') { '<implicit>' } else { 'hmac-sha2-256-etm@openssh.com' }
    foreach ($direction in @('client->server', 'server->client')) {
        $expected = "kex: $direction cipher: $cipher MAC: $mac compression: none"
        if ($log -notmatch [regex]::Escape($expected)) {
            throw "OpenSSH $name did not negotiate $expected"
        }
    }
    $accepted = [regex]::Match($log, '(?m)^.*Accepted password for scoplen.*\n')
    if (-not $accepted.Success) { throw "OpenSSH $name log has no authenticated session" }
    $strict = [regex]::Match($log, 'will use strict KEX ordering')
    if (-not $strict.Success -or $strict.Index -ge $accepted.Index) {
        throw "OpenSSH $name did not negotiate strict KEX before authentication"
    }
    foreach ($direction in @('send', 'receive')) {
        $newKeysInDirection = @([regex]::Matches($log, "\b$direction packet: type 21\b"))
        $resetDirection = if ($direction -eq 'send') { 'send' } else { 'read' }
        $resets = @([regex]::Matches($log, "resetting $resetDirection seqnr (\d+)\b"))
        if ($newKeysInDirection.Count -ne $resets.Count) {
            throw "OpenSSH $name $direction NEWKEYS count does not match sequence resets"
        }
        for ($index = 0; $index -lt $resets.Count; $index++) {
            if ($resets[$index].Index -le $newKeysInDirection[$index].Index -or
                ($index + 1 -lt $newKeysInDirection.Count -and
                    $resets[$index].Index -ge $newKeysInDirection[$index + 1].Index) -or
                [uint64]$resets[$index].Groups[1].Value -eq 0) {
                throw "OpenSSH $name $direction NEWKEYS was not followed by a nonzero sequence reset"
            }
        }
    }
    $postAuth = $log.Substring($accepted.Index + $accepted.Length)
    $kex = @([regex]::Matches($postAuth, '\b(send|receive) packet: type 20\b'))
    $newKeys = @([regex]::Matches($postAuth, '\b(send|receive) packet: type 21\b'))
    $sentKex = @($kex | Where-Object { $_.Groups[1].Value -eq 'send' }).Count
    $receivedKex = @($kex | Where-Object { $_.Groups[1].Value -eq 'receive' }).Count
    $sentNewKeys = @($newKeys | Where-Object { $_.Groups[1].Value -eq 'send' }).Count
    $receivedNewKeys = @($newKeys | Where-Object { $_.Groups[1].Value -eq 'receive' }).Count
    if ($firstDirection -eq 'none') {
        if ($kex.Count -ne 0 -or $newKeys.Count -ne 0) {
            throw "OpenSSH $name unexpectedly rekeyed after authentication"
        }
        Write-Output "OpenSSH ${name}: $cipher, strict initial KEX reset both sequence numbers; no post-auth rekey"
        return
    }
    if ($kex.Count -lt 4 -or $kex[0].Groups[1].Value -ne $firstDirection -or
        $sentKex -lt 2 -or $receivedKex -lt 2 -or
        $sentKex -ne $receivedKex -or $sentKex -ne $sentNewKeys -or
        $sentKex -ne $receivedNewKeys) {
        throw "OpenSSH $name did not complete the expected $firstDirection-first rekey"
    }
    Write-Output "OpenSSH ${name}: $cipher, strict KEX; first post-auth KEXINIT=$firstDirection, rekeys=$sentKex, send/read sequence reset after every NEWKEYS"
}

try {
    $portArguments = @()
    foreach ($serverPort in @(2222, 2223, 2227) + @($rekeyCases | ForEach-Object { $_.Port })) {
        $portArguments += @('-p', "127.0.0.1::$serverPort")
    }
    $rekeyRows = @($rekeyCases | ForEach-Object { "$($_.Name)|$($_.Port)|$($_.Cipher)|$($_.Limit)" })
    $setup = @'
set -eu
apk add --no-cache openssh-server
adduser -D scoplen
printf 'scoplen:scoplen-test-password\n' | chpasswd
ssh-keygen -q -t ed25519 -N '' -f /tmp/host_key
mkdir -p /run/sshd
cat > /tmp/modern.conf <<'SSHD'
Port 2222
ListenAddress 0.0.0.0
HostKey /tmp/host_key
PasswordAuthentication yes
KexAlgorithms curve25519-sha256
HostKeyAlgorithms ssh-ed25519
Ciphers aes256-ctr
MACs hmac-sha2-256-etm@openssh.com
Compression no
SSHD
cat > /tmp/mlkem.conf <<'SSHD'
Port 2227
ListenAddress 0.0.0.0
HostKey /tmp/host_key
PasswordAuthentication yes
KexAlgorithms mlkem768x25519-sha256
HostKeyAlgorithms ssh-ed25519
Ciphers chacha20-poly1305@openssh.com
MACs hmac-sha2-256-etm@openssh.com
Compression no
SSHD
cat > /tmp/legacy.conf <<'SSHD'
Port 2223
ListenAddress 0.0.0.0
HostKey /tmp/host_key
PasswordAuthentication yes
KexAlgorithms diffie-hellman-group14-sha256
HostKeyAlgorithms ssh-ed25519
Ciphers aes256-cbc
MACs hmac-sha1
Compression no
SSHD
cat > /tmp/rekey-cases <<'CASES'
__REKEY_CASES__
CASES
while IFS='|' read -r name port cipher limit; do
    cat > "/tmp/rekey-$name.conf" <<SSHD
Port $port
ListenAddress 0.0.0.0
HostKey /tmp/host_key
PasswordAuthentication yes
KexAlgorithms curve25519-sha256
HostKeyAlgorithms ssh-ed25519
Ciphers $cipher
MACs hmac-sha2-256-etm@openssh.com
Compression no
LogLevel DEBUG3
RekeyLimit $limit
SSHD
    /usr/sbin/sshd -t -f "/tmp/rekey-$name.conf"
    /usr/sbin/sshd -D -E "/tmp/rekey-$name.log" -f "/tmp/rekey-$name.conf" &
done < /tmp/rekey-cases
/usr/sbin/sshd -t -f /tmp/modern.conf
/usr/sbin/sshd -t -f /tmp/mlkem.conf
/usr/sbin/sshd -t -f /tmp/legacy.conf
/usr/sbin/sshd -D -e -f /tmp/modern.conf &
/usr/sbin/sshd -D -e -f /tmp/mlkem.conf &
exec /usr/sbin/sshd -D -e -f /tmp/legacy.conf
'@
    # A CRLF checkout leaves carriage returns in PowerShell here-strings; Alpine sh rejects them.
    $setup = $setup.Replace("`r", '').Replace('__REKEY_CASES__', ($rekeyRows -join "`n"))
    $setup = $setup.Replace('Ciphers aes256-cbc', "Ciphers $LegacyCipher")
    docker run -d --name $container @portArguments alpine:3.21 sh -c $setup | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to start disposable OpenSSH algorithm container' }
    $started = $true

    $ports = @{}
    foreach ($serverPort in @(2222, 2223, 2227) + @($rekeyCases | ForEach-Object { $_.Port })) {
        $published = docker port $container "$serverPort/tcp"
        if ($LASTEXITCODE -ne 0 -or $published -notmatch '^127\.0\.0\.1:(\d+)$') {
            throw "Disposable OpenSSH port $serverPort was not published on loopback"
        }
        $ports[$serverPort] = [int]$Matches[1]
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
    if (-not $ready) { throw 'Constrained OpenSSH listeners did not become ready within 60 seconds' }

    $env:SCOPLEN_ALGORITHM_MODERN_PORT = $ports[2222].ToString()
    $env:SCOPLEN_ALGORITHM_MLKEM_PORT = $ports[2227].ToString()
    $env:SCOPLEN_ALGORITHM_LEGACY_PORT = $ports[2223].ToString()
    $env:SCOPLEN_ALGORITHM_LEGACY_CIPHER = $LegacyCipher
    $env:SCOPLEN_ALGORITHM_HOST_KEY = $hostKey
    $env:SCOPLEN_ALGORITHM_USER = 'scoplen'
    $env:SCOPLEN_ALGORITHM_PASSWORD = 'scoplen-test-password'
    cargo run --quiet --locked -p scoplen-ssh --example algorithm_interop
    if ($LASTEXITCODE -ne 0) { throw 'Constrained OpenSSH algorithm interop failed' }
    cargo run --quiet --locked -p scoplen-ssh --example strict_kex_interop
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSH strict KEX interop failed' }
    foreach ($case in $rekeyCases) {
        docker exec $container sh -c ": > /tmp/rekey-$($case.Name).log" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not clear OpenSSH $($case.Name) rekey log" }
    }
    foreach ($cipher in $rekeyCiphers) {
        $env:SCOPLEN_REKEY_CLIENT_PORT = $ports[$cipher.FirstPort].ToString()
        $env:SCOPLEN_REKEY_SERVER_PORT = $ports[$cipher.FirstPort + 1].ToString()
        $env:SCOPLEN_REKEY_CONTROL_PORT = $ports[$cipher.FirstPort + 2].ToString()
        cargo run --quiet --locked -p scoplen-ssh --example rekey_interop
        if ($LASTEXITCODE -ne 0) { throw "OpenSSH $($cipher.Name) rekey interop failed" }
        foreach ($case in @($rekeyCases | Where-Object { $_.Cipher -eq $cipher.Cipher })) {
            Assert-RekeyLog $case.Name $case.FirstDirection $case.Cipher
        }
    }
    Write-Output 'OpenSSH client-initiated, server-initiated, and no-rekey control passed for all rekey ciphers'
}
catch {
    if ($started) {
        $state = docker inspect --format '{{.State.Status}} exit={{.State.ExitCode}}' $container 2>$null
        if ($LASTEXITCODE -eq 0) { Write-Warning "Disposable OpenSSH state: $state" }
        $logs = docker logs --tail 30 $container 2>&1
        if ($LASTEXITCODE -eq 0 -and $logs) { Write-Warning "Disposable OpenSSH log:`n$($logs | Out-String)" }
        foreach ($case in $rekeyCases) {
            $rekeyLog = docker exec $container tail -n 35 "/tmp/rekey-$($case.Name).log" 2>$null
            if ($LASTEXITCODE -eq 0 -and $rekeyLog) {
                Write-Warning "OpenSSH $($case.Name) rekey log:`n$($rekeyLog | Out-String)"
            }
        }
    }
    throw
}
finally {
    if ($started) { docker rm -f $container 2>$null | Out-Null }
    foreach ($name in $testVariables) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
}
