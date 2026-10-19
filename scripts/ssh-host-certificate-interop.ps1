# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$container = 'scoplen-host-cert-interop-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$started = $false
$variables = @('SCOPLEN_HOST_CERT_PORT', 'SCOPLEN_HOST_CERT_RAW_KEY', 'SCOPLEN_HOST_CERT_CA_KEY')
foreach ($name in $variables) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }

function Invoke-Case {
    param([string]$curve, [string]$mode, [int]$port)

    $env:SCOPLEN_HOST_CERT_PORT = $port.ToString()
    $output = & cargo run --quiet --locked -p scoplen-ssh --example host_certificate_interop -- $mode 2>&1 | Out-String
    $expected = if ($mode -eq 'raw' -or $mode -eq 'valid') {
        "host certificate $mode command ok"
    } else {
        "host certificate $mode rejected"
    }
    if ($LASTEXITCODE -ne 0 -or $output.Trim() -ne $expected) {
        throw "P-$curve ${mode}: expected '$expected', got exit $LASTEXITCODE and '$output'"
    }
    Write-Output "P-$curve ${mode}: $expected"
}

try {
    $setup = @'
set -eu
apk add --no-cache openssh-server
adduser -D scoplen
printf 'scoplen:scoplen-test-password\n' | chpasswd
mkdir -p /run/sshd
ssh-keygen -q -t ed25519 -N '' -f /tmp/ca_trusted
ssh-keygen -q -t ed25519 -N '' -f /tmp/ca_other
for curve in 384 521; do
    ssh-keygen -q -t ecdsa -b "$curve" -N '' -f "/tmp/host_$curve"
    algorithm="ecdsa-sha2-nistp$curve"
    ssh-keygen -q -s /tmp/ca_trusted -h -I "p${curve}-valid" -n 127.0.0.1 -V -1m:+10m "/tmp/host_$curve.pub"
    mv "/tmp/host_$curve-cert.pub" "/tmp/host_${curve}_valid-cert.pub"
    ssh-keygen -q -s /tmp/ca_other -h -I "p${curve}-wrong-ca" -n 127.0.0.1 -V -1m:+10m "/tmp/host_$curve.pub"
    mv "/tmp/host_$curve-cert.pub" "/tmp/host_${curve}_wrong-ca-cert.pub"
    ssh-keygen -q -s /tmp/ca_trusted -h -I "p${curve}-wrong-principal" -n other.example -V -1m:+10m "/tmp/host_$curve.pub"
    mv "/tmp/host_$curve-cert.pub" "/tmp/host_${curve}_wrong-principal-cert.pub"
    ssh-keygen -q -s /tmp/ca_trusted -h -I "p${curve}-expired" -n 127.0.0.1 -V -2h:-1h "/tmp/host_$curve.pub"
    mv "/tmp/host_$curve-cert.pub" "/tmp/host_${curve}_expired-cert.pub"
    for mode in raw valid wrong-ca wrong-principal expired; do
        case "$curve:$mode" in
            384:raw) port=23840 ;;
            384:valid) port=23841 ;;
            384:wrong-ca) port=23842 ;;
            384:wrong-principal) port=23843 ;;
            384:expired) port=23844 ;;
            521:raw) port=25210 ;;
            521:valid) port=25211 ;;
            521:wrong-ca) port=25212 ;;
            521:wrong-principal) port=25213 ;;
            521:expired) port=25214 ;;
        esac
        config="/tmp/sshd_${curve}_${mode}.conf"
        cat > "$config" <<SSHD
Port $port
ListenAddress 0.0.0.0
HostKey /tmp/host_$curve
PasswordAuthentication yes
PerSourcePenalties no
HostKeyAlgorithms $algorithm
SSHD
        if [ "$mode" != raw ]; then
            printf 'HostCertificate /tmp/host_%s_%s-cert.pub\nHostKeyAlgorithms %s-cert-v01@openssh.com\n' "$curve" "$mode" "$algorithm" >> "$config"
            sed -i "/^HostKeyAlgorithms $algorithm$/d" "$config"
        fi
        /usr/sbin/sshd -t -f "$config"
        /usr/sbin/sshd -D -e -f "$config" &
    done
done
wait
'@
    $setup = $setup.Replace("`r", '')
    $publish = @()
    foreach ($port in @(23840, 23841, 23842, 23843, 23844, 25210, 25211, 25212, 25213, 25214)) {
        $publish += @('-p', "127.0.0.1::$port")
    }
    docker run -d --name $container @publish alpine:3.21 sh -c $setup | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not start disposable OpenSSH host-certificate container' }
    $started = $true

    $ports = @{}
    foreach ($serverPort in @(23840, 23841, 23842, 23843, 23844, 25210, 25211, 25212, 25213, 25214)) {
        $published = docker port $container "$serverPort/tcp"
        if ($LASTEXITCODE -ne 0 -or $published -notmatch '^127\.0\.0\.1:(\d+)$') {
            throw "OpenSSH port $serverPort was not published on loopback"
        }
        $ports[$serverPort] = [int]$Matches[1]
    }
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $caKey = docker exec $container cat /tmp/ca_trusted.pub 2>$null
        if ($LASTEXITCODE -ne 0 -or $caKey -notmatch '^ssh-ed25519 ') {
            Start-Sleep -Seconds 1
            continue
        }
        docker exec $container pidof sshd 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
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
    if (-not $ready) { throw 'OpenSSH host-certificate listeners did not become ready within 60 seconds' }

    $env:SCOPLEN_HOST_CERT_CA_KEY = $caKey
    foreach ($curve in @(384, 521)) {
        $env:SCOPLEN_HOST_CERT_RAW_KEY = docker exec $container cat "/tmp/host_$curve.pub"
        if ($LASTEXITCODE -ne 0) { throw "Could not read P-$curve host key" }
        $base = if ($curve -eq 384) { 23840 } else { 25210 }
        Invoke-Case $curve 'raw' $ports[$base]
        Invoke-Case $curve 'valid' $ports[($base + 1)]
        foreach ($case in @(
            @{ Mode = 'wrong-ca'; Offset = 2 },
            @{ Mode = 'wrong-principal'; Offset = 3 },
            @{ Mode = 'expired'; Offset = 4 }
        )) {
            Invoke-Case $curve $case.Mode $ports[($base + $case.Offset)]
            Invoke-Case $curve 'valid' $ports[($base + 1)]
        }
    }
}
catch {
    if ($started) {
        $logs = docker logs --tail 40 $container 2>&1
        if ($logs) { Write-Warning "Disposable OpenSSH log:`n$($logs | Out-String)" }
    }
    throw
}
finally {
    if ($started) { docker rm -f $container 2>$null | Out-Null }
    foreach ($name in $variables) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
}
