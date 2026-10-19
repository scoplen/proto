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
    'SCOPLEN_OPENSSH_USER_CA_KEY', 'SCOPLEN_OPENSSH_SFTP', 'SCOPLEN_OPENSSH_SFTP_PROFILE',
    'SCOPLEN_OPENSSH_FORWARD',
    'SCOPLEN_OPENSSH_JUMP_TARGET_PORT', 'SCOPLEN_HOST_CERT_PORT',
    'SCOPLEN_HOST_CERT_RAW_KEY', 'SCOPLEN_HOST_CERT_CA_KEY'
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
    elseif ($exitCode -ne 0 -or $output -notmatch '(?m)^openssh interop ok\s*$' -or
        ($env:SCOPLEN_OPENSSH_SFTP -eq '1' -and $output -notmatch '(?m)^openssh sftp interop ok\s*$') -or
        ($env:SCOPLEN_OPENSSH_FORWARD -eq '1' -and $output -notmatch '(?m)^openssh forwarding interop ok\s*$')) {
        throw "OpenSSH 8.8p1 $caseName failed (exit $exitCode): $output"
    }
    Write-Output "OpenSSH 8.8p1 ${caseName}: passed"
}

function Invoke-HostCertificateCase {
    param([string]$caseName, [int]$casePort, [string]$outcome)

    $env:SCOPLEN_HOST_CERT_PORT = $casePort.ToString()
    $output = & cargo run --quiet --locked -p scoplen-ssh --example host_certificate_interop -- mixed $outcome 2>&1 | Out-String
    $expected = if ($outcome -eq 'valid') { 'host certificate mixed-valid command ok' }
        else { "host certificate mixed-$outcome rejected" }
    if ($LASTEXITCODE -ne 0 -or $output.Trim() -ne $expected) {
        throw "OpenSSH 8.8p1 host certificate ${caseName}: expected '$expected', got '$output'"
    }
    Write-Output "OpenSSH 8.8p1 host certificate ${caseName}: passed"
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
ssh-keygen -q -t ed25519 -N '' -f /tmp/ca_trusted
ssh-keygen -q -t ed25519 -N '' -f /tmp/ca_other
ssh-keygen -q -t ed25519 -N '' -f /tmp/ca_krl
ssh-keygen -q -s /tmp/ca_trusted -I user-valid -n scoplen -V -1m:+10m /tmp/user_ed.pub
mv /tmp/user_ed-cert.pub /tmp/user_valid-cert.pub
ssh-keygen -q -s /tmp/ca_trusted -I user-wrong-principal -n other -V -1m:+10m /tmp/user_ed.pub
mv /tmp/user_ed-cert.pub /tmp/user_wrong-principal-cert.pub
ssh-keygen -q -s /tmp/ca_other -I user-untrusted -n scoplen -V -1m:+10m /tmp/user_ed.pub
mv /tmp/user_ed-cert.pub /tmp/user_untrusted-cert.pub
ssh-keygen -q -s /tmp/ca_krl -I user-krl-valid -z 4100 -n scoplen -V -1m:+10m /tmp/user_ed.pub
mv /tmp/user_ed-cert.pub /tmp/user_krl-valid-cert.pub
ssh-keygen -q -s /tmp/ca_krl -I user-krl-serial -z 4101 -n scoplen -V -1m:+10m /tmp/user_ed.pub
mv /tmp/user_ed-cert.pub /tmp/user_krl-serial-cert.pub
ssh-keygen -q -s /tmp/ca_krl -I user-krl-id -z 4102 -n scoplen -V -1m:+10m /tmp/user_ed.pub
mv /tmp/user_ed-cert.pub /tmp/user_krl-id-cert.pub
cat > /tmp/krl_spec <<'KRL'
serial: 4101
id: user-krl-id
KRL
ssh-keygen -q -k -f /tmp/revoked.krl -s /tmp/ca_krl.pub /tmp/krl_spec
ssh-keygen -q -s /tmp/ca_trusted -h -I host-valid -n 127.0.0.1 -V -1m:+10m /tmp/host_key.pub
mv /tmp/host_key-cert.pub /tmp/host_valid-cert.pub
ssh-keygen -q -s /tmp/ca_trusted -h -I host-wrong-principal -n other.example -V -1m:+10m /tmp/host_key.pub
mv /tmp/host_key-cert.pub /tmp/host_wrong-principal-cert.pub
ssh-keygen -q -s /tmp/ca_trusted -h -I host-expired -n 127.0.0.1 -V -2h:-1h /tmp/host_key.pub
mv /tmp/host_key-cert.pub /tmp/host_expired-cert.pub
mkdir -p /home/scoplen/.ssh /run/sshd
cat /tmp/user_ed.pub /tmp/user_rsa.pub > /home/scoplen/.ssh/authorized_keys
cat /tmp/ca_trusted.pub /tmp/ca_krl.pub > /tmp/trusted_user_cas.pub
chown -R scoplen:scoplen /home/scoplen/.ssh
chmod 700 /home/scoplen/.ssh
chmod 600 /home/scoplen/.ssh/authorized_keys
cat > /tmp/sshd_config <<'SSHD'
Port 2222
ListenAddress 0.0.0.0
HostKey /tmp/host_key
PasswordAuthentication yes
PubkeyAuthentication yes
TrustedUserCAKeys /tmp/trusted_user_cas.pub
RevokedKeys /tmp/revoked.krl
AllowTcpForwarding yes
LogLevel VERBOSE
Subsystem sftp internal-sftp
SSHD
/usr/sbin/sshd -t -f /tmp/sshd_config
for case in valid wrong-principal expired; do
    case "$case" in
        valid) port=2223 ;;
        wrong-principal) port=2224 ;;
        expired) port=2225 ;;
    esac
    cat > "/tmp/sshd_host_$case" <<SSHD
Port $port
ListenAddress 0.0.0.0
HostKey /tmp/host_key
HostCertificate /tmp/host_$case-cert.pub
HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-ed25519
PasswordAuthentication yes
SSHD
    /usr/sbin/sshd -t -f "/tmp/sshd_host_$case"
    advertised=$(/usr/sbin/sshd -T -f "/tmp/sshd_host_$case" | sed -n 's/^hostkeyalgorithms //p')
    [ "$advertised" = 'ssh-ed25519-cert-v01@openssh.com,ssh-ed25519' ] || {
        printf 'host certificate listener did not offer both identities: %s\n' "$advertised" >&2
        exit 1
    }
    /usr/sbin/sshd -D -e -f "/tmp/sshd_host_$case" &
done
exec /usr/sbin/sshd -D -e -f /tmp/sshd_config
'@
    $setup = $setup.Replace("`r", '')
    docker run -d --name $container -p '127.0.0.1::2222' -p '127.0.0.1::2223' -p '127.0.0.1::2224' -p '127.0.0.1::2225' alpine:3.15 sh -c $setup | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not start disposable OpenSSH 8.8p1 container' }
    $started = $true

    $published = docker port $container '2222/tcp'
    if ($LASTEXITCODE -ne 0 -or $published -notmatch '^127\.0\.0\.1:(\d+)$') {
        throw 'OpenSSH 8.8p1 was not published on loopback'
    }
    $port = [int]$Matches[1]
    $hostCertPorts = @{}
    foreach ($case in @(@{ Name = 'valid'; Port = 2223 }, @{ Name = 'wrong-principal'; Port = 2224 }, @{ Name = 'expired'; Port = 2225 })) {
        $published = docker port $container "$($case.Port)/tcp"
        if ($LASTEXITCODE -ne 0 -or $published -notmatch '^127\.0\.0\.1:(\d+)$') {
            throw "OpenSSH 8.8p1 host certificate $($case.Name) port was not published on loopback"
        }
        $hostCertPorts[$case.Name] = [int]$Matches[1]
    }
    $ready = $false
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
            $socket.ReceiveTimeout = 2000
            $reader = [System.IO.StreamReader]::new($socket.GetStream())
            $banner = $reader.ReadLine()
            $ready = -not [string]::IsNullOrEmpty($banner)
        }
        catch { $ready = $false }
        finally { $socket.Dispose() }
        foreach ($hostCertPort in $hostCertPorts.Values) {
            $socket = [System.Net.Sockets.TcpClient]::new()
            try { $socket.Connect('127.0.0.1', $hostCertPort) }
            catch { $ready = $false }
            finally { $socket.Dispose() }
        }
        if ($ready) { break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw 'OpenSSH 8.8p1 did not become ready within 60 seconds' }
    $package = docker exec $container apk list --installed openssh-server
    if ($LASTEXITCODE -ne 0 -or ($package | Out-String).Trim() -notmatch '^openssh-server-8\.8_p1-r1 ' -or
        $banner -notmatch '^SSH-2\.0-OpenSSH_8\.8(?:\r)?$') {
        throw "Unexpected OpenSSH 8.8p1 package or SSH banner: $package; $banner"
    }
    Write-Output "OpenSSH package $package; banner $banner"

    foreach ($name in @(
        'user_ed', 'other_user_ed', 'user_rsa', 'other_user_rsa',
        'ca_trusted.pub', 'ca_other.pub', 'ca_krl.pub',
        'user_valid-cert.pub', 'user_wrong-principal-cert.pub', 'user_untrusted-cert.pub',
        'user_krl-valid-cert.pub', 'user_krl-serial-cert.pub', 'user_krl-id-cert.pub'
    )) {
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
    $env:SCOPLEN_OPENSSH_SFTP = '1'
    $env:SCOPLEN_OPENSSH_SFTP_PROFILE = '8.8p1'
    $env:SCOPLEN_OPENSSH_FORWARD = '1'
    Invoke-Interop 'password, command, SFTP, and direct forwarding'
    Remove-Item Env:SCOPLEN_OPENSSH_SFTP, Env:SCOPLEN_OPENSSH_SFTP_PROFILE, Env:SCOPLEN_OPENSSH_FORWARD

    $env:SCOPLEN_OPENSSH_JUMP_TARGET_PORT = '2222'
    $jumpOutput = & cargo run --quiet --locked -p scoplen-ssh --example jump_chain_interop 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or $jumpOutput.Trim() -ne 'openssh nested jump interop ok') {
        throw "OpenSSH 8.8p1 nested jump failed: $jumpOutput"
    }
    Write-Output 'OpenSSH 8.8p1 nested jump, host-pin rejection, and parent reuse: passed'
    Remove-Item Env:SCOPLEN_OPENSSH_JUMP_TARGET_PORT

    $env:SCOPLEN_HOST_CERT_RAW_KEY = $hostKey
    $env:SCOPLEN_HOST_CERT_CA_KEY = Get-Content (Join-Path $tempRoot 'ca_trusted.pub')
    Invoke-HostCertificateCase 'mixed valid' $hostCertPorts['valid'] 'valid'
    $env:SCOPLEN_HOST_CERT_CA_KEY = Get-Content (Join-Path $tempRoot 'ca_other.pub')
    Invoke-HostCertificateCase 'mixed wrong CA' $hostCertPorts['valid'] 'wrong-ca'
    $env:SCOPLEN_HOST_CERT_CA_KEY = Get-Content (Join-Path $tempRoot 'ca_trusted.pub')
    Invoke-HostCertificateCase 'mixed valid after wrong CA' $hostCertPorts['valid'] 'valid'
    Invoke-HostCertificateCase 'mixed wrong principal' $hostCertPorts['wrong-principal'] 'wrong-principal'
    Invoke-HostCertificateCase 'mixed valid after wrong principal' $hostCertPorts['valid'] 'valid'
    Invoke-HostCertificateCase 'mixed expired' $hostCertPorts['expired'] 'expired'
    Invoke-HostCertificateCase 'mixed valid after expiry' $hostCertPorts['valid'] 'valid'
    Remove-Item Env:SCOPLEN_HOST_CERT_PORT, Env:SCOPLEN_HOST_CERT_RAW_KEY, Env:SCOPLEN_HOST_CERT_CA_KEY

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

    $env:SCOPLEN_OPENSSH_ED25519_KEY = Join-Path $tempRoot 'user_ed'
    $env:SCOPLEN_OPENSSH_USER_CA_KEY = Join-Path $tempRoot 'ca_trusted.pub'
    $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot 'user_valid-cert.pub'
    Invoke-Interop 'valid Ed25519 user certificate'
    $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot 'user_wrong-principal-cert.pub'
    Invoke-Interop 'wrong user-certificate principal' 'PrincipalMismatch'
    $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot 'user_valid-cert.pub'
    $env:SCOPLEN_OPENSSH_USER_CA_KEY = Join-Path $tempRoot 'ca_other.pub'
    Invoke-Interop 'wrong local user-certificate CA pin' 'UntrustedUserCa'
    $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot 'user_untrusted-cert.pub'
    $env:SCOPLEN_OPENSSH_USER_CA_KEY = Join-Path $tempRoot 'ca_other.pub'
    Invoke-Interop 'server-untrusted user-certificate CA' 'AuthenticationRejected'
    $env:SCOPLEN_OPENSSH_USER_CA_KEY = Join-Path $tempRoot 'ca_krl.pub'
    $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot 'user_krl-valid-cert.pub'
    Invoke-Interop 'unrevoked KRL-trusted user certificate'
    $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot 'user_krl-serial-cert.pub'
    Invoke-Interop 'serial-revoked user certificate' 'AuthenticationRejected'
    $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot 'user_krl-id-cert.pub'
    Invoke-Interop 'key-ID-revoked user certificate' 'AuthenticationRejected'
    $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot 'user_krl-valid-cert.pub'
    Invoke-Interop 'unrevoked certificate after KRL rejections'
    Remove-Item Env:SCOPLEN_OPENSSH_ED25519_KEY, Env:SCOPLEN_OPENSSH_USER_CA_KEY, Env:SCOPLEN_OPENSSH_USER_CERT

    $env:SCOPLEN_OPENSSH_PASSWORD = 'scoplen-test-password'
    $env:SCOPLEN_OPENSSH_HOST_KEY = $otherHostKey
    Invoke-Interop 'untrusted host key' 'unexpected server key'
    Write-Output 'OpenSSH 8.8p1 public client authentication, certificates, SFTP, forwarding, and jump interoperability passed'
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
