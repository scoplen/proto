# SPDX-License-Identifier: Apache-2.0

param([ValidateSet('9.9p2', '10.6p1')][string]$ServerVersion = '9.9p2')

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$container = 'scoplen-openssh-interop-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/')
$tempRoot = [System.IO.Path]::GetFullPath((Join-Path $tempBase ('scoplen-openssh-keys-' + [guid]::NewGuid().ToString('N'))))
$started = $false
$serverProfiles = @{
    '9.9p2' = @{ Image = 'alpine:3.21'; Package = 'openssh-server=9.9_p2-r0'; Installed = 'openssh-server-9.9_p2-r0 '; Banner = '^SSH-2\.0-OpenSSH_9\.9\r?$' }
    '10.6p1' = @{ Image = 'alpine:edge'; Package = 'openssh-server=10.6_p1-r1'; Installed = 'openssh-server-10.6_p1-r1 '; Banner = '^SSH-2\.0-OpenSSH_10\.6\r?$' }
}
$serverProfile = $serverProfiles[$ServerVersion]
$authVariables = @(
    'SCOPLEN_OPENSSH_PASSWORD', 'SCOPLEN_OPENSSH_RSA_KEY', 'SCOPLEN_OPENSSH_RSA_HASH',
    'SCOPLEN_OPENSSH_ED25519_KEY', 'SCOPLEN_OPENSSH_P256_KEY', 'SCOPLEN_OPENSSH_ECDSA_KEY',
    'SCOPLEN_OPENSSH_USER_CERT', 'SCOPLEN_OPENSSH_USER_CA_KEY'
)
$testVariables = @(
    'SCOPLEN_OPENSSH_HOST', 'SCOPLEN_OPENSSH_PORT', 'SCOPLEN_OPENSSH_USER',
    'SCOPLEN_OPENSSH_PASSWORD', 'SCOPLEN_OPENSSH_HOST_KEY', 'SCOPLEN_OPENSSH_HOST_CA_KEY',
    'SCOPLEN_OPENSSH_RSA_KEY', 'SCOPLEN_OPENSSH_RSA_HASH',
    'SCOPLEN_OPENSSH_ED25519_KEY', 'SCOPLEN_OPENSSH_P256_KEY', 'SCOPLEN_OPENSSH_ECDSA_KEY',
    'SCOPLEN_OPENSSH_USER_CERT', 'SCOPLEN_OPENSSH_USER_CA_KEY',
    'SCOPLEN_OPENSSH_SFTP', 'SCOPLEN_OPENSSH_FORWARD',
    'SCOPLEN_OPENSSH_JUMP_TARGET_PORT'
)
foreach ($name in $testVariables) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }

function Clear-AuthMode {
    foreach ($name in $authVariables) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
}

function Invoke-AuthExample {
    param([string]$caseName, [string]$expectedError = '')

    $output = & cargo run --quiet --locked -p scoplen-ssh --example openssh_interop 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    if ($expectedError) {
        if ($exitCode -eq 0 -or $output -notmatch [regex]::Escape($expectedError)) {
            throw "$caseName did not fail as expected (exit $exitCode): $output"
        }
    }
    elseif ($exitCode -ne 0 -or $output -notmatch '(?m)^openssh interop ok\s*$') {
        throw "$caseName failed (exit $exitCode): $output"
    }
}

function Invoke-SecurityKeyExample {
    param([string]$caseName, [string]$algorithm, [string]$fault = 'valid', [string]$expectedError = '')

    $output = & cargo run --quiet --locked -p scoplen-ssh --example security_key_interop -- auth $algorithm $fault 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    if ($expectedError) {
        if ($exitCode -eq 0 -or $output -notmatch [regex]::Escape($expectedError)) {
            throw "$caseName did not fail as expected (exit $exitCode): $output"
        }
    }
    elseif ($exitCode -ne 0 -or $output -notmatch '(?m)^security-key interop ok\s*$') {
        throw "$caseName failed (exit $exitCode): $output"
    }
}

try {
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    $setup = @'
set -eu
apk add --no-cache __OPENSSH_PACKAGE__
adduser -D scoplen
printf 'scoplen:scoplen-test-password\n' | chpasswd
ssh-keygen -q -t ed25519 -N '' -f /tmp/host_key
ssh-keygen -q -t ed25519 -N '' -f /tmp/user_ed
ssh-keygen -q -t ecdsa -b 256 -N '' -f /tmp/user_p256
ssh-keygen -q -t ecdsa -b 384 -N '' -f /tmp/user_p384
ssh-keygen -q -t ecdsa -b 521 -N '' -f /tmp/user_p521
ssh-keygen -q -t ecdsa -b 384 -N '' -f /tmp/wrong_p384
ssh-keygen -q -t ecdsa -b 521 -N '' -f /tmp/wrong_p521
ssh-keygen -q -t rsa -b 3072 -N '' -f /tmp/user_rsa
ssh-keygen -q -t ed25519 -N '' -f /tmp/wrong_ed
ssh-keygen -q -t ed25519 -N '' -f /tmp/ca_trusted
ssh-keygen -q -t ed25519 -N '' -f /tmp/ca_other
ssh-keygen -q -t ed25519 -N '' -f /tmp/ca_krl
ssh-keygen -q -s /tmp/ca_trusted -I ed25519 -n scoplen -V -1m:+10m /tmp/user_ed.pub
mv /tmp/user_ed-cert.pub /tmp/user_ed_good-cert.pub
ssh-keygen -q -s /tmp/ca_trusted -I p256 -n scoplen -V -1m:+10m /tmp/user_p256.pub
for curve in p384 p521; do
    ssh-keygen -q -s /tmp/ca_trusted -I "${curve}-valid" -n scoplen -V -1m:+10m "/tmp/user_${curve}.pub"
    mv "/tmp/user_${curve}-cert.pub" "/tmp/user_${curve}_valid-cert.pub"
    ssh-keygen -q -s /tmp/ca_trusted -I "${curve}-wrong-principal" -n other -V -1m:+10m "/tmp/user_${curve}.pub"
    mv "/tmp/user_${curve}-cert.pub" "/tmp/user_${curve}_wrong-principal-cert.pub"
    mv "/tmp/user_${curve}_valid-cert.pub" "/tmp/user_${curve}-cert.pub"
    ssh-keygen -q -s /tmp/ca_trusted -I "${curve}-wrong-subject" -n scoplen -V -1m:+10m "/tmp/wrong_${curve}.pub"
done
ssh-keygen -q -s /tmp/ca_trusted -I rsa -n scoplen -V -1m:+10m /tmp/user_rsa.pub
ssh-keygen -q -s /tmp/ca_trusted -I wrong-principal -n other -V -1m:+10m /tmp/user_ed.pub
mv /tmp/user_ed-cert.pub /tmp/user_ed_wrong-principal-cert.pub
ssh-keygen -q -s /tmp/ca_other -I untrusted-ca -n scoplen -V -1m:+10m /tmp/user_ed.pub
mv /tmp/user_ed-cert.pub /tmp/user_ed_untrusted-cert.pub
ssh-keygen -q -s /tmp/ca_krl -I krl-serial-revoked -z 4101 -n scoplen -V -1m:+10m /tmp/user_ed.pub
mv /tmp/user_ed-cert.pub /tmp/user_ed_krl-serial-cert.pub
ssh-keygen -q -s /tmp/ca_krl -I krl-id-revoked -z 4102 -n scoplen -V -1m:+10m /tmp/user_ed.pub
mv /tmp/user_ed-cert.pub /tmp/user_ed_krl-id-cert.pub
ssh-keygen -q -s /tmp/ca_krl -I krl-allowed -z 4103 -n scoplen -V -1m:+10m /tmp/user_ed.pub
mv /tmp/user_ed-cert.pub /tmp/user_ed_krl-allowed-cert.pub
cat > /tmp/krl_spec <<'KRL'
serial: 4101
id: krl-id-revoked
KRL
ssh-keygen -q -k -f /tmp/revoked.krl -s /tmp/ca_krl.pub /tmp/krl_spec
mkdir -p /home/scoplen/.ssh /run/sshd
cat /tmp/user_ed.pub /tmp/user_p256.pub /tmp/user_p384.pub /tmp/user_p521.pub /tmp/user_rsa.pub > /home/scoplen/.ssh/authorized_keys
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
# Avoid source penalties from intentional auth failures blocking later control connections.
PerSourcePenalties no
AllowTcpForwarding yes
Subsystem sftp internal-sftp
SSHD
exec /usr/sbin/sshd -D -e -f /tmp/sshd_config
'@
    $setup = $setup.Replace("`r", '').Replace('__OPENSSH_PACKAGE__', $serverProfile.Package)
    docker run -d --name $container -p '127.0.0.1::2222' $serverProfile.Image sh -c $setup | Out-Null
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
            $socket.ReceiveTimeout = 2000
            $reader = [System.IO.StreamReader]::new($socket.GetStream())
            $banner = $reader.ReadLine()
            $ready = $true
        }
        catch { Start-Sleep -Seconds 1 }
        finally { $socket.Dispose() }
        if ($ready) { break }
    }
    if (-not $ready) { throw 'OpenSSH did not become ready within 60 seconds' }
    $package = docker exec $container apk list --installed openssh-server
    if ($LASTEXITCODE -ne 0 -or -not ($package | Out-String).Trim().StartsWith($serverProfile.Installed, [System.StringComparison]::Ordinal) -or
        $banner -notmatch $serverProfile.Banner) {
        throw "Expected OpenSSH $ServerVersion package and SSH banner, got: $package; $banner"
    }
    Write-Output "OpenSSH $ServerVersion package and SSH banner verified"
    $fixtureFiles = @(
        'user_ed', 'user_p256', 'user_p384', 'user_p521', 'user_rsa', 'wrong_ed', 'wrong_p384', 'wrong_p521',
        'ca_trusted.pub', 'ca_other.pub', 'ca_krl.pub',
        'user_ed_good-cert.pub', 'user_p256-cert.pub', 'user_p384-cert.pub', 'user_p521-cert.pub', 'user_rsa-cert.pub',
        'user_p384_wrong-principal-cert.pub', 'user_p521_wrong-principal-cert.pub',
        'wrong_p384-cert.pub', 'wrong_p521-cert.pub',
        'user_ed_wrong-principal-cert.pub', 'user_ed_untrusted-cert.pub',
        'user_ed_krl-serial-cert.pub', 'user_ed_krl-id-cert.pub', 'user_ed_krl-allowed-cert.pub'
    )
    foreach ($name in $fixtureFiles) {
        docker cp "${container}:/tmp/$name" (Join-Path $tempRoot $name) | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not copy disposable OpenSSH fixture $name" }
    }
    foreach ($case in @(
        @{ Algorithm = 'ed25519'; Stem = 'sk_ed'; Prefix = 'sk-ssh-ed25519@openssh.com ' },
        @{ Algorithm = 'p256'; Stem = 'sk_p256'; Prefix = 'sk-ecdsa-sha2-nistp256@openssh.com ' }
    )) {
        foreach ($variant in @(
            @{ Argument = 'valid'; Suffix = '' },
            @{ Argument = 'wrong-key'; Suffix = '_other-key' },
            @{ Argument = 'wrong-application'; Suffix = '_other-application' }
        )) {
            $publicLine = & cargo run --quiet --locked -p scoplen-ssh --example security_key_interop -- public $case.Algorithm $variant.Argument
            if ($LASTEXITCODE -ne 0 -or -not $publicLine.StartsWith($case.Prefix, [System.StringComparison]::Ordinal)) {
                throw "Could not generate disposable $($case.Algorithm) $($variant.Argument) security-key identity"
            }
            $file = "$($case.Stem)$($variant.Suffix).pub"
            $keyPath = Join-Path $tempRoot $file
            Set-Content -LiteralPath $keyPath -Value $publicLine -Encoding ascii
            docker cp $keyPath "${container}:/tmp/$file" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Could not copy disposable $file security-key identity" }
        }
    }
    docker exec $container sh -c 'cat /tmp/sk_ed.pub /tmp/sk_p256.pub >> /home/scoplen/.ssh/authorized_keys && chown scoplen:scoplen /home/scoplen/.ssh/authorized_keys && chmod 600 /home/scoplen/.ssh/authorized_keys' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not authorize disposable security-key identities' }
    $securityKeyCertificates = @'
set -eu
for stem in sk_ed sk_p256; do
    ssh-keygen -q -s /tmp/ca_trusted -I "${stem}-valid" -z 4200 -n scoplen -V -1m:+10m "/tmp/${stem}.pub"
    mv "/tmp/${stem}-cert.pub" "/tmp/${stem}_valid-cert.pub"
    ssh-keygen -q -s /tmp/ca_trusted -I "${stem}-wrong-subject" -z 4204 -n scoplen -V -1m:+10m "/tmp/${stem}_other-key.pub"
    mv "/tmp/${stem}_other-key-cert.pub" "/tmp/${stem}_wrong-subject-cert.pub"
    ssh-keygen -q -s /tmp/ca_trusted -I "${stem}-wrong-application" -z 4205 -n scoplen -V -1m:+10m "/tmp/${stem}_other-application.pub"
    mv "/tmp/${stem}_other-application-cert.pub" "/tmp/${stem}_wrong-application-cert.pub"
    ssh-keygen -q -s /tmp/ca_trusted -I "${stem}-wrong-principal" -z 4207 -n other -V -1m:+10m "/tmp/${stem}.pub"
    mv "/tmp/${stem}-cert.pub" "/tmp/${stem}_wrong-principal-cert.pub"
    ssh-keygen -q -s /tmp/ca_trusted -I "${stem}-future" -z 4209 -n scoplen -V +5m:+10m "/tmp/${stem}.pub"
    mv "/tmp/${stem}-cert.pub" "/tmp/${stem}_future-cert.pub"
    ssh-keygen -q -s /tmp/ca_trusted -I "${stem}-expired" -z 4208 -n scoplen -V -10m:-5m "/tmp/${stem}.pub"
    mv "/tmp/${stem}-cert.pub" "/tmp/${stem}_expired-cert.pub"
    ssh-keygen -q -s /tmp/ca_other -I "${stem}-untrusted" -z 4206 -n scoplen -V -1m:+10m "/tmp/${stem}.pub"
    mv "/tmp/${stem}-cert.pub" "/tmp/${stem}_untrusted-cert.pub"
    ssh-keygen -q -s /tmp/ca_krl -I krl-allowed -z 4103 -n scoplen -V -1m:+10m "/tmp/${stem}.pub"
    mv "/tmp/${stem}-cert.pub" "/tmp/${stem}_krl-allowed-cert.pub"
    ssh-keygen -q -s /tmp/ca_krl -I krl-serial-revoked -z 4101 -n scoplen -V -1m:+10m "/tmp/${stem}.pub"
    mv "/tmp/${stem}-cert.pub" "/tmp/${stem}_krl-serial-cert.pub"
    ssh-keygen -q -s /tmp/ca_krl -I krl-id-revoked -z 4102 -n scoplen -V -1m:+10m "/tmp/${stem}.pub"
    mv "/tmp/${stem}-cert.pub" "/tmp/${stem}_krl-id-cert.pub"
done
'@
    docker exec $container sh -c ($securityKeyCertificates.Replace("`r", '')) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not sign disposable security-key user certificates' }
    foreach ($stem in @('sk_ed', 'sk_p256')) {
        foreach ($suffix in @('valid', 'wrong-subject', 'wrong-application', 'wrong-principal', 'future', 'expired', 'untrusted', 'krl-allowed', 'krl-serial', 'krl-id')) {
            $file = "${stem}_${suffix}-cert.pub"
            docker cp "${container}:/tmp/$file" (Join-Path $tempRoot $file) | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Could not copy disposable security-key certificate $file" }
        }
    }
    $env:SCOPLEN_OPENSSH_HOST = '127.0.0.1'
    $env:SCOPLEN_OPENSSH_PORT = $port.ToString()
    $env:SCOPLEN_OPENSSH_USER = 'scoplen'
    $env:SCOPLEN_OPENSSH_PASSWORD = 'scoplen-test-password'
    $env:SCOPLEN_OPENSSH_HOST_KEY = $hostKey
    $env:SCOPLEN_OPENSSH_SFTP = '1'
    $env:SCOPLEN_OPENSSH_FORWARD = '1'
    $env:SCOPLEN_OPENSSH_JUMP_TARGET_PORT = '2222'

    cargo run --quiet --locked -p scoplen-ssh --example openssh_interop
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSH SFTP or forwarding interop failed' }
    cargo run --quiet --locked -p scoplen-ssh --example proxy_command_interop
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSH ProxyCommand interop failed' }
    cargo run --quiet --locked -p scoplen-ssh --example dynamic_socks_interop
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSH dynamic SOCKS interop failed' }
    cargo run --quiet --locked -p scoplen-ssh --example jump_chain_interop
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSH nested jump interop failed' }

    $env:SCOPLEN_OPENSSH_PASSWORD = 'wrong-password'
    Invoke-AuthExample 'wrong password' 'AuthenticationRejected'

    Remove-Item Env:SCOPLEN_OPENSSH_SFTP, Env:SCOPLEN_OPENSSH_FORWARD, Env:SCOPLEN_OPENSSH_JUMP_TARGET_PORT
    $keyCases = @(
        @{ Name = 'Ed25519'; Variable = 'SCOPLEN_OPENSSH_ED25519_KEY'; File = 'user_ed'; Certificate = 'user_ed_good-cert.pub' },
        @{ Name = 'P-256'; Variable = 'SCOPLEN_OPENSSH_P256_KEY'; File = 'user_p256'; Certificate = 'user_p256-cert.pub' },
        @{ Name = 'P-384'; Variable = 'SCOPLEN_OPENSSH_ECDSA_KEY'; File = 'user_p384'; Certificate = 'user_p384-cert.pub' },
        @{ Name = 'P-521'; Variable = 'SCOPLEN_OPENSSH_ECDSA_KEY'; File = 'user_p521'; Certificate = 'user_p521-cert.pub' },
        @{ Name = 'RSA-SHA2-256'; Variable = 'SCOPLEN_OPENSSH_RSA_KEY'; File = 'user_rsa'; Certificate = 'user_rsa-cert.pub'; Hash = '256' },
        @{ Name = 'RSA-SHA2-512'; Variable = 'SCOPLEN_OPENSSH_RSA_KEY'; File = 'user_rsa'; Certificate = 'user_rsa-cert.pub'; Hash = '512' }
    )
    foreach ($case in $keyCases) {
        Clear-AuthMode
        Set-Item "Env:$($case.Variable)" (Join-Path $tempRoot $case.File)
        if ($case.Hash) { $env:SCOPLEN_OPENSSH_RSA_HASH = $case.Hash }
        Invoke-AuthExample "$($case.Name) public key"
    }

    foreach ($curve in @('p384', 'p521')) {
        Clear-AuthMode
        $env:SCOPLEN_OPENSSH_ECDSA_KEY = Join-Path $tempRoot "wrong_$curve"
        Invoke-AuthExample "unauthorized $curve public key" 'AuthenticationRejected'
    }

    Clear-AuthMode
    $env:SCOPLEN_OPENSSH_ED25519_KEY = Join-Path $tempRoot 'wrong_ed'
    Invoke-AuthExample 'unauthorized Ed25519 public key' 'AuthenticationRejected'

    Clear-AuthMode
    $env:SCOPLEN_OPENSSH_ED25519_KEY = Join-Path $tempRoot 'user_ed'
    $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot 'user_ed_wrong-principal-cert.pub'
    $env:SCOPLEN_OPENSSH_USER_CA_KEY = Join-Path $tempRoot 'ca_trusted.pub'
    Invoke-AuthExample 'wrong user-certificate principal' 'PrincipalMismatch'

    $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot 'user_ed_good-cert.pub'
    $env:SCOPLEN_OPENSSH_USER_CA_KEY = Join-Path $tempRoot 'ca_other.pub'
    Invoke-AuthExample 'wrong local user-certificate CA pin' 'UntrustedUserCa'

    $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot 'user_ed_untrusted-cert.pub'
    Invoke-AuthExample 'server-untrusted user-certificate CA' 'AuthenticationRejected'

    foreach ($case in $keyCases) {
        Clear-AuthMode
        Set-Item "Env:$($case.Variable)" (Join-Path $tempRoot $case.File)
        if ($case.Hash) { $env:SCOPLEN_OPENSSH_RSA_HASH = $case.Hash }
        $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot $case.Certificate
        $env:SCOPLEN_OPENSSH_USER_CA_KEY = Join-Path $tempRoot 'ca_trusted.pub'
        Invoke-AuthExample "$($case.Name) user certificate"
    }

    foreach ($curve in @('p384', 'p521')) {
        Clear-AuthMode
        $env:SCOPLEN_OPENSSH_ECDSA_KEY = Join-Path $tempRoot "user_$curve"
        $env:SCOPLEN_OPENSSH_USER_CA_KEY = Join-Path $tempRoot 'ca_trusted.pub'
        $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot "wrong_$curve-cert.pub"
        Invoke-AuthExample "$curve certificate wrong subject" 'KeyMismatch'
        $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot "user_${curve}_wrong-principal-cert.pub"
        Invoke-AuthExample "$curve certificate wrong principal" 'PrincipalMismatch'
    }

    Clear-AuthMode
    $env:SCOPLEN_OPENSSH_ED25519_KEY = Join-Path $tempRoot 'user_ed'
    $env:SCOPLEN_OPENSSH_USER_CA_KEY = Join-Path $tempRoot 'ca_krl.pub'
    $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot 'user_ed_krl-allowed-cert.pub'
    Invoke-AuthExample 'unrevoked certificate from KRL-trusted CA'

    $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot 'user_ed_krl-serial-cert.pub'
    Invoke-AuthExample 'serial-revoked user certificate' 'AuthenticationRejected'

    $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot 'user_ed_krl-id-cert.pub'
    Invoke-AuthExample 'key-ID-revoked user certificate' 'AuthenticationRejected'

    Clear-AuthMode
    $env:SCOPLEN_OPENSSH_ED25519_KEY = Join-Path $tempRoot 'user_ed'
    Invoke-AuthExample 'raw public key remains valid with KRL enabled'
    foreach ($algorithm in @('ed25519', 'p256')) {
        Invoke-SecurityKeyExample "$algorithm security key" $algorithm
        foreach ($fault in @('wrong-key', 'wrong-application', 'wrong-payload')) {
            Invoke-SecurityKeyExample "$algorithm security key $fault" $algorithm $fault 'AuthenticationRejected'
        }
    }
    foreach ($case in @(
        @{ Algorithm = 'ed25519'; Stem = 'sk_ed' },
        @{ Algorithm = 'p256'; Stem = 'sk_p256' }
    )) {
        $stem = $case.Stem
        $algorithm = $case.Algorithm
        $env:SCOPLEN_OPENSSH_USER_CA_KEY = Join-Path $tempRoot 'ca_trusted.pub'
        $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot "${stem}_valid-cert.pub"
        Invoke-SecurityKeyExample "$algorithm security-key certificate" $algorithm
        foreach ($fault in @('wrong-key', 'wrong-application', 'wrong-payload')) {
            Invoke-SecurityKeyExample "$algorithm security-key certificate $fault" $algorithm $fault 'AuthenticationRejected'
        }
        foreach ($caseName in @('wrong-subject', 'wrong-application')) {
            $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot "${stem}_${caseName}-cert.pub"
            Invoke-SecurityKeyExample "$algorithm certificate $caseName" $algorithm 'valid' 'KeyMismatch'
        }
        foreach ($rejection in @(
            @{ Suffix = 'wrong-principal'; Error = 'PrincipalMismatch' },
            @{ Suffix = 'future'; Error = 'NotYetValid' },
            @{ Suffix = 'expired'; Error = 'Expired' }
        )) {
            $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot "${stem}_$($rejection.Suffix)-cert.pub"
            Invoke-SecurityKeyExample "$algorithm certificate $($rejection.Suffix)" $algorithm 'valid' $rejection.Error
        }
        $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot "${stem}_valid-cert.pub"
        $env:SCOPLEN_OPENSSH_USER_CA_KEY = Join-Path $tempRoot 'ca_other.pub'
        Invoke-SecurityKeyExample "$algorithm certificate wrong local CA pin" $algorithm 'valid' 'UntrustedUserCa'
        $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot "${stem}_untrusted-cert.pub"
        Invoke-SecurityKeyExample "$algorithm certificate server-untrusted CA" $algorithm 'valid' 'AuthenticationRejected'
        $env:SCOPLEN_OPENSSH_USER_CA_KEY = Join-Path $tempRoot 'ca_krl.pub'
        $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot "${stem}_krl-allowed-cert.pub"
        Invoke-SecurityKeyExample "$algorithm certificate unrevoked by KRL" $algorithm
        foreach ($suffix in @('krl-serial', 'krl-id')) {
            $env:SCOPLEN_OPENSSH_USER_CERT = Join-Path $tempRoot "${stem}_${suffix}-cert.pub"
            Invoke-SecurityKeyExample "$algorithm certificate $suffix" $algorithm 'valid' 'AuthenticationRejected'
        }
        Remove-Item Env:SCOPLEN_OPENSSH_USER_CERT, Env:SCOPLEN_OPENSSH_USER_CA_KEY
        Invoke-SecurityKeyExample "$algorithm raw key remains valid with KRL enabled" $algorithm
    }
    Write-Output "OpenSSH $ServerVersion password, routes, software keys, security keys and certificates, user certificates, KRL revocation, and rejection paths passed"
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
        [System.IO.Path]::GetFileName($tempRoot).StartsWith('scoplen-openssh-keys-', [System.StringComparison]::Ordinal) -and
        (Test-Path -LiteralPath $tempRoot)) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
    foreach ($name in $testVariables) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
}
