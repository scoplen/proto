# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$owner = [guid]::NewGuid().ToString('N')
$container = 'scoplen-mixed-jump-' + $owner.Substring(0, 12)
$scratchRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$scratchName = 'scoplen-mixed-jump-' + $owner
$scratch = Join-Path $scratchRoot $scratchName
$attempted = $false
$completed = $false

function Check-LastExit([string]$description) {
    if ($LASTEXITCODE -ne 0) { throw "$description failed (exit $LASTEXITCODE)" }
}

try {
    New-Item -ItemType Directory -Path $scratch | Out-Null
    if ($IsWindows) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        ))
        Set-Acl -LiteralPath $scratch -AclObject $acl
    } else {
        & chmod 700 $scratch
        Check-LastExit 'restrict mixed Jump fixture directory'
    }

    $passwords = @(0..3 | ForEach-Object { 'disposable-' + [guid]::NewGuid().ToString('N') })
    $environmentArguments = @()
    for ($index = 0; $index -lt 4; $index++) {
        $environmentArguments += @('-e', "SCOPLEN_HOP_PASSWORD_$index=$($passwords[$index])")
    }
    $setup = @'
set -eu
apk add --no-cache dropbear=2024.86-r0 openssh-server=9.9_p2-r0 python3
mkdir -p /run/sshd
for index in 0 1 2 3; do
  adduser -D "hop$index"
  password=$(printenv "SCOPLEN_HOP_PASSWORD_$index")
  printf '%s:%s\n' "hop$index" "$password" | chpasswd
  printf '127.0.0.1 scoplen-jump-hop%s.invalid\n' "$index" >> /etc/hosts
  port=$((2230 + index))
  listen=127.0.0.1
  if [ "$index" -lt 2 ]; then listen=0.0.0.0; fi
  if [ "$((index % 2))" -eq 0 ]; then
    ssh-keygen -q -t ed25519 -N '' -f "/tmp/hop-$index-key"
    cp "/tmp/hop-$index-key.pub" "/tmp/hop-$index-public"
    cat > "/tmp/hop-$index.conf" <<SSHD
Port $port
ListenAddress $listen
HostKey /tmp/hop-$index-key
PidFile /tmp/hop-$index.pid
AllowUsers hop$index
UsePAM no
PasswordAuthentication yes
PubkeyAuthentication no
KbdInteractiveAuthentication no
AllowTcpForwarding yes
PermitOpen scoplen-jump-hop0.invalid:2230 scoplen-jump-hop1.invalid:2231 scoplen-jump-hop2.invalid:2232 scoplen-jump-hop3.invalid:2233 scoplen-jump-closed.invalid:2299 scoplen-jump-stall.invalid:2240
PerSourcePenalties no
LogLevel DEBUG1
SSHD
    /usr/sbin/sshd -t -f "/tmp/hop-$index.conf"
    /usr/sbin/sshd -D -E "/tmp/hop-$index.log" -f "/tmp/hop-$index.conf" &
  else
    dropbearkey -t ed25519 -f "/tmp/hop-$index-key" > /dev/null
    dropbearkey -y -f "/tmp/hop-$index-key" | sed -n '/^ssh-ed25519 /p' > "/tmp/hop-$index-public"
    dropbear -F -E -p "$listen:$port" -r "/tmp/hop-$index-key" > "/tmp/hop-$index.log" 2>&1 &
  fi
done
printf '127.0.0.1 scoplen-jump-closed.invalid scoplen-jump-stall.invalid\n' >> /etc/hosts
cat > /tmp/stalled-ssh.py <<'PY'
import socketserver
import threading

lock = threading.Lock()
accepted = closed = failed = 0

def save():
    with open('/tmp/stalled-ssh-counts', 'w') as output:
        output.write(f'{accepted} {closed} {failed}\n')

class Stalled(socketserver.BaseRequestHandler):
    def handle(self):
        global accepted, closed, failed
        with lock:
            accepted += 1
            save()
        self.request.settimeout(15)
        self.request.sendall(b'SSH-2.0-ScoplenFixture')
        received = b''
        try:
            while True:
                data = self.request.recv(4096)
                if not data:
                    if not received.startswith(b'SSH-2.0-'):
                        raise ValueError('no SSH identification before cancellation')
                    with lock:
                        closed += 1
                        save()
                    return
                received += data
                if len(received) > 4096:
                    raise ValueError('unexpected stalled SSH input')
        except Exception:
            with lock:
                failed += 1
                save()
            raise

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

with Server(('127.0.0.1', 2240), Stalled) as server:
    save()
    open('/tmp/stalled-ssh-ready', 'x').close()
    server.serve_forever()
PY
python3 /tmp/stalled-ssh.py > /tmp/stalled-ssh.log 2>&1 &
wait
'@
    $attempted = $true
    & docker run -d --stop-timeout 5 --name $container --label "scoplen.fixture.owner=$owner" `
        -p '127.0.0.1::2230' -p '127.0.0.1::2231' @environmentArguments `
        'alpine:3.21' sh -c ($setup.Replace("`r", '')) | Out-Null
    Check-LastExit 'start isolated pinned mixed Jump fixture'

    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        & docker exec $container sh -c 'test -f /tmp/stalled-ssh-ready && test -s /tmp/hop-0-public && test -s /tmp/hop-1-public && test -s /tmp/hop-2-public && test -s /tmp/hop-3-public && netstat -ltn | grep -q "127.0.0.1:2233"' 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw 'Mixed Jump SSH listeners did not become ready' }
    $packages = & docker exec $container apk info -v
    Check-LastExit 'read mixed Jump package versions'
    if ($packages -notcontains 'dropbear-2024.86-r0' -or $packages -notcontains 'openssh-server-9.9_p2-r0') {
        throw 'Mixed Jump server packages differed from their fixed versions'
    }

    $descriptor = Join-Path $scratch 'profiles'
    $rows = @()
    for ($index = 0; $index -lt 4; $index++) {
        $port = 2230 + $index
        $ingress = 0
        if ($index -lt 2) {
            $published = & docker port $container "$port/tcp"
            Check-LastExit 'read mixed Jump ingress port'
            if ($published -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'Mixed Jump ingress was not loopback-published' }
            $ingress = [int]$Matches[1]
        }
        $kind = if ($index % 2 -eq 0) { 'openssh' } else { 'dropbear' }
        $key = & docker exec $container cat "/tmp/hop-$index-public"
        Check-LastExit 'read disposable mixed Jump public identity'
        $rows += "$index|$kind|scoplen-jump-hop$index.invalid|$port|$ingress|hop$index|$($passwords[$index])|$($key.Trim())"
    }
    Set-Content -LiteralPath $descriptor -Value ($rows -join "`n") -NoNewline -Encoding utf8
    $buildLog = Join-Path $scratch 'build.log'
    & cargo build --locked --manifest-path (Join-Path $repository 'Cargo.toml') -p scoplen-ssh --example mixed_jump_interop *> $buildLog
    if ($LASTEXITCODE -ne 0) { throw 'Build mixed Jump public example failed' }
    $metadata = & cargo metadata --locked --no-deps --format-version 1 --manifest-path (Join-Path $repository 'Cargo.toml') | ConvertFrom-Json
    Check-LastExit 'read mixed Jump managed build directory'
    $suffix = if ($IsWindows) { '.exe' } else { '' }
    $smoke = Join-Path $metadata.target_directory "debug/examples/mixed_jump_interop$suffix"
    $launch = [Diagnostics.ProcessStartInfo]::new()
    $launch.FileName = $smoke
    $launch.ArgumentList.Add($descriptor)
    $launch.UseShellExecute = $false
    $launch.CreateNoWindow = $true
    $launch.RedirectStandardOutput = $true
    $launch.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $launch
    if (-not $process.Start()) { throw 'Mixed Jump example did not start' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    try {
        $finished = $process.WaitForExit(600000)
        if (-not $finished) {
            $process.Kill($true)
            $process.WaitForExit()
        }
        $output = $stdout.GetAwaiter().GetResult()
        $errors = $stderr.GetAwaiter().GetResult()
        Set-Content -LiteralPath (Join-Path $scratch 'smoke.stdout') -Value $output -NoNewline
        Set-Content -LiteralPath (Join-Path $scratch 'smoke.stderr') -Value $errors -NoNewline
        if (-not $finished) { throw 'Mixed Jump example exceeded its ten-minute fixture deadline' }
        if ($process.ExitCode -ne 0 -or $output -notmatch '(?m)^mixed OpenSSH/Dropbear Jump depths 1/2/3 acceptance passed\s*$') {
            throw 'Mixed Jump public API acceptance failed; private diagnostics retained'
        }
        Write-Output $output.Trim()
    } finally {
        if (-not $process.HasExited) { $process.Kill($true); $process.WaitForExit() }
        $process.Dispose()
    }

    $evidence = @'
set -eu
for index in 0 2; do
  grep -Eq 'target scoplen-jump-hop[0-3]\.invalid port 223[0-3]' "/tmp/hop-$index.log"
done
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if [ "$(cat /tmp/stalled-ssh-counts)" = '12 12 0' ] && ! netstat -tn | grep -E ':(2230|2231|2232|2233|2240)[[:space:]].*(ESTABLISHED|CLOSE_WAIT)' > /dev/null; then
    printf 'Mixed Jump parents and all twelve canceled remote handshakes closed\n'
    exit 0
  fi
  sleep 1
done
printf 'Owned SSH or stalled-handshake sockets remain after complete teardown\n' >&2
exit 1
'@
    & docker exec $container sh -c ($evidence.Replace("`r", ''))
    Check-LastExit 'verify mixed Jump remote names, canceled handshakes and complete parent cleanup'
    $completed = $true
} catch {
    if (Test-Path -LiteralPath $scratch) {
        Set-Content -LiteralPath (Join-Path $scratch 'failure.txt') -Value $_.Exception.Message
        if ($attempted) {
            & docker logs --tail 100 $container *> (Join-Path $scratch 'container.log')
            & docker exec $container sh -c 'cat /tmp/hop-0.log /tmp/hop-1.log /tmp/hop-2.log /tmp/hop-3.log /tmp/stalled-ssh.log /tmp/stalled-ssh-counts 2>/dev/null' *> (Join-Path $scratch 'servers.log')
        }
    }
    throw
} finally {
    if ($attempted) {
        $actualOwner = & docker inspect --format '{{index .Config.Labels "scoplen.fixture.owner"}}' $container 2>$null
        if ($LASTEXITCODE -eq 0 -and $actualOwner -eq $owner) {
            if ($completed) {
                & docker rm -f $container 2>$null | Out-Null
                Check-LastExit 'remove successful owned mixed Jump fixture'
            } else {
                & docker stop --time 5 $container 2>$null | Out-Null
                if ($LASTEXITCODE -eq 0) { Write-Warning "Stopped failed fixture $container; retained for diagnosis" }
                else { Write-Warning "Stop was not confirmed for owned fixture $container" }
            }
        } elseif ($completed) {
            throw 'Mixed Jump fixture ownership could not be verified for cleanup'
        }
    }
    if ($completed -and (Test-Path -LiteralPath $scratch)) {
        $resolved = (Resolve-Path -LiteralPath $scratch).Path
        $expected = [IO.Path]::GetFullPath((Join-Path $scratchRoot $scratchName))
        if ($resolved -ne $expected -or [IO.Path]::GetFileName($resolved) -ne $scratchName -or [IO.Path]::GetDirectoryName($resolved) -ne $scratchRoot) {
            throw 'Refusing mixed Jump cleanup outside the exact owned fixture directory'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    } elseif (Test-Path -LiteralPath $scratch) {
        Write-Warning "Mixed Jump private failure diagnostics retained at $scratch"
    }
}
