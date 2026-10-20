# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if (-not $IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'The native Windows agent fixture runs only on an isolated Windows GitHub Actions runner'
}

$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$targetDirectory = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $repository 'target' }
$example = Join-Path $targetDirectory 'debug/examples/windows_agent_interop.exe'
$tempRoot = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')
$tempDirectory = Join-Path $tempRoot ('scoplen-windows-agent-interop-' + [guid]::NewGuid().ToString('N'))
$keyPath = Join-Path $tempDirectory 'user_key'
$publicKeyPath = "$keyPath.pub"
$otherKeyPath = Join-Path $tempDirectory 'other_key'
$addAttempted = $false
$variables = @('SCOPLEN_AGENT_USER_KEY', 'SCOPLEN_AGENT_PIPE')
$originalEnvironment = @{}
foreach ($name in $variables) {
    $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    Remove-Item "Env:$name" -ErrorAction SilentlyContinue
}

function Invoke-Case {
    param(
        [string]$name,
        [string]$mode,
        [string]$userKey,
        [string]$expectedError = ''
    )

    $env:SCOPLEN_AGENT_USER_KEY = $userKey
    $outputPath = Join-Path $tempDirectory 'case.stdout'
    $errorPath = Join-Path $tempDirectory 'case.stderr'
    Remove-Item -LiteralPath $outputPath, $errorPath -ErrorAction SilentlyContinue
    $process = Start-Process -FilePath $example -ArgumentList $mode -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $outputPath -RedirectStandardError $errorPath
    if (-not $process.WaitForExit(45000)) {
        $process.Kill($true)
        $process.WaitForExit()
        throw "${name}: SSH example exceeded the 45-second fixture deadline"
    }
    $output = ([string](Get-Content -LiteralPath $outputPath -Raw)).Trim()
    $errorOutput = ([string](Get-Content -LiteralPath $errorPath -Raw)).Trim()
    if ($expectedError) {
        if ($process.ExitCode -eq 0 -or -not $errorOutput.Contains($expectedError)) {
            throw "${name}: expected '$expectedError', got exit $($process.ExitCode), stdout '$output', stderr '$errorOutput'"
        }
        Write-Output "${name}: rejected ($expectedError)"
    }
    else {
        if ($process.ExitCode -ne 0 -or $output -ne 'windows agent SSH command ok') {
            throw "${name}: expected command success, got exit $($process.ExitCode), stdout '$output', stderr '$errorOutput'"
        }
        Write-Output "${name}: windows agent SSH command ok"
    }
}

try {
    if ((Get-Service -Name ssh-agent).Status -ne 'Running') {
        throw 'The Windows OpenSSH ssh-agent service must be running before this fixture starts'
    }
    New-Item -ItemType Directory -Path $tempDirectory | Out-Null
    ssh-keygen -q -t ed25519 -N '' -C 'scoplen-agent-test' -f $keyPath
    if ($LASTEXITCODE -ne 0) { throw 'Could not generate disposable user key' }
    ssh-keygen -q -t ed25519 -N '' -C 'scoplen-agent-absent' -f $otherKeyPath
    if ($LASTEXITCODE -ne 0) { throw 'Could not generate disposable absent-identity key' }

    cargo build --locked -p scoplen-ssh --example windows_agent_interop
    if ($LASTEXITCODE -ne 0) { throw 'Could not build public Windows agent example' }
    $env:SCOPLEN_AGENT_PIPE = '\\.\pipe\openssh-ssh-agent'
    $userKey = (Get-Content -LiteralPath $publicKeyPath -Raw).Trim()
    $otherKey = (Get-Content -LiteralPath "$otherKeyPath.pub" -Raw).Trim()

    $addAttempted = $true
    $addOutput = ssh-add $keyPath 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "Could not add disposable key to Windows OpenSSH agent: $addOutput" }

    Invoke-Case 'raw key' 'raw' $userKey
    Invoke-Case 'missing identity' 'raw' $otherKey 'requested identity is absent from Windows OpenSSH agent'
    Invoke-Case 'raw control after missing identity' 'raw' $userKey
    Invoke-Case 'wrong host-key pin' 'wrong-host' $userKey 'unexpected test host key'
    Invoke-Case 'raw control after wrong pin' 'raw' $userKey
    $env:SCOPLEN_AGENT_PIPE = '\\.\pipe\scoplen-nonexistent-agent-' + [guid]::NewGuid().ToString('N')
    Invoke-Case 'missing agent pipe' 'raw' $userKey 'Windows agent pipe not found'
    $env:SCOPLEN_AGENT_PIPE = '\\.\pipe\openssh-ssh-agent'
    Invoke-Case 'raw control after missing pipe' 'raw' $userKey

    $removeOutput = ssh-add -d $publicKeyPath 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "Could not remove disposable key from Windows OpenSSH agent: $removeOutput" }
    $addAttempted = $false
    Invoke-Case 'removed identity' 'raw' $userKey 'requested identity is absent from Windows OpenSSH agent'
}
finally {
    if ($addAttempted) {
        ssh-add -d $publicKeyPath 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Warning 'Exact test-key removal failed; the isolated runner will be discarded' }
    }
    $resolvedTemp = [IO.Path]::GetFullPath($tempDirectory)
    if ($resolvedTemp.StartsWith($tempRoot + '\', [StringComparison]::OrdinalIgnoreCase) -and
        [IO.Path]::GetFileName($resolvedTemp).StartsWith('scoplen-windows-agent-interop-', [StringComparison]::Ordinal)) {
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
    foreach ($name in $variables) {
        [Environment]::SetEnvironmentVariable($name, $originalEnvironment[$name], 'Process')
    }
}
