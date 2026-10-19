# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$container = 'scoplen-forwarded-agent-interop-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

try {
    docker run --rm --name $container `
        --mount "type=bind,source=$repository,target=/repo,readonly" `
        --workdir /repo `
        rust:1.99.0-bookworm bash scripts/ssh-agent-forwarded-interop.sh
    if ($LASTEXITCODE -ne 0) { throw "Forwarded OpenSSH agent interoperability failed (exit $LASTEXITCODE)" }
}
finally {
    docker rm -f $container 2>$null | Out-Null
}
