[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
Push-Location -LiteralPath $ProjectRoot
try {
    uv run --no-project --python 3.12 python -m scripts.demo_e2e.clean_install `
        --source-root $ProjectRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Clean-install verification failed safely."
    }
}
finally {
    Pop-Location
}
