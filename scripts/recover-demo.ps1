[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Ledger
)

$ErrorActionPreference = "Stop"
if (-not [System.IO.Path]::IsPathFullyQualified($Ledger)) {
    throw "Recovery ledger path must be absolute."
}
$ledgerPath = [System.IO.Path]::GetFullPath($Ledger)
uv run --no-sync python -m scripts.demo_e2e.recovery cleanup --ledger $ledgerPath
exit $LASTEXITCODE
