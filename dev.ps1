[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet("setup", "test", "lint", "build")]
    [string]$Action
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path $PSScriptRoot).Path

# See the comment on this setting in ./dev: a machine-level uv index would
# otherwise rewrite every URL in uv.lock, and nothing the project declares
# outranks it.  UV_CONFIG_FILE (not UV_NO_CONFIG) keeps .python-version
# honoured while suppressing the user-level configuration (RAY-400).
$env:UV_CONFIG_FILE = "NUL"
$uv = Get-Command ($env:UV_BIN ?? "uv") -ErrorAction SilentlyContinue
if (-not $uv) {
    Write-Error "uv is required; install it as a device bootstrap prerequisite."
    exit 127
}

Push-Location $projectRoot
try {
    & $uv.Source sync --locked --extra dev --reinstall-package techflex-cloud-foundation
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    switch ($Action) {
        "setup" { }
        "test" { & $uv.Source run --locked --extra dev python -m pytest }
        "lint" {
            & $uv.Source run --locked --extra dev ruff check .
            if ($LASTEXITCODE -eq 0) {
                & $uv.Source run --locked --extra dev mypy src/techflex_cloud_foundation
            }
        }
        "build" {
            & $uv.Source run --locked --extra dev python scripts/build_foundation_release.py `
                --project-root $projectRoot --uv-bin $uv.Source
        }
    }
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
