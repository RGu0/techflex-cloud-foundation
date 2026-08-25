[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet("setup", "test", "lint", "build")]
    [string]$Action
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path $PSScriptRoot).Path
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
            $releaseDirectory = Join-Path ([IO.Path]::GetTempPath()) ("techflex-cloud-foundation-" + [guid]::NewGuid().ToString("N"))
            New-Item -ItemType Directory -Path $releaseDirectory | Out-Null
            try {
                & $uv.Source build --out-dir $releaseDirectory
                if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
                & $uv.Source run --locked --extra dev python scripts/record_foundation_release_baseline.py `
                    --project-root $projectRoot `
                    --dist-dir $releaseDirectory `
                    --baseline-strategy legacy-httpx-client/1 `
                    --output (Join-Path $releaseDirectory "release-evidence.json")
            } finally {
                Remove-Item -LiteralPath $releaseDirectory -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
