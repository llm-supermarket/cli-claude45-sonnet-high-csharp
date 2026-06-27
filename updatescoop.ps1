param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$exePath = Join-Path $PSScriptRoot "artifacts" "cli-claude45-sonnet-csharp-win-x64.exe"

if (-not (Test-Path $exePath)) {
    throw "Unable to locate cli-claude45-sonnet-csharp-win-x64.exe at $exePath"
}

$hash = (Get-FileHash -Path $exePath -Algorithm SHA256).Hash.ToLower()

Write-Host "Hash: $hash"

$url = "https://github.com/llm-supermarket-org/cli-claude45-sonnet-csharp/releases/download/v$Version/cli-claude45-sonnet-csharp-win-x64.exe"

$manifestPath = Join-Path $PSScriptRoot "cli-claude45-sonnet-csharp.json"

$manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json

$manifest.version = $Version
$manifest.architecture."64bit".url = $url
$manifest.architecture."64bit".hash = $hash

$manifest | ConvertTo-Json -Depth 10 | Set-Content -Path $manifestPath -NoNewline

Write-Host "Updated cli-claude45-sonnet-csharp.json to v$Version"
