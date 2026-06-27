param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$repo = "llm-supermarket/cli-claude45-sonnet-csharp"
$platforms = @("osx-arm64", "osx-x64", "linux-x64")
$formulaPath = "$PSScriptRoot/Formula/cli-claude45-sonnet-csharp.rb"
$base = "https://github.com/$repo/releases/download/v$Version"

$hash = @{}
foreach ($platform in $platforms) {
    $url = "$base/cli-claude45-sonnet-csharp-$platform.tar.gz"
    $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "cli-claude45-sonnet-csharp-$platform.tar.gz"

    Write-Host "Downloading $url ..."
    Invoke-WebRequest -Uri $url -OutFile $tempFile

    $hash[$platform] = (Get-FileHash -Path $tempFile -Algorithm SHA256).Hash.ToLower()
    Write-Host "SHA256 for ${platform}: $($hash[$platform])"

    Remove-Item $tempFile
}

$formula = @"
class CliClaude45SonetCsharp < Formula
  desc "CLI tool to encrypt and decrypt files using rclone's crypt format"
  homepage "https://github.com/$repo"
  version "$Version"

  on_macos do
    if Hardware::CPU.arm?
      url "$base/cli-claude45-sonnet-csharp-osx-arm64.tar.gz"
      sha256 "$($hash['osx-arm64'])"
    else
      url "$base/cli-claude45-sonnet-csharp-osx-x64.tar.gz"
      sha256 "$($hash['osx-x64'])"
    end
  end

  on_linux do
    url "$base/cli-claude45-sonnet-csharp-linux-x64.tar.gz"
    sha256 "$($hash['linux-x64'])"
  end

  def install
    bin.install "cli-claude45-sonnet-csharp-osx-arm64" => "cli-claude45-sonnet-csharp" if OS.mac? && Hardware::CPU.arm?
    bin.install "cli-claude45-sonnet-csharp-osx-x64" => "cli-claude45-sonnet-csharp" if OS.mac? && !Hardware::CPU.arm?
    bin.install "cli-claude45-sonnet-csharp-linux-x64" => "cli-claude45-sonnet-csharp" if OS.linux?
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/cli-claude45-sonnet-csharp --version")
  end
end
"@

Set-Content -Path $formulaPath -Value $formula -NoNewline
Write-Host "Wrote $formulaPath for version $Version"
