class CliClaude45SonetCsharp < Formula
  desc "CLI tool to encrypt and decrypt files using rclone's crypt format"
  homepage "https://github.com/llm-supermarket-org/cli-claude45-sonnet-csharp"
  version "0.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/llm-supermarket-org/cli-claude45-sonnet-csharp/releases/download/v0.0.0/cli-claude45-sonnet-csharp-osx-arm64.tar.gz"
      sha256 "placeholder"
    else
      url "https://github.com/llm-supermarket-org/cli-claude45-sonnet-csharp/releases/download/v0.0.0/cli-claude45-sonnet-csharp-osx-x64.tar.gz"
      sha256 "placeholder"
    end
  end

  on_linux do
    url "https://github.com/llm-supermarket-org/cli-claude45-sonnet-csharp/releases/download/v0.0.0/cli-claude45-sonnet-csharp-linux-x64.tar.gz"
    sha256 "placeholder"
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
