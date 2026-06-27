class CliClaude45SonetCsharp < Formula
  desc "CLI tool to encrypt and decrypt files using rclone's crypt format"
  homepage "https://github.com/llm-supermarket/cli-claude45-sonnet-csharp"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/llm-supermarket/cli-claude45-sonnet-csharp/releases/download/v1.0.0/cli-claude45-sonnet-csharp-osx-arm64.tar.gz"
      sha256 "abb1c54c0288b9f5b4d33a3ab5f2db84f364f99e1c05ae868d93681bfecae455"
    else
      url "https://github.com/llm-supermarket/cli-claude45-sonnet-csharp/releases/download/v1.0.0/cli-claude45-sonnet-csharp-osx-x64.tar.gz"
      sha256 "c1247169795d26439544145a78313e6454b96b1d7efd3366a6e1353897fdbc88"
    end
  end

  on_linux do
    url "https://github.com/llm-supermarket/cli-claude45-sonnet-csharp/releases/download/v1.0.0/cli-claude45-sonnet-csharp-linux-x64.tar.gz"
    sha256 "51b4bdb8b35bd5376bb4d967fd7a70c2f5c2999ec164c2fc4f5975dcb5f90476"
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