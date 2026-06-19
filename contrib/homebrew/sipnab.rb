class Sipnab < Formula
  desc "SIP & RTP capture, analysis, and security"
  homepage "https://sipnab.com"
  # `version` must be declared explicitly: the url interpolates #{version}, and
  # Homebrew otherwise tries to derive the version *from* the url -- a circular
  # dependency that resolves to an empty string (".../tags/v.tar.gz"). Bump both
  # `version` and `sha256` (of the GitHub source archive) on each release.
  version "0.4.3"
  url "https://github.com/NormB/sipnab/archive/refs/tags/v#{version}.tar.gz"
  sha256 "6c97d1e2cfbcdb7605c8463c689abbcc7530ffd7b5d69180b13bf766e0669b79"
  license "GPL-3.0-only"
  head "https://github.com/NormB/sipnab.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args, "--features", "full"
    man1.install "man/sipnab.1"
  end

  test do
    assert_match "sipnab", shell_output("#{bin}/sipnab --version")
  end
end
