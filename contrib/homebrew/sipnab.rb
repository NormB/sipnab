class Sipnab < Formula
  desc "SIP & RTP capture, analysis, and security"
  homepage "https://sipnab.com"
  url "https://github.com/NormB/sipnab/archive/refs/tags/v#{version}.tar.gz"
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
