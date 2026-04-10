Name:           sipnab
Version:        %{version}
Release:        1%{?dist}
Summary:        SIP & RTP capture, analysis, and security

License:        GPL-3.0-only
URL:            https://sipnab.com
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo >= 1.92
BuildRequires:  libpcap-devel
Requires:       libpcap

%description
sipnab unifies sngrep and sipgrep into a single Rust binary with
first-class RTP support, VoIP diagnosis, security analysis, and
a declarative filter DSL.

%prep
%autosetup

%build
cargo build --release --features full

%install
install -Dm755 target/release/sipnab %{buildroot}%{_bindir}/sipnab
install -Dm644 man/sipnab.1 %{buildroot}%{_mandir}/man1/sipnab.1
install -Dm644 contrib/sipnab.service %{buildroot}%{_unitdir}/sipnab.service

%pre
getent passwd sipnab > /dev/null 2>&1 || useradd -r -s /sbin/nologin sipnab

%files
%license LICENSE
%doc README.md CONTRIBUTING.md
%{_bindir}/sipnab
%{_mandir}/man1/sipnab.1*
%{_unitdir}/sipnab.service
