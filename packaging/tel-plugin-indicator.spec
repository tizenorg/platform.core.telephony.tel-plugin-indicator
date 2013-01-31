Name:       tel-plugin-indicator
Summary:    Telephony Indicator plugin
Version:    0.1.7
Release:    2
Group:      System/Libraries
License:    Apache
Source0:    tel-plugin-indicator-%{version}.tar.gz
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(tcore)
BuildRequires:  pkgconfig(dlog)

%description
Telephony Indicator plugin

%prep
%setup -q

%build
%cmake .
make %{?jobs:-j%jobs}

%post 
/sbin/ldconfig

%postun -p /sbin/ldconfig

%install
%make_install
mkdir -p %{buildroot}/usr/share/license

%files
%manifest tel-plugin-indicator.manifest
%defattr(-,root,root,-)
%{_libdir}/telephony/plugins/indicator-plugin*
/usr/share/license/tel-plugin-indicator
