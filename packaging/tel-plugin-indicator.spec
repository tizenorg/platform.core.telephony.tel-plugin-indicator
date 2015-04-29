%define major 0
%define minor 1
%define patchlevel 62

Name:           tel-plugin-indicator
Version:        %{major}.%{minor}.%{patchlevel}
Release:        5
License:        Apache-2.0
Summary:        Telephony Indicator plugin
Group:          System/Libraries
Source0:        tel-plugin-indicator-%{version}.tar.gz
BuildRequires:  cmake
BuildRequires:  pkgconfig(deviced)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(tcore)
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
Telephony Indicator plugin

%prep
%setup -q

%build
versionint=$[%{major} * 1000000 + %{minor} * 1000 + %{patchlevel}]
CFLAGS+=" -fgnu89-inline "

%cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} \
	-DLIB_INSTALL_DIR=%{_libdir} \
	-DVERSION=$versionint \

make %{?_smp_mflags}

%post
/sbin/ldconfig

##setting vconf key##
vconftool set -t bool memory/testmode/fast_dormancy 0 -i -f -s telephony_framework::vconf
vconftool set -t bool memory/testmode/fast_dormancy2 0 -i -f -s telephony_framework::vconf

%postun -p /sbin/ldconfig

%install
%make_install
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%files
%manifest tel-plugin-indicator.manifest
%defattr(-,root,root,-)
%{_libdir}/telephony/plugins/indicator-plugin*
/usr/share/license/%{name}
