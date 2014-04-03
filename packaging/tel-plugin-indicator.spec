%define major 3
%define minor 0
%define patchlevel 1

Name:       tel-plugin-indicator
Summary:    Telephony Indicator plugin
Version:        %{major}.%{minor}.%{patchlevel}
Release:    1
Group:      System/Libraries
License:    Apache-2.0
Source0:    tel-plugin-indicator-%{version}.tar.gz
Source1001: 	tel-plugin-indicator.manifest
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(tcore)

%description
Telephony Indicator plugin

%prep
%setup -q
cp %{SOURCE1001} .

%build
%cmake .
make %{?jobs:-j%jobs}

%post 
/sbin/ldconfig

%postun -p /sbin/ldconfig

%install
%make_install
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%files
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_libdir}/telephony/plugins/indicator-plugin*
/usr/share/license/%{name}
