#sbs-git:slp/pkgs/t/tel-plugin-indicator
Name:       tel-plugin-indicator
Summary:    Telephony Indicator plugin
Version: 0.1.1
Release:    1
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
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}
make %{?jobs:-j%jobs}

%post 
/sbin/ldconfig

%postun -p /sbin/ldconfig

%install
rm -rf %{buildroot}
%make_install

%files
%defattr(-,root,root,-)
#%doc COPYING
%{_libdir}/telephony/plugins/indicator-plugin*
