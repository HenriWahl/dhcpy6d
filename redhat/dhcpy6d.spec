%{?!dhcpy6d_uid:   %define dhcpy6d_uid dhcpy6d}
%{?!dhcpy6d_gid:   %define dhcpy6d_gid %dhcpy6d_uid}

%{!?python3_sitelib: %global python3_sitelib %(%{__python3} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}

Name:              dhcpy6d
Version:           1.0.9
Release:           1%{?dist}
Summary:           DHCPv6 server daemon

%if 0%{?suse_version}
Group:             Productivity/Networking/Boot/Servers
%else
Group:             System Environment/Daemons
%endif

License:           GPLv2
URL:               https://dhcpy6d.de
Source0:           https://github.com/HenriWahl/%{name}/archive/refs/tags/v%{version}.tar.gz
# in order to build from tarball
# tar -zxvf dhcpy6d-%%{version}.tar.gz -C ~/ dhcpy6d-%%{version}/redhat/init.d/dhcpy6d --strip-components=4&& rpmbuild -ta dhcpy6d-%%{version}.tar.gz&& rm -f ~/dhcpy6d
Source1:           %{name}

BuildRoot:         %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildArch: noarch

BuildRequires: python3
BuildRequires: python3-setuptools
BuildRequires: python3-devel
Requires: python3

BuildRequires: systemd
Requires: systemd

%if 0%{?suse_version}
Requires: python3-mysql
Requires: python3-dnspython
%else
Requires: python3-distro
Requires: python3-dns
Requires: python3-PyMySQL
%endif

Requires: coreutils
Requires: filesystem
Requires(pre): /usr/sbin/useradd, /usr/sbin/groupadd
Requires(post): coreutils, filesystem, systemd

Requires(preun): coreutils, /usr/sbin/userdel, /usr/sbin/groupdel
Requires: logrotate

%description
Dhcpy6d delivers IPv6 addresses for DHCPv6 clients, which can be identified by DUID, hostname or MAC address as in the good old IPv4 days. It allows easy dualstack transition, addresses may be generated randomly, by range, by DNS, by arbitrary ID or MAC address. Clients can get more than one address, leases and client configuration can be stored in databases and DNS can be updated dynamically.

%prep
%setup -q

%build
%py3_build
#CFLAGS="%{optflags}" %{__python3} setup.py build


%install
%{__python3} setup.py install --skip-build --prefix=%{_prefix} --install-scripts=%{_sbindir} --root=%{buildroot}
install -p -D -m 644 %{S:1} %{buildroot}%{_unitdir}/%{name}.service
install -p -D -m 644 etc/logrotate.d/%{name} %{buildroot}%{_sysconfdir}/logrotate.d/%{name}
/bin/chmod 0550 %{buildroot}%{_sbindir}/%{name}

%pre
# enable that only for non-root user!
%if "%{dhcpy6d_uid}" != "root"
/usr/sbin/groupadd -f -r %{dhcpy6d_gid} > /dev/null 2>&1 || :
/usr/sbin/useradd -r -s /sbin/nologin -d /var/lib/%{name} -M \
                  -g %{dhcpy6d_gid} %{dhcpy6d_uid} > /dev/null 2>&1 || :
%endif

%post
file=/var/log/%{name}.log
if [ ! -f ${file} ]
    then
    /bin/touch ${file}
fi
file=/var/lib/%{name}/volatile.sqlite
if [ ! -f ${file} ]
    then
    /bin/touch ${file}
fi
/bin/chown %{dhcpy6d_uid}:%{dhcpy6d_gid} ${file}
/bin/chmod 0640 ${file}

%preun
if [ "$1" = "0" ]; then
    /bin/systemctl %{name}.service stop > /dev/null 2>&1 || :
    /bin/rm -f /var/lib/%{name}/pid > /dev/null 2>&1 || :
    %{?stop_on_removal:
    %{stop_on_removal %{name}}
    }
    %{!?stop_on_removal:
    # undefined
    /bin/systemctl disable %{name}.service
    }
    # enable that only for non-root user!
    %if "%{dhcpy6d_uid}" != "root"
    /usr/sbin/userdel %{dhcpy6d_uid}
    if [ ! `grep %{dhcpy6d_gid} /etc/group` = "" ]; then
        /usr/sbin/groupdel %{dhcpy6d_uid}
    fi
    %endif
fi

%postun
if [ $1 -ge 1 ]; then
    %{?restart_on_update:
    %{restart_on_update %{name}}
    }
    %{!?restart_on_update:
    # undefined
    /bin/systemctl start %{name}.service > /dev/null 2>&1 || :
    }
fi


%files
%doc 
%{_defaultdocdir}/*
%{_mandir}/man?/*
%{_sbindir}/%{name}
%{python3_sitelib}/*dhcpy6*
%config(noreplace) %{_sysconfdir}/logrotate.d/%{name}
%config(noreplace) %{_sysconfdir}/%{name}.conf
%exclude %{_localstatedir}/log/%{name}.log
%exclude %{_localstatedir}/lib/%{name}/volatile.sqlite
%{_unitdir}/%{name}.service
%dir %attr(0775,%{dhcpy6d_uid},%{dhcpy6d_gid}) %{_localstatedir}/lib/%{name}
%config(noreplace) %attr(0644,%{dhcpy6d_uid},%{dhcpy6d_gid}) %{_localstatedir}/lib/%{name}/volatile.sqlite

%changelog
* Fri Jul 24 2020 Henri Wahl <h.wahl@ifw-dresden.de> - 1.0.1-1
- New upstream release

* Fri Apr 03 2020 Henri Wahl <h.wahl@ifw-dresden.de> - 1.0-1
- New upstream release

* Mon Apr 30 2018 Henri Wahl <h.wahl@ifw-dresden.de> - 0.7-1
- New upstream release

* Fri Sep 15 2017 Henri Wahl <h.wahl@ifw-dresden.de> - 0.6-1
- New upstream release

* Mon May 29 2017 Henri Wahl <h.wahl@ifw-dresden.de> - 0.5-1
- New upstream release

* Sat Dec 26 2015 Henri Wahl <h.wahl@ifw-dresden.de> - 0.4.3-1
- New upstream release

* Tue Aug 18 2015 Henri Wahl <h.wahl@ifw-dresden.de> - 0.4.2-1
- New upstream release

* Tue Mar 17 2015 Henri Wahl <h.wahl@ifw-dresden.de> - 0.4.1-1
- New upstream release

* Tue Oct 21 2014 Henri Wahl <h.wahl@ifw-dresden.de> - 0.4-1
- New upstream release

* Sun Jun 09 2013 Marcin Dulak <Marcin.Dulak@gmail.com> - 0.2-1
- RHEL and openSUSE versions based on Christopher Meng's spec

* Tue Jun 04 2013 Christopher Meng <rpm@cicku.me> - 0.2-1
- New upstream release.

* Thu May 09 2013 Christopher Meng <rpm@cicku.me> - 0.1.3-1
- Initial Package.
