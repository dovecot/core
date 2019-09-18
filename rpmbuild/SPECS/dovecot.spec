%global __provides_exclude_from %{_docdir}
%global __requires_exclude_from %{_docdir}
Summary: Secure imap and pop3 server
Name: dovecot
Epoch: 1
Version: 2.2.36.4
%global prever %{nil}
Release: 1%{?dist}
#dovecot itself is MIT, a few sources are PD, pigeonhole is LGPLv2
License: MIT and LGPLv2
Group: System Environment/Daemons

URL: http://www.dovecot.org/
Source: %{name}-%{version}%{?prever}.tar.gz
Source1: dovecot.init
Source2: dovecot.pam
%global pigeonholever 0.4.24
Source8: http://www.rename-it.nl/dovecot/2.2/dovecot-2.2-pigeonhole-%{pigeonholever}.tar.gz
#wget http://hg.rename-it.nl/dovecot-2.2-pigeonhole/archive/%{pigeonholever}.tar.bz2 -O dovecot-2.2-pigeonhole-%{pigeonholever}.tar.bz2
#Source8: dovecot-2.2-pigeonhole-%{pigeonholever}.tar.bz2
Source9: dovecot.sysconfig
Source10: dovecot.tmpfilesd

#our own
Source14: dovecot.conf.5

# 3x Fedora/RHEL specific
Patch1: dovecot-2.0-defaultconfig.patch
Patch2: dovecot-1.0.beta2-mkcert-permissions.patch
Patch3: dovecot-1.0.rc7-mkcert-paths.patch

Patch5: dovecot-2.1-privatetmp.patch

#wait for network
Patch6: dovecot-2.1.10-waitonline.patch

#workaround for chroot installation without /dev/random present, rhbz#1026790
Patch7: dovecot-2.2.9-nodevrand.patch

# sent upstream, rhbz#1630380
Patch9: dovecot-2.2.36-aclfix.patch

# dovecot < 2.3, rhbz#1280436
Patch10: dovecot-2.2-gidcheck.patch


Source15: prestartscript

Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: openssl-devel, pam-devel, zlib-devel, bzip2-devel, xz-devel, libcap-devel
BuildRequires: libtool, autoconf, automake, pkgconfig
BuildRequires: sqlite-devel, tcp_wrappers-devel
BuildRequires: postgresql-devel
BuildRequires: mysql-devel
BuildRequires: openldap-devel
BuildRequires: krb5-devel
BuildRequires: quota-devel

# gettext-devel is needed for running autoconf because of the
# presence of AM_ICONV
BuildRequires: gettext-devel

# Explicit Runtime Requirements for executalbe
Requires: openssl >= 0.9.7f-4

# Package includes an initscript service file, needs to require initscripts package
Requires(pre): shadow-utils
%if %{?fedora}0 > 140 || %{?rhel}0 > 60
Requires: systemd
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units
%else
Requires: initscripts
Requires(post): chkconfig
Requires(preun): chkconfig initscripts
Requires(postun): initscripts
%endif

%if %{?fedora}0 > 150 || %{?rhel}0 >60
#clucene in fedora <=15 and rhel<=6 is too old
BuildRequires: clucene-core-devel
%endif

%define ssldir %{_sysconfdir}/pki/%{name}

%if %{?fedora}00%{?rhel} < 6
%define _initddir %{_initrddir}
BuildRequires: curl-devel expat-devel
%else
BuildRequires: libcurl-devel expat-devel
%endif

%global restart_flag /var/run/%{name}/%{name}-restart-after-rpm-install

%description
Dovecot is an IMAP server for Linux/UNIX-like systems, written with security 
primarily in mind.  It also contains a small POP3 server.  It supports mail 
in either of maildir or mbox formats.

The SQL drivers and authentication plug-ins are in their subpackages.

%package pigeonhole
Requires: %{name} = %{epoch}:%{version}-%{release}
Obsoletes: dovecot-sieve < 1:1.2.10-3
Obsoletes: dovecot-managesieve < 1:1.2.10-3
Summary: Sieve and managesieve plug-in for dovecot
Group: System Environment/Daemons
License: MIT and LGPLv2

%description pigeonhole
This package provides sieve and managesieve plug-in for dovecot LDA.

%package pgsql
Requires: %{name} = %{epoch}:%{version}-%{release}
Summary: Postgres SQL back end for dovecot
Group: System Environment/Daemons
%description pgsql
This package provides the Postgres SQL back end for dovecot-auth etc.

%package mysql
Requires: %{name} = %{epoch}:%{version}-%{release}
Summary: MySQL back end for dovecot
Group: System Environment/Daemons
%description mysql
This package provides the MySQL back end for dovecot-auth etc.

%package devel
Requires: %{name} = %{epoch}:%{version}-%{release}
Summary: Development files for dovecot
Group: Development/Libraries
%description devel
This package provides the development files for dovecot.

%prep
%setup -q -n %{name}-%{version}%{?prever} -a 8
%patch1 -p1 -b .default-settings
%patch2 -p1 -b .mkcert-permissions
%patch3 -p1 -b .mkcert-paths
%patch6 -p1 -b .waitonline
%patch7 -p1 -b .nodevrand
%patch9 -p1 -b .aclfix
%patch10 -p1 -b .gidcheck
sed -i '/DEFAULT_INCLUDES *=/s|$| '"$(pkg-config --cflags libclucene-core)|" src/plugins/fts-lucene/Makefile.in
#pigeonhole
pushd dovecot-2*2-pigeonhole-%{pigeonholever}
popd

%build
#required for fdpass.c line 125,190: dereferencing type-punned pointer will break strict-aliasing rules
%global _hardened_build 1
export CFLAGS="-fno-strict-aliasing"
export LDFLAGS="-Wl,-z,now -Wl,-z,relro"
#autoreconf -I . -fiv #required for aarch64 support
%configure                       \
    INSTALL_DATA="install -c -p -m644" \
    --docdir=%{_docdir}/%{name}-%{version}     \
    --disable-static             \
    --disable-rpath              \
    --with-nss                   \
    --with-shadow                \
    --with-pam                   \
    --with-gssapi=plugin         \
    --with-ldap=plugin           \
    --with-sql=plugin            \
    --with-pgsql                 \
    --with-mysql                 \
    --with-sqlite                \
    --with-lzma                  \
    --with-zlib                  \
    --with-libcap                \
%if %{?fedora}0 > 150 || %{?rhel}0 >60
    --with-lucene                \
%endif
    --with-ssl=openssl           \
    --with-ssldir=%{ssldir}      \
    --with-solr                  \
%if %{?fedora}0 > 140 || %{?rhel}0 > 60
    --with-systemdsystemunitdir=%{_unitdir}  \
%endif
    --with-docs                  \
    --with-libwrap

sed -i 's|/etc/ssl|/etc/pki/dovecot|' doc/mkcert.sh doc/example-config/conf.d/10-ssl.conf

make %{?_smp_mflags}

#pigeonhole
pushd dovecot-2*2-pigeonhole-%{pigeonholever}

# required for snapshot
[ -f configure ] || autoreconf -fiv
[ -f ChangeLog ] || echo "Pigeonhole ChangeLog is not available, yet" >ChangeLog

%configure                             \
    INSTALL_DATA="install -c -p -m644" \
    --disable-static                   \
    --with-dovecot=../                 \
    --without-unfinished-features

make %{?_smp_mflags}
popd

%install
rm -rf $RPM_BUILD_ROOT

make install DESTDIR=$RPM_BUILD_ROOT

#move doc dir back to build dir so doc macro in files section can use it
mv $RPM_BUILD_ROOT/%{_docdir}/%{name}-%{version} %{_builddir}/%{name}-%{version}%{?prever}/docinstall


pushd dovecot-2*2-pigeonhole-%{pigeonholever}
make install DESTDIR=$RPM_BUILD_ROOT

mv $RPM_BUILD_ROOT/%{_docdir}/%{name}-%{version} $RPM_BUILD_ROOT/%{_docdir}/%{name}-pigeonhole

install -m 644 AUTHORS ChangeLog COPYING COPYING.LGPL INSTALL NEWS README $RPM_BUILD_ROOT/%{_docdir}/%{name}-pigeonhole
popd


%if %{?fedora}00%{?rhel} < 6
sed -i 's|password-auth|system-auth|' %{SOURCE2}
%endif

install -p -D -m 644 %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/pam.d/dovecot

#install man pages
install -p -D -m 644 %{SOURCE14} $RPM_BUILD_ROOT%{_mandir}/man5/dovecot.conf.5

#install waitonline script
install -p -D -m 755 %{SOURCE15} $RPM_BUILD_ROOT%{_libexecdir}/dovecot/prestartscript

# generate ghost .pem files
mkdir -p $RPM_BUILD_ROOT%{ssldir}/certs
mkdir -p $RPM_BUILD_ROOT%{ssldir}/private
touch $RPM_BUILD_ROOT%{ssldir}/certs/dovecot.pem
chmod 600 $RPM_BUILD_ROOT%{ssldir}/certs/dovecot.pem
touch $RPM_BUILD_ROOT%{ssldir}/private/dovecot.pem
chmod 600 $RPM_BUILD_ROOT%{ssldir}/private/dovecot.pem

%if %{?fedora}0 > 140 || %{?rhel}0 > 60
install -p -D -m 644 %{SOURCE10} $RPM_BUILD_ROOT%{_tmpfilesdir}/dovecot.conf
%else
install -p -D -m 755 %{SOURCE1} $RPM_BUILD_ROOT%{_initddir}/dovecot
install -p -D -m 600 %{SOURCE9} $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/dovecot
%endif

mkdir -p $RPM_BUILD_ROOT/var/run/dovecot/{login,empty}

# Install dovecot configuration and dovecot-openssl.cnf
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/dovecot/conf.d
install -p -m 644 docinstall/example-config/dovecot.conf $RPM_BUILD_ROOT%{_sysconfdir}/dovecot
install -p -m 644 docinstall/example-config/conf.d/*.conf $RPM_BUILD_ROOT%{_sysconfdir}/dovecot/conf.d
install -p -m 644 $RPM_BUILD_ROOT/%{_docdir}/%{name}-pigeonhole/example-config/conf.d/*.conf $RPM_BUILD_ROOT%{_sysconfdir}/dovecot/conf.d
install -p -m 644 docinstall/example-config/conf.d/*.conf.ext $RPM_BUILD_ROOT%{_sysconfdir}/dovecot/conf.d
install -p -m 644 $RPM_BUILD_ROOT/%{_docdir}/%{name}-pigeonhole/example-config/conf.d/*.conf.ext $RPM_BUILD_ROOT%{_sysconfdir}/dovecot/conf.d ||:
install -p -m 644 doc/dovecot-openssl.cnf $RPM_BUILD_ROOT%{ssldir}/dovecot-openssl.cnf

install -p -m755 doc/mkcert.sh $RPM_BUILD_ROOT%{_libexecdir}/%{name}/mkcert.sh

mkdir -p $RPM_BUILD_ROOT/var/lib/dovecot

#remove the libtool archives
find $RPM_BUILD_ROOT%{_libdir}/%{name}/ -name '*.la' | xargs rm -f

#remove what we don't want
rm -f $RPM_BUILD_ROOT%{_sysconfdir}/dovecot/README
pushd docinstall
rm -f securecoding.txt thread-refs.txt
popd


%clean
rm -rf $RPM_BUILD_ROOT


%pre
#dovecot uid and gid are reserved, see /usr/share/doc/setup-*/uidgid 
getent group dovecot >/dev/null || groupadd -r --gid 97 dovecot
getent passwd dovecot >/dev/null || \
useradd -r --uid 97 -g dovecot -d /usr/libexec/dovecot -s /sbin/nologin -c "Dovecot IMAP server" dovecot

getent group dovenull >/dev/null || groupadd -r dovenull
getent passwd dovenull >/dev/null || \
useradd -r -g dovenull -d /usr/libexec/dovecot -s /sbin/nologin -c "Dovecot's unauthorized user" dovenull

# do not let dovecot run during upgrade rhbz#134325
if [ "$1" = "2" ]; then
  rm -f %restart_flag
%if %{?fedora}0 > 140 || %{?rhel}0 > 60
  /bin/systemctl is-active %{name}.service >/dev/null 2>&1 && touch %restart_flag ||:
  /bin/systemctl stop %{name}.service >/dev/null 2>&1
%else
  /sbin/service %{name} status >/dev/null 2>&1 && touch %restart_flag ||:
  /sbin/service %{name} stop >/dev/null 2>&1
%endif
fi

%post
if [ $1 -eq 1 ]
then
%if %{?fedora}0 > 140 || %{?rhel}0 > 60
  %systemd_post dovecot.service
%else
  /sbin/chkconfig --add %{name}
%endif
fi

# generate the ssl certificates
if [ ! -f %{ssldir}/certs/%{name}.pem ]; then
    SSLDIR=%{ssldir} OPENSSLCONFIG=%{ssldir}/dovecot-openssl.cnf \
         %{_libexecdir}/%{name}/mkcert.sh &> /dev/null
fi

if [ ! -f /var/lib/dovecot/ssl-parameters.dat ]; then
    /usr/libexec/dovecot/ssl-params &>/dev/null
fi

install -d -m 0755 -g dovecot -d /var/run/dovecot
install -d -m 0755 -d /var/run/dovecot/empty
install -d -m 0750 -g dovenull /var/run/dovecot/login
/sbin/restorecon -R /var/run/dovecot 2>/dev/null || :

%preun
if [ $1 = 0 ]; then
%if %{?fedora}0 > 140 || %{?rhel}0 > 60
        /bin/systemctl disable dovecot.service dovecot.socket >/dev/null 2>&1 || :
        /bin/systemctl stop dovecot.service dovecot.socket >/dev/null 2>&1 || :
%else
    /sbin/service %{name} stop > /dev/null 2>&1
    /sbin/chkconfig --del %{name}
%endif
    rm -rf /var/run/dovecot
fi

%postun
%if %{?fedora}0 > 140 || %{?rhel}0 > 60
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
%endif

if [ "$1" -ge "1" -a -e %restart_flag ]; then
%if %{?fedora}0 > 140 || %{?rhel}0 > 60
    /bin/systemctl start dovecot.service >/dev/null 2>&1 || :
%else
    /sbin/service %{name} start >/dev/null 2>&1 || :
%endif
rm -f %restart_flag
fi

%posttrans
# dovecot should be started again in #postun, but it's not executed on reinstall
# if it was already started, restart_flag won't be here, so it's ok to test it again
if [ -e %restart_flag ]; then
%if %{?fedora}0 > 140 || %{?rhel}0 > 60
    /bin/systemctl start dovecot.service >/dev/null 2>&1 || :
%else
    /sbin/service %{name} start >/dev/null 2>&1 || :
%endif
rm -f %restart_flag
fi

%check
make check
cd dovecot-2*2-pigeonhole-%{pigeonholever}
make check

%files
%defattr(-,root,root,-)
%doc docinstall/* AUTHORS ChangeLog COPYING COPYING.LGPL COPYING.MIT NEWS README
%{_sbindir}/dovecot

%{_bindir}/doveadm
%{_bindir}/doveconf
%{_bindir}/dsync


%if %{?fedora}0 > 140 || %{?rhel}0 > 60
%_tmpfilesdir/dovecot.conf
%{_unitdir}/dovecot.service
%{_unitdir}/dovecot.socket
%else
%{_initddir}/dovecot
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/sysconfig/dovecot
%endif

%dir %{_sysconfdir}/dovecot
%dir %{_sysconfdir}/dovecot/conf.d
%config(noreplace) %{_sysconfdir}/dovecot/dovecot.conf
#list all so we'll be noticed if upstream changes anything
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/10-auth.conf
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/10-director.conf
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/10-logging.conf
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/10-mail.conf
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/10-master.conf
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/10-ssl.conf
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/15-lda.conf
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/15-mailboxes.conf
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/20-imap.conf
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/20-lmtp.conf
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/20-pop3.conf
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/90-acl.conf
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/90-quota.conf
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/90-plugin.conf
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/auth-checkpassword.conf.ext
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/auth-deny.conf.ext
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/auth-dict.conf.ext
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/auth-ldap.conf.ext
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/auth-master.conf.ext
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/auth-passwdfile.conf.ext
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/auth-sql.conf.ext
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/auth-static.conf.ext
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/auth-system.conf.ext
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/auth-vpopmail.conf.ext

%config(noreplace) %{_sysconfdir}/pam.d/dovecot
%config(noreplace) %{ssldir}/dovecot-openssl.cnf

%dir %{ssldir}
%dir %{ssldir}/certs
%dir %{ssldir}/private
%attr(0600,root,root) %ghost %config(missingok,noreplace) %verify(not md5 size mtime) %{ssldir}/certs/dovecot.pem
%attr(0600,root,root) %ghost %config(missingok,noreplace) %verify(not md5 size mtime) %{ssldir}/private/dovecot.pem

%dir %{_libdir}/dovecot
%dir %{_libdir}/dovecot/auth
%dir %{_libdir}/dovecot/dict
%dir %{_libdir}/dovecot/stats
%{_libdir}/dovecot/doveadm
%exclude %{_libdir}/dovecot/doveadm/*sieve*
%{_libdir}/dovecot/*.so.*
#these (*.so files) are plugins, not devel files
%{_libdir}/dovecot/*_plugin.so
%exclude %{_libdir}/dovecot/*_sieve_plugin.so
%{_libdir}/dovecot/auth/lib20_auth_var_expand_crypt.so
%{_libdir}/dovecot/auth/libauthdb_imap.so
%{_libdir}/dovecot/auth/libauthdb_ldap.so
%{_libdir}/dovecot/auth/libmech_gssapi.so
%{_libdir}/dovecot/auth/libdriver_sqlite.so
%{_libdir}/dovecot/dict/libdriver_sqlite.so
%{_libdir}/dovecot/dict/libdict_ldap.so
%{_libdir}/dovecot/stats/libstats_auth.so
%{_libdir}/dovecot/stats/libstats_mail.so
%{_libdir}/dovecot/libdriver_sqlite.so
%{_libdir}/dovecot/libssl_iostream_openssl.so
%{_libdir}/dovecot/libfs_compress.so
%{_libdir}/dovecot/libfs_crypt.so
%{_libdir}/dovecot/libfs_mail_crypt.so
%{_libdir}/dovecot/libdcrypt_openssl.so
%{_libdir}/dovecot/lib20_var_expand_crypt.so

%dir %{_libdir}/dovecot/settings

%{_libexecdir}/%{name}
%exclude %{_libexecdir}/%{name}/managesieve*

%attr(0755,root,dovecot) %ghost /var/run/dovecot
%attr(0750,root,dovenull) %ghost /var/run/dovecot/login
%attr(0755,root,root) %ghost /var/run/dovecot/empty
%attr(0750,dovecot,dovecot) /var/lib/dovecot

%{_datadir}/%{name}

%{_mandir}/man1/deliver.1*
%{_mandir}/man1/doveadm*.1*
%{_mandir}/man1/doveconf.1*
%{_mandir}/man1/dovecot*.1*
%{_mandir}/man1/dsync.1*
%{_mandir}/man5/dovecot.conf.5*
%{_mandir}/man7/doveadm-search-query.7*

%files pigeonhole
%defattr(-,root,root,-)
%{_bindir}/sieve-dump
%{_bindir}/sieve-filter
%{_bindir}/sieve-test
%{_bindir}/sievec
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/20-managesieve.conf
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/90-sieve.conf
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/90-sieve-extprograms.conf

%{_docdir}/%{name}-pigeonhole

%{_libexecdir}/%{name}/managesieve
%{_libexecdir}/%{name}/managesieve-login

%{_libdir}/dovecot/doveadm/*sieve*
%{_libdir}/dovecot/*_sieve_plugin.so
%{_libdir}/dovecot/settings/libmanagesieve_*.so
%{_libdir}/dovecot/settings/libpigeonhole_*.so
%{_libdir}/dovecot/sieve/

%{_mandir}/man1/sieve-dump.1*
%{_mandir}/man1/sieve-filter.1*
%{_mandir}/man1/sieve-test.1*
%{_mandir}/man1/sievec.1*
%{_mandir}/man1/sieved.1*
%{_mandir}/man7/pigeonhole.7*

%files mysql
%defattr(-,root,root,-)
%{_libdir}/%{name}/libdriver_mysql.so
%{_libdir}/%{name}/auth/libdriver_mysql.so
%{_libdir}/%{name}/dict/libdriver_mysql.so

%files pgsql
%defattr(-,root,root,-)
%{_libdir}/%{name}/libdriver_pgsql.so
%{_libdir}/%{name}/auth/libdriver_pgsql.so
%{_libdir}/%{name}/dict/libdriver_pgsql.so

%files devel
%{_includedir}/dovecot
%{_datadir}/aclocal/dovecot*.m4
%{_libdir}/dovecot/libdovecot*.so
%{_libdir}/dovecot/dovecot-config


%changelog
* Wed Sep 19 2018 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.36-3
- fix global ACL directory configuration search path (#1630380)
- update first/last_valid_gid range patch (#1630409)

* Mon Jul 30 2018 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.36-2
- fix defaut permissions of gost run files

* Tue Jun 12 2018 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.36-1
- dovecot updated to 2.2.36, pigeonhole to 0.4.24
- fixed dsync not replicating sieve scripts (#1419426)
- fix plugins incorrectly reporting epipe errors(#1489943)

* Tue Mar 21 2017 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.10-8
- do not iterate over users outside of first/last_valid_gid range (#1280436)

* Thu Jun 09 2016 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.10-7
- prevent warning messages from %%post section if selinux-policy is
  not installed (yet) (#1057522)
- compile with xz compression support enabled (#1176214)
- fix crash in sieve script compilation (#1177852)
- wait with start after network-online target (#1209006)
- build with tcp wrappers enabled (#1229164)
- fixed userdb extra fields handling in passdb failure (#1234868)
- fix valgrind option detection for make check (#1249625)
- first valid regular user id is 1000 (#1280433)
- fixed race condition when creating a new mailbox and another process getting its GUID (#1331478)
- fixed header parsing when there were multiple same header names (#1224496)

* Mon Jun 06 2016 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.10-6
- add devel sub-package (#1122676)

* Wed Jun 11 2014 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.10-5
- fix CVE-2014-3430: denial of service through maxxing out SSL connections (#1108004)

* Fri Jan 24 2014 Daniel Mach <dmach@redhat.com> - 1:2.2.10-4
- Mass rebuild 2014-01-24

* Wed Jan 15 2014 Honza Horak <hhorak@redhat.com> - 1:2.2.10-3
- Rebuild for mariadb-libs
  Related: #1045013

* Wed Jan 08 2014 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.10-2
- fix pigeonhole docdir name

* Fri Jan 03 2014 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.10-1
- dovecot updated to 2.2.10, pigeonhole updated to 0.4.2

* Fri Dec 27 2013 Daniel Mach <dmach@redhat.com> - 1:2.2.5-3
- Mass rebuild 2013-12-27

* Fri Dec 06 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.5-2
- fix chroot installation hang (#1026790)

* Wed Aug 07 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.5-1
- dovecot updated to 2.2.5

* Tue Jul 30 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.4-2
- dovecot pigeonhole updated to 0.4.1

* Fri Jul 19 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.4-1
- fix name conflict with cyrus-sasl
- dovecot updated to 2.2.4
- drop devel sub-package

* Mon Jun 17 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.3-1
- dovecot updated to 2.2.3
- IMAP: If subject contained only whitespace, Dovecot returned an
  ENVELOPE reply with a huge literal value, effectively causing the
  IMAP client to wait for more data forever.
- IMAP: Various URLAUTH fixes.
- imapc: Various bugfixes and improvements
- pop3c: Various fixes to make it work in dsync (without imapc)
- dsync: Fixes to syncing subscriptions. Fixes to syncing mailbox
  renames.

* Tue May 21 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.2-2
- fix location of tmpfiles configuration (#964448)

* Mon May 20 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.2-1
- dovecot updated to 2.2.2
- IMAP: Various URLAUTH fixes.
- IMAP: Fixed a hang with invalid APPEND parameters.
- IMAP LIST-EXTENDED: INBOX was never listed with \Subscribed flag.
- mailbox_list_index=yes still caused crashes.
- maildir: Fixed a crash after dovecot-keywords file was re-read.
- maildir: If files had reappeared unexpectedly to a Maildir, they
  were ignored until index files were deleted.
- Maildir: Fixed handling over 26 keywords in a mailbox. 
- imap/pop3-login proxying: Fixed a crash if TCP connection succeeded,
  but the remote login timed out.

* Thu May 16 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.1-4
- update pigeonhole to 0.4.0

* Mon Apr 29 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.1-3
- revert last change and use different fix

* Wed Apr 24 2013 Kalev Lember <kalevlember@gmail.com> - 1:2.2.1-2
- Filter out autogenerated perl deps (#956194)

* Fri Apr 19 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.1-1
- dovecot updated to 2.2.1
- mailbox_list_index=yes was broken.
- LAYOUT=index didn't list subscriptions.
- auth: Multiple master passdbs didn't work.
- Message parsing (e.g. during search) crashed when multipart message
  didn't actually contain any parts.
- dovecot updated to 2.2.1

* Mon Apr 15 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2.0-1
- dovecot updated to 2.2.0
- Mailbox list indexes weren't using proper file permissions based
  on the root directory.
- replicator: doveadm commands and user list export may have skipped
  some users.
- Various fixes to mailbox_list_index=yes

* Fri Apr 05 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2-0.4
- dovecot updated to 2.2 RC4
- various bugfixes to LDAP changes in rc3

* Wed Mar 27 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2-0.3
- dovecot updated to 2.2 RC3
- Fixed a crash when decoding quoted-printable content.
- dsync: Various bugfixes

* Thu Feb 28 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2-0.2
- do not print error when NetworkManager is not installed (#916456)

* Wed Feb 27 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.2-0.1
- major update to dovecot 2.2 RC2

* Mon Feb 11 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.15-1
- dovecot updated to 2.1.15
- v2.1.14's dovecot.index.cache fixes caused Dovecot to use more disk I/O
  and memory than was necessary.

* Tue Feb 05 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.14-2
- spec clean up

* Thu Jan 31 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.14-1
- dovecot updated to 2.1.14
- v2.1.11+ had a race condition where it sometimes overwrote data in
  dovecot.index.cache file. This could have caused Dovecot to return
  the same cached data to two different messages.
- mdbox: Fixes to handling duplicate GUIDs during index rebuild

* Tue Jan 15 2013 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.13-1
- dovecot updated to 2.1.13
- Some fixes to cache file changes in v2.1.11.
- virtual storage: Sorting mailbox by from/to/cc/bcc didn't work.

* Mon Dec 03 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.12-1
- dovecot updated to 2.1.12
- lmtp proxy: Fixed hanging if remote server was down.
- doveadm: Various fixes to handling doveadm-server connections.
- auth: passdb imap was broken in v2.1.10.

* Thu Nov 08 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.10-3
- fix network still not ready race condition (#871623)

* Fri Nov 02 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.10-2
- add reload command to service file

* Wed Sep 19 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.10-1
- dovecot updated to 2.1.10, pigeonhole updated to 0.3.3
- director: In some conditions director may have disconnected from
  another director (without logging about it), thinking it was sending
  invalid data.
- imap: Various fixes to listing mailboxes.
- login processes crashed if there were a lot of local {} or remote {}
  settings blocks.

* Fri Aug 24 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.9-2
- use new systemd rpm macros (#851238)

* Thu Aug 02 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.9-1
- dovecot updated to 2.1.9
- Full text search indexing might have failed for some messages,
  always causing indexer-worker process to run out of memory.
- fts-lucene: Fixed handling SEARCH HEADER FROM/TO/SUBJECT/CC/BCC when
  the header wasn't lowercased.
- fts-squat: Fixed crash when searching a virtual mailbox.
- pop3: Fixed assert crash when doing UIDL on empty mailbox on some
  setups. 
- auth: GSSAPI RFC compliancy and error handling fixes.
- Various fixes related to handling shared namespaces

* Wed Jul 18 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1:2.1.8-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Tue Jul 03 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.8-2
- pigeonhole updated to 0.3.1
- Fixed several small issues, including a few potential segfault bugs, based
  on static source code analysis.

* Tue Jul 03 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.8-1
- dovecot updated to 2.1.8
- imap: Mailbox names were accidentally sent as UTF-8 instead of mUTF-7
  in previous v2.1.x releases for STATUS, MYRIGHTS and GETQUOTAROOT commands.
- lmtp proxy: Don't timeout connections too early when mail has a lot of RCPT TOs.
- director: Don't crash if the director is working alone.
- shared mailboxes: Avoid doing "@domain" userdb lookups.
- doveadm: Fixed crash with proxying some commands.
- fts-squat: Fixed handling multiple SEARCH parameters.
- imapc: Fixed a crash when message had more than 8 keywords.
- imapc: Don't crash on APPEND/COPY if server doesn't support UIDPLUS.


* Mon Jul 02 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.7-5
- make quota work with NFS mounted mailboxes

* Fri Jun 22 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.7-4
- posttrans argument is always zero

* Fri Jun 15 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.7-3
- do not let dovecot run during upgrade (#134325)

* Wed May 30 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.7-2
- fix changelog, 2.1.7-1 had copy-pasted upstream changelog, which was wrong
- director: Don't crash with quickly disconnecting incoming director
  connections.
- mdbox: If mail was originally saved to non-INBOX, and namespace
  prefix is non-empty, don't assert-crash when rebuilding indexes.
- sdbox: Don't use more fds than necessary when copying mails.
- auth: Fixed crash with DIGEST-MD5 when attempting to do master user
  login without master passdbs. 
- Several fixes to mail_shared_explicit_inbox=no
- imapc: Use imapc_list_prefix also for listing subscriptions.

* Wed May 30 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.7-1
- updated to 2.1.7
- v2.1.5: Using "~/" as mail_location or elsewhere failed to actually
  expand it to home directory.
- dbox: Fixed potential assert-crash when reading dbox files.
- trash plugin: Fixed behavior when quota is already over limit.
- mail_log plugin: Logging "copy" event didn't work.
- Proxying to backend server with SSL: Verifying server certificate
  name always failed, because it was compared to an IP address.

* Wed May 09 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.6-2
- fix socket activation again, fix in 2.1.6 is incomplete

* Wed May 09 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.6-1
- v2.1.5: Using "~/" as mail_location or elsewhere failed to actually
  expand it to home directory.
- dbox: Fixed potential assert-crash when reading dbox files.
- trash plugin: Fixed behavior when quota is already over limit.
- Proxying to backend server with SSL: Verifying server certificate
  name always failed, because it was compared to an IP address.

* Tue Apr 24 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.5-1
- IMAP: Several fixes related to mailbox listing in some configs
- director: A lot of fixes and performance improvements
- mbox: Deleting a mailbox didn't delete its index files.
- pop3c: TOP command was sent incorrectly
- trash plugin didn't work properly
- LMTP: Don't add a duplicate Return-Path: header when proxying.
- listescape: Don't unescape namespace prefixes.

* Tue Apr 24 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.4-2
- close systemd extra sockets that are not configured

* Tue Apr 10 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.4-1
- dovecot updated to 2.1.4
- Proxying SSL connections crashed in v2.1.[23]
- fts-solr: Indexing mail bodies was broken.
- director: Several changes to significantly improve error handling
- doveadm import didn't import messages' flags
- mail_full_filesystem_access=yes was broken
- Make sure IMAP clients can't create directories when accessing
  nonexistent users' mailboxes via shared namespace.
- Dovecot auth clients authenticating via TCP socket could have failed
  with bogus "PID already in use" errors.

* Mon Mar 19 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.3-1
- dovecot updated to 2.1.3
- multi-dbox format in dovecot 2.1.2 was broken
- temporarily disable check phase until bug #798968 is fixed

* Fri Mar 16 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.2-1
- dovecot updated to 2.1.2
- doveadm sync: If mailbox was expunged empty, messages may have
  become back instead of also being expunged in the other side.
- imap_id_* settings were ignored before login.
- Several fixes to mailbox_list_index=yes
- Previous v2.1.x didn't log all messages at shutdown.

* Thu Mar 01 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.1-2
- enable fts_lucene plugin (#798661)

* Fri Feb 24 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.1-1
- dovecot updated to 2.1.1
- acl plugin + autocreated mailboxes crashed when listing mailboxes
- doveadm force-resync: Don't skip autocreated mailboxes (especially
  INBOX). 
- If process runs out of fds, stop listening for new connections only
  temporarily, not permanently (avoids hangs with process_limit=1
  services)
- auth: passdb imap crashed for non-login authentication (e.g. smtp).


* Mon Feb 20 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1.0-1
- updated to 2.1.0 (no major changes since .rc6)
- include pigeonhole doc files (NEWS, README, ...)

* Tue Feb 14 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1-0.7.rc6
- updated to 2.1.rc6
- dbox: Fixed error handling when saving failed or was aborted
- IMAP: Using COMPRESS extension may have caused assert-crashes
- IMAP: THREAD REFS sometimes returned invalid (0) nodes.
- dsync: Fixed handling non-ASCII characters in mailbox names.

* Tue Feb 07 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1-0.6.rc5
- use PrivateTmp in systemd unit file

* Tue Feb 07 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1-0.5.rc5
- updated to 2.1.rc5
- director: With >2 directors ring syncing might have stalled during
  director connect/disconnect, causing logins to fail.
- LMTP client/proxy: Fixed potential hanging when sending (big) mails
- Compressed mails with external attachments (dbox + SIS + zlib) failed
  sometimes with bogus "cached message size wrong" errors.

* Mon Jan 09 2012 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1-0.4.rc3
- updated to 2.1.rc3
- dsync was merged into doveadm
- added pop3c (= POP3 client) storage backend

* Wed Dec 14 2011 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1-0.3.rc1
- allow imap+TLS and pop3+TLS by default

* Fri Dec 02 2011 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1-0.2.rc1
- call systemd reload in postun

* Wed Nov 30 2011 Michal Hlavinka <mhlavink@redhat.com> - 1:2.1-0.1.rc1
- updated to 2.1.rc1
- major changes since 2.0.x:
- plugins now use UTF-8 mailbox names rather than mUTF-7
- auth_username_format default changed to %Lu
- solr full text search backend changed to use mailbox GUIDs instead of
  mailbox names, requiring reindexing everything

* Mon Nov 21 2011 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.16-1
- dovecot updated to 2.0.16

* Mon Oct 24 2011 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.15-2
- do not use obsolete settings in default configuration (#743444)

* Mon Sep 19 2011 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.15-1
- dovecot updated to 2.0.15
- v2.0.14: Index reading could have eaten a lot of memory in some
  situations
- mbox: Fixed crash during mail delivery when mailbox didn't yet have
  GUID assigned to it.
- zlib+mbox: Fetching last message from compressed mailboxes crashed.

* Tue Sep 13 2011 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.14-2
- do not enable insecure connections by default

* Mon Aug 29 2011 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.14-1
- dovecot updated to 2.0.14
- userdb extra fields can now return name+=value to append to an
  existing name
- script-login attempted an unnecessary config lookup, which usually
  failed with "Permission denied".
- lmtp: Fixed parsing quoted strings with spaces as local-part for
  MAIL FROM and RCPT TO.
- imap: FETCH BODY[HEADER.FIELDS (..)] may have crashed or not
  returned all data sometimes.
- ldap: Fixed random assert-crashing with with sasl_bind=yes.
- Fixes to handling mail chroots
- Fixed renaming mailboxes under different parent with FS layout when
  using separate ALT, INDEX or CONTROL paths.
- zlib: Fixed reading concatenated .gz files.

* Fri Jul 15 2011 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.13-2
- do not include sysv init script

* Thu May 12 2011 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.13-1
- dovecot updated to 2.0.13
- mdbox purge: Fixed wrong warning about corrupted extrefs.
- script-login binary wasn't actually dropping privileges to the
  user/group/chroot specified by its service settings.
- Fixed potential crashes and other problems when parsing header names
  that contained NUL characters.

* Fri Apr 15 2011 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.12-2
- pigeonhole updated to 0.2.3, which includes:
- managesieve: fixed bug in UTF-8 checking of string values
- sieve command line tools now avoid initializing the mail store unless necessary
- removed header MIME-decoding to fix erroneous address parsing
- fixed segfault bug in extension configuration, triggered when unknown
  extension is mentioned in sieve_extensions setting.

* Wed Apr 13 2011 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.12-1
- dbox: Fixes to handling external attachments
- dsync: More fixes to avoid hanging with remote syncs
- dsync: Many other syncing/correctness fixes
- doveconf: v2.0.10 and v2.0.11 didn't output plugin {} section right

* Mon Mar 28 2011 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.11-5
- rebuild with new patch

* Mon Mar 28 2011 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.11-4
- fix regression in config file parsing (#690401)

* Wed Mar 23 2011 Dan Horák <dan@danny.cz> - 1:2.0.11-3
- rebuilt for mysql 5.5.10 (soname bump in libmysqlclient)

* Wed Mar 23 2011 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.11-2
- rebuild because of updated dependencies

* Mon Mar 07 2011 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.11-1
- IMAP: Fixed hangs with COMPRESS extension
- IMAP: Fixed a hang when trying to COPY to a nonexistent mailbox. 
- IMAP: Fixed hang/crash with SEARCHRES + pipelining $.
- IMAP: Fixed assert-crash if IDLE+DONE is sent in same TCP packet.

* Thu Feb 17 2011 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.9-3
- add missing section to dovecot's systemd service file

* Tue Feb 08 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1:2.0.9-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Thu Jan 13 2011 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.9-1
- dovecot updated to 2.0.9
- fixed a high system CPU usage / high context switch count performance problem
- lda: Fixed a crash when trying to send "out of quota" reply

* Mon Dec 20 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.8-3
- add full path and check to restorecon in post

* Tue Dec 07 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.8-2
- fix s/foobar/dovecot/ typo in post script

* Tue Dec 07 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.8-1
- dovecot updated to 2.0.8, pigeonhole updated to 0.2.2
- services' default vsz_limits weren't being enforced correctly
- added systemd support
- dbox: Fixes to handling external mail attachments
- imap, pop3: When service { client_count } was larger than 1, the
  log messages didn't use the correct prefix
- MySQL: Only the first specified host was ever used

* Mon Nov 29 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.7-3
- make it work with /var/run on tmpfs (#656577)

* Tue Nov 23 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.7-2
- fix regression with  valid_chroot_dirs being ignored (#654083)

* Tue Nov 09 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.7-1
- dovecot updated to 2.0.7
- IMAP: Fixed LIST-STATUS when listing subscriptions with subscriptions=no namespaces.
- IMAP: Fixed SELECT QRESYNC not to crash on mailbox close if a lot of changes were being sent. 
- quota: Don't count virtual mailboxes in quota
- doveadm expunge didn't always actually do the physical expunging
- Fixed some index reading optimizations introduced by v2.0.5.
- LMTP proxying fixes

* Fri Oct 22 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.6-1
- dovecot updated to 2.0.6
- Pre-login CAPABILITY includes IDLE again. Mainly to make Blackberry
  servers happy.
- auth: auth_cache_negative_ttl default was 0 in earlier v2.0.x, but it
  was supposed to be 1 hour as in v1.x. Changed it back to 1h.
- doveadm: Added import command for importing mails from other storages.
- Reduced NFS I/O operations for index file accesses
- dbox, Maildir: When copying messages, copy also already cached fields
  from dovecot.index.cache
- Maildir: LDA/LMTP assert-crashed sometimes when saving a mail.
- Fixed leaking fds when writing to dovecot.mailbox.log.
- Fixed rare dovecot.index.cache corruption
- IMAP: SEARCH YOUNGER/OLDER wasn't working correctly

* Mon Oct 04 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.5-1
- dovecot updated to 2.0.5
- acl: Fixed the logic of merging multiple ACL entries
- sdbox: Fixed memory leak when copying messages with hard links. 
- zlib: Fixed several crashes, which mainly showed up with mbox.
- quota: Don't crash if user has quota disabled, but plugin loaded.
- acl: Fixed crashing when sometimes listing shared mailboxes via dict proxy.

* Tue Sep 28 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.4-1
- dovecot updated to 2.0.4
- multi-dbox: If :INDEX=path is specified, keep storage/dovecot.map.index* 
  files also in the index path rather than in the main storage directory.
- dsync: POP3 UIDLs weren't copied with Maildir
- dict file: Fixed fd leak (showed up easily with LMTP + quota)

* Mon Sep 20 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.3-1
- dovecot updated to 2.0.3
- dovecot-lda: Removed use of non-standard Envelope-To: header as 
  a default for -a
- dsync: Fixed handling \Noselect mailboxes
- Fixed an infinite loop introduced by v2.0.2's message parser changes.
- Fixed a crash introduced by v2.0.2's istream-crlf changes.

* Thu Sep 16 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.2-1
- dovecot updated
- vpopmail support is disabled for now, since it's broken. You can use
  it via checkpassword support or its sql/ldap database directly.
- maildir: Fixed "duplicate uidlist entry" errors that happened at
  least with LMTP when mail was delivered to multiple recipients
- Deleting ACLs didn't cause entries to be removed from acl_shared_dict
- mail_max_lock_timeout setting wasn't working with all locks

* Wed Aug 25 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0.1-1
- dovecot and pigeonhole updated
- sieve: sieved renamed to sieve-dump
- when dsync is started as root, remote dsync command is now also executed 
  as root instead of with dropped privileges.
- IMAP: QRESYNC parameters for SELECT weren't handled correctly.
- UTF-8 string validity checking wasn't done correctly
- dsync: Fixed a random assert-crash with remote dsyncing

* Tue Aug 17 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-1
- dovecot and pigeonhole updated
- dict quota didn't always decrease quota when messages were expunged
- Shared INBOX wasn't always listed with FS layout

* Wed Aug 11 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.21.rc5
- dovecot and pigeonhole updated
- Using more than 2 plugins could have caused broken behavior
- Listescape plugin fixes
- mbox: Fixed a couple of assert-crashes
- mdbox: Fixed potential assert-crash when saving multiple messages 
  in one transaction

* Thu Aug 05 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.20.rc4
- dovecot and pigeonhole updated
- doveadm mailbox status: Fixed listing non-ASCII mailbox names. 
- doveadm fetch: Fixed output when fetching message header or body
- doveadm director map/add/remove: Fixed handling IP address as parameter. 
- dsync: A few more fixes

* Wed Jul 21 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.19.rc3
- dovecot and pigeonhole updated
- fixed lda + sieve crash
- added mail_temp_dir setting, used by deliver and lmtp for creating
  temporary mail files. Default is /tmp.
- imap: Fixed checking if list=children namespace has children.
- mdbox: Race condition fixes related to copying and purging

* Fri Jul 16 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.18.rc2.20100716
- dovecot and pigeonhole updated
- enabled pigeonhole's build time test suite
- acl: Fixed crashon FS layout with non-default hierarchy separator
- dbox renamed to sdbox
- dsync fixes and improvements

* Mon Jul 12 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.17.rc2.20100712
- dovecot and pigeonhole updated
- fixed a crash with empty mail_plugins
- fixed sharing INBOX to other users
- director+LMTP proxy wasn't working correctly
- v1.x config parser failed with some settings if pigeonhole wasn't installed.
- virtual: If non-matching messages weren't expunged within same session,
  they never got expunged.

* Wed Jul 07 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.16.rc1.20100707
- updated dovecot and pigeonhole
- a lot of dsync fixes
- improved (m)dbox recovery

* Mon Jun 28 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.15.beta6.20100626
- updated dovecot, pigeonhole and man pages
- moved disable_plaintext_auth to 10-auth.conf
- mdbox: Fixed assert-crash on storage rebuild if file got lost
- lib-charset: Don't assert-crash when iconv() skips lots of invalid input
- master: Fixed crash on deinit (maybe also on reload)

* Thu Jun 10 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.14.beta5.20100610
- dovecot updated 
- lib-storage: Fixed accessing uncommitted saved mails with dsync
- example-config: Moved ACL and quota settings to a separate .conf files
- dbox, mdbox: Fixed race conditions when creating mailboxes

* Mon May 31 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.13.beta5.20100529
- dovecot and pigeonhole updated
- enable solr fulltext search
- master: Fixed crash on config reload
- lib-storage: Don't assert-crash when copying a mail fails

* Tue May 18 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.12.beta5.20100515
- dovenull is unauthorized user, needs own dovenull group

* Tue May 18 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.11.beta5.20100515
- fix typo in dovenull username

* Mon May 17 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.9.beta5.20100515
- pigeonhole and dovecot updated to snapshot 20100515
- fix crash for THREAD command

* Wed May 05 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.8.beta4.20100505
- pigeonhole and dovecot updated to snapshot 20100505
- mdbox: Avoid rebuilding storage if another process already did it
- lib-storage: Fixed () sublists in IMAP SEARCH parser
- example-config: auth-checkpassword include wasn't listed in 10-auth.conf
- doveadm: Added search command
- lib-master: Don't crash after timeouting an auth-master request
- master: If inet listener uses DNS name, which returns multiple IPs, 
  listen in all of them

* Wed Apr 28 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.7.beta4.20100427
- updated to snapshot 20100427
- doveconf <setting name> now prints only the one setting's value
- mdbox: Automatically delete old temp.* files from storage/ directory
- mdbox: use flock locking by default

* Wed Apr 21 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.6.beta4.20100421
- updated to snapshot 20100421
- mdbox: Purge crashed if it purged all messages from a file
- lib-storage: Shared namespace's prefix_len wasn't updated after prefix was truncated
- imap-quota: Iterate quota roots only once when replying to GETQUOTAROOT
- idle: Do cork/uncork when sending "OK Still here" notification
- login: If proxy returns ssl=yes and no port, switch port to imaps/pop3s

* Wed Apr 14 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.5.beta4.20100414
- add make check
- updated to snapshot 20100414
- config: Added nn- prefix to *.conf files so the sort ordering makes more sense
- lib-master: Log an error if login client disconnects too early
- mdbox: If purging found corrupted files, it didn't auto-rebuild storage
- lib-storage: Added support for searching save date
- and more...
- pigeonhole updated:
- Mailbox extension: fixed memory leak in the mailboxexists test
- added login failure handler

* Tue Apr 06 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.4.beta4.20100406
- updated to snapshot 20100406
- auth: If userdb lookup fails internally, don't cache the result.
- Added support for userdb lookup to fail with a reason
- sdbox: mailbox_update() could have changed UIDVALIDITY incorrectly
- layout=maildir++: Fixed deleting mailboxes with mailbox=file storages
- Fixed potential problems with parsing invalid address groups.
- dsync: Don't repeatedly try to keep opening the same failing mailbox
- lib-storage: Don't crash if root mail directory isn't given.

* Tue Mar 30 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.3.beta4.20100330
- fix certs location in ssl.conf

* Mon Mar 29 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.2.beta4.aefa279e2c70
- update to snapshot aefa279e2c70 from 2010-03-27
- fixes complains about missing tcpwrap (#577426)

* Thu Mar 25 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:2.0-0.1.beta4
- dovecot updated to 2.0 beta 4

* Fri Mar 12 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.11-2
- fix missing bzip2 support in zlib plugin (#572797)

* Tue Mar 09 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.11-1
- updated to 1.2.11
- mbox: Message header reading was unnecessarily slow. Fetching a
  huge header could have resulted in Dovecot eating a lot of CPU.
  Also searching messages was much slower than necessary.
- maildir: Reading uidlist could have ended up in an infinite loop.
- IMAP IDLE: v1.2.7+ caused extra load by checking changes every
  0.5 seconds after a change had occurred in mailbox

* Tue Feb 23 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.10-4
- move libs to correct package

* Fri Feb 19 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.10-3
- merged dovecot-sieve and dovecot-managesieve into dovecot-pigeonhole
- merged dovecot-sqlite, dovecot-gssapi and dovecot-ldap into dovecot

* Mon Jan 25 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.10-2
- updated sive and managesieve
- Added preliminary support for Sieve plugins and added support for
  installing Sieve development headers
- Variables extension: added support for variable namespaces.
- Added configurable script size limit. Compiler will refuse to
  compile files larger than sieve_max_script_size.
- Fixed a bug in the i;ascii-numeric comparator. If one of the
  strings started with a non-digit character, the comparator would
  always yield less-than.
- Imap4flags extension: fixed bug in removeflag: removing a single
  flag failed due to off-by-one error (bug report by Julian Cowley).
- Fixed parser recovery. In particular cases it would trigger spurious
  errors after an initial valid error and sometimes additional errors
  were inappropriately ignored.
- Implemented ManageSieve QUOTA enforcement.
- Added MAXREDIRECTS capability after login.
- Implemented new script name rules specified in most recent
  ManageSieve draft.
- Fixed assertion failure occuring with challenge-response SASL
  mechanisms.

* Mon Jan 25 2010 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.10-1
- updated to 1.2.10
- %%variables now support %%{host}, %%{pid} and %%{env:ENVIRONMENT_NAME}
  everywhere.
- LIST-STATUS capability is now advertised
- maildir: Fixed several assert-crashes.
- imap: LIST "" inbox shouldn't crash when using namespace with
  "INBOX." prefix.
- lazy_expunge now ignores non-private namespaces.

* Tue Dec 22 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.9-2
- sieve updated to 0.1.14
- managesieve updated to 0.11.10 

* Fri Dec 18 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.9-1
- updated to 1.2.9
- maildir: When saving, filenames now always contain ,S=<size>.
  Previously this was done only when quota plugin was loaded. It's
  required for zlib plugin and may be useful for other things too.
- maildir: v1.2.7 and v1.2.8 caused assert-crashes in
  maildir_uidlist_records_drop_expunges()
- maildir_copy_preserve_filename=yes could have caused crashes.
- Maildir++ quota: % limits weren't updated when limits were read
  from maildirsize.
- virtual: v1.2.8 didn't fully fix the "lots of mailboxes" bug
- virtual: Fixed updating virtual mailbox based on flag changes.
- fts-squat: Fixed searching multi-byte characters.

* Wed Nov 25 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.8-4
- spec cleanup

* Tue Nov 24 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.8-3
- fix dovecot's restart after update (#518753)

* Tue Nov 24 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.8-2
- fix initdddir typo (for rhel rebuilds)

* Fri Nov 20 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.8-1
- update to dovecot 1.2.8

* Mon Nov 16 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.7-2
- use originall managesieve to dovecot diff
- EPEL-ize spec for rhel5 rebuilds (#537666)

* Fri Nov 13 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.7-1
- updated to dovecot 1.2.7
- add man pages
- IMAP: IDLE now sends "Still here" notifications to same user's
  connections at the same time. This hopefully reduces power usage
  of some mobile clients that use multiple IDLEing connections.
- IMAP: If imap_capability is set, show it in the login banner.
- IMAP: Implemented SORT=DISPLAY extension.
- Login process creation could have sometimes failed with epoll_ctl()
  errors or without epoll probably some other strange things could
  have happened.
- Maildir: Fixed some performance issues
- Maildir: Fixed crash when using a lot of keywords.
- Several fixes to QRESYNC extension and modseq handling
- mbox: Make sure failed saves get rolled back with NFS.
- dbox: Several fixes.

* Mon Nov 02 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.6-5
- spec cleanup

* Wed Oct 21 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.6-4
- imap-login: If imap_capability is set, show it in the banner 
  instead of the default (#524485)

* Mon Oct 19 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.6-3
- sieve updated to 0.1.13 which brings these changes:
- Body extension: implemented proper handling of the :raw transform
  and added various new tests to the test suite. However, :content
  "multipart" and :content "message/rfc822" are still not working.
- Fixed race condition occuring when multiple instances are saving the
  same binary (patch by Timo Sirainen).
- Body extension: don't give SKIP_BODY_BLOCK flag to message parser,
  we want the body!
- Fixed bugs in multiscript support; subsequent keep actions were not
  always merged correctly and implicit side effects were not always
  handled correctly.
- Fixed a segfault bug in the sieve-test tool occuring when compile
  fails.
- Fixed segfault bug in action procesing. It was triggered while
  merging side effects in duplicate actions.
- Fixed bug in the Sieve plugin that caused it to try to stat() a NULL
  path, yielding a 'Bad address' error.

* Fri Oct 09 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.6-2
- fix init script for case when no action was specified

* Tue Oct 06 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.6-1
- dovecot updated to 1.2.6
- Added authtest utility for doing passdb and userdb lookups.
- login: ssl_security string now also shows the used compression.
- quota: Don't crash with non-Maildir++ quota backend.
- imap proxy: Fixed crashing with some specific password characters.
- fixed broken dovecot --exec-mail.
- Avoid assert-crashing when two processes try to create index at the
  same time.

* Tue Sep 29 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.5-2
- build with libcap enabled

* Thu Sep 17 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.5-1
- updated to dovecot 1.2.5
- Authentication: DIGEST-MD5 and RPA mechanisms no longer require
  user's login realm to be listed in auth_realms. It only made
  configuration more difficult without really providing extra security.
- zlib plugin: Don't allow clients to save compressed data directly.
  This prevents users from exploiting (most of the) potential security
  holes in zlib/bzlib.
- fix index file handling that could have caused an assert-crash
- IMAP: Fixes to QRESYNC extension.
- deliver: Don't send rejects to any messages that have Auto-Submitted
  header. This avoids emails loops.

* Wed Sep 16 2009 Tomas Mraz <tmraz@redhat.com> - 1:1.2.4-3
- use password-auth common PAM configuration instead of system-auth

* Fri Aug 21 2009 Tomas Mraz <tmraz@redhat.com> - 1:1.2.4-2
- rebuilt with new openssl

* Fri Aug 21 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.4-1
- updated: dovecot 1.2.4, managesieve 0.11.9, sieve 0.1.12
- fixed a crash in index file handling
- fixed a crash in saving messages where message contained a CR
  character that wasn't followed by LF
- fixed a crash when listing shared namespace prefix
- sieve: implemented the new date extension. This allows matching
  against date values in header fields and the current date at
  the time of script evaluation
- managesieve: reintroduced ability to abort SASL with "*" response

* Mon Aug 10 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.3-1
- updated: dovecot 1.2.3, managesieve 0.11.8, sieve 0.1.11
- Mailbox names with control characters can't be created anymore.
  Existing mailboxes can still be accessed though.
- Allow namespace prefix to be opened as mailbox, if a mailbox
  already exists in the root dir.
- Maildir: dovecot-uidlist was being recreated every time a mailbox
  was accessed, even if nothing changed.
- listescape plugin was somewhat broken
- ldap: Fixed hang when >128 requests were sent at once.
- fts_squat: Fixed crashing when searching virtual mailbox.
- imap: Fixed THREAD .. INTHREAD crashing.

* Tue Jul 28 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.2-1.20090728snap
- updated to post 1.2.2 snapshot (including post release GSSAPI fix)
- Fixed "corrupted index cache file" errors
- IMAP: FETCH X-* parameters weren't working.
- Maildir++ quota: Quota was sometimes updated wrong
- Dovecot master process could hang if it received signals too rapidly

* Fri Jul 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1:1.2.1-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Thu Jul 23 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.1-2
- updated sieve plugin to 0.1.9

* Mon Jul 13 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2.1-1
- updated to 1.2.1
- GSSAPI authentication is fixed (#506782)
- logins now fail if home directory path is relative, because it was 
  not working correctly and never was expected to work
- sieve and managesieve update

* Mon Apr 20 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2-0.rc3.1
- updated to 1.2.rc3

* Mon Apr 06 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2-0.rc2.1
- updated to 1.2.rc2

* Mon Mar 30 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2-0.beta4.2
- fix typo and rebuild

* Mon Mar 30 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.2-0.beta4.1
- spec clean-up
- updated to 1.2.beta4

* Tue Feb 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1:1.1.11-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Wed Feb 11 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.1.11-1
- updated to 1.1.11
- IMAP: PERMANENTFLAGS list didn't contain \*, causing some clients
  not to save keywords.
- auth: Using "username" or "domain" passdb fields caused problems
  with cache and blocking passdbs in v1.1.8 .. v1.1.10.   
- userdb prefetch + blocking passdbs was broken with non-plaintext
  auth in v1.1.8 .. v1.1.10.

* Tue Jan 27 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.1.10-1
- updated to 1.1.10

* Sat Jan 24 2009 Dan Horak <dan[at]danny.cz> - 1:1.1.8-3
- rebuild with new mysql

* Tue Jan 13 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.1.8-2
- added managesieve support (thanks Helmut K. C. Tessarek)

* Thu Jan 8 2009 Michal Hlavinka <mhlavink@redhat.com> - 1:1.1.8-1
- dovecot updated to 1.1.8
- sieve-plugin updated to 1.1.6

* Tue Dec 2 2008 Michal Hlavinka <mhlavink@redhat.com> - 1:1.1.7-2
- revert changes from 1:1.1.6-2 and 1:1.1.6-1
- password can be stored in different file readable only for root 
  via !include_try directive

* Tue Dec 2 2008 Michal Hlavinka <mhlavink@redhat.com> - 1:1.1.7-1
- update to upstream version 1.1.7

* Mon Nov 3 2008 Michal Hlavinka <mhlavink@redhat.com> - 1:1.1.6-2
- changed comment in sysconfig to match actual state

* Mon Nov 3 2008 Michal Hlavinka <mhlavink@redhat.com> - 1:1.1.6-1
- update to upstream version 1.1.6
- change permissions of deliver and dovecot.conf to prevent possible password exposure

* Wed Oct 29 2008 Michal Hlavinka <mhlavink@redhat.com> - 1:1.1.5-1
- update to upstream version 1.1.5 (Resolves: CVE-2008-4577, CVE-2008-4578)

* Tue Sep  2 2008 Dan Horak <dan[at]danny.cz> - 1:1.1.3-1
- update to upstream version 1.1.3

* Tue Jul 29 2008 Dan Horak <dan[at]danny.cz> - 1:1.1.2-2
- really ask for the password during start-up

* Tue Jul 29 2008 Dan Horak <dan[at]danny.cz> - 1:1.1.2-1
- update to upstream version 1.1.2
- final solution for #445200 (add /etc/sysconfig/dovecot for start-up options)

* Fri Jun 27 2008 Dan Horak <dan[at]danny.cz> - 1:1.1.1-2
- update default settings to listen on both IPv4 and IPv6 instead of IPv6 only

* Sun Jun 22 2008 Dan Horak <dan[at]danny.cz> - 1:1.1.1-1
- update to upstream version 1.1.1

* Sat Jun 21 2008 Dan Horak <dan[at]danny.cz> - 1:1.1.0-1
- update to upstream version 1.1.0
- update sieve plugin to 1.1.5
- remove unnecessary patches
- enable ldap and gssapi plugins
- change ownership of dovecot.conf (Resolves: #452088)

* Wed Jun 18 2008 Dan Horak <dan[at]danny.cz> - 1:1.0.14-4
- update init script (Resolves: #451838)

* Fri Jun  6 2008 Dan Horak <dan[at]danny.cz> - 1:1.0.14-3
- build devel subpackage (Resolves: #306881)

* Thu Jun  5 2008 Dan Horak <dan[at]danny.cz> - 1:1.0.14-2
- install convert-tool (Resolves: #450010)

* Tue Jun  3 2008 Dan Horak <dan[at]danny.cz> - 1:1.0.14-1
- update to upstream version 1.0.14
- remove setcred patch (use of setcred must be explictly enabled in config)

* Thu May 29 2008 Dan Horak <dan[at]danny.cz> - 1:1.0.13-8
- update scriptlets to follow UsersAndGroups guideline
- remove support for upgrading from version < 1.0 from scriptlets
- Resolves: #448095

* Tue May 20 2008 Dan Horak <dan[at]danny.cz> - 1:1.0.13-7
- spec file cleanup
- update sieve plugin to 1.0.3
- Resolves: #445200, #238018

* Sun Mar 09 2008 Tomas Janousek <tjanouse@redhat.com> - 1:1.0.13-6
- update to latest upstream stable (1.0.13)

* Wed Feb 20 2008 Fedora Release Engineering <rel-eng@fedoraproject.org> - 1:1.0.10-5
- Autorebuild for GCC 4.3

* Mon Jan 07 2008 Tomas Janousek <tjanouse@redhat.com> - 1:1.0.10-4
- update to latest upstream stable (1.0.10)

* Wed Dec 05 2007 Jesse Keating <jkeating@redhat.com> - 1:1.0.7-3
- Bump for deps

* Mon Nov 05 2007 Tomas Janousek <tjanouse@redhat.com> - 1:1.0.7-2
- update to latest upstream stable (1.0.7)
- added the winbind patch (#286351)

* Tue Sep 25 2007 Tomas Janousek <tjanouse@redhat.com> - 1:1.0.5-1
- downgraded to lastest upstream stable (1.0.5)

* Wed Aug 22 2007 Tomas Janousek <tjanouse@redhat.com> - 1.1-16.1.alpha3
- updated license tags

* Mon Aug 13 2007 Tomas Janousek <tjanouse@redhat.com> - 1.1-16.alpha3
- updated to latest upstream alpha
- update dovecot-sieve to 0367450c9382 from hg

* Fri Aug 10 2007 Tomas Janousek <tjanouse@redhat.com> - 1.1-15.alpha2
- updated to latest upstream alpha
- split ldap and gssapi plugins to subpackages

* Wed Jul 25 2007 Tomas Janousek <tjanouse@redhat.com> - 1.1-14.6.hg.a744ae38a9e1
- update to a744ae38a9e1 from hg
- update dovecot-sieve to 131e25f6862b from hg and enable it again

* Thu Jul 19 2007 Tomas Janousek <tjanouse@redhat.com> - 1.1-14.5.alpha1
- update to latest upstream alpha
- don't build dovecot-sieve, it's only for 1.0

* Sun Jul 15 2007 Tomas Janousek <tjanouse@redhat.com> - 1.0.2-13.5
- update to latest upstream

* Mon Jun 18 2007 Tomas Janousek <tjanouse@redhat.com> - 1.0.1-12.5
- update to latest upstream

* Fri Jun 08 2007 Tomas Janousek <tjanouse@redhat.com> - 1.0.0-11.7
- specfile merge from 145241 branch
    - new sql split patch
    - support for not building all sql modules
    - split sql libraries to separate packages

* Sat Apr 14 2007 Tomas Janousek <tjanouse@redhat.com> - 1.0.0-11.1
- dovecot-1.0.beta2-pam-tty.patch is no longer needed

* Fri Apr 13 2007 Tomas Janousek <tjanouse@redhat.com> - 1.0.0-11
- update to latest upstream

* Tue Apr 10 2007 Tomas Janousek <tjanouse@redhat.com> - 1.0-10.rc31
- update to latest upstream

* Fri Apr 06 2007 Tomas Janousek <tjanouse@redhat.com> - 1.0-9.rc30
- update to latest upstream

* Fri Mar 30 2007 Tomas Janousek <tjanouse@redhat.com> - 1.0-8.1.rc28
- spec file cleanup (fixes docs path)

* Fri Mar 23 2007 Tomas Janousek <tjanouse@redhat.com> - 1.0-8.rc28
- update to latest upstream

* Mon Mar 19 2007 Tomas Janousek <tjanouse@redhat.com> - 1.0-7.rc27
- use dovecot-sieve's version for the package

* Mon Mar 19 2007 Tomas Janousek <tjanouse@redhat.com> - 1.0-6.rc27
- update to latest upstream
- added dovecot-sieve

* Fri Mar 02 2007 Tomas Janousek <tjanouse@redhat.com> - 1.0-5.rc25
- update to latest upstream

* Sun Feb 25 2007 Jef Spaleta <jspaleta@gmail.com> - 1.0-4.rc22
- Merge review changes

* Thu Feb 08 2007 Tomas Janousek <tjanouse@redhat.com> - 1.0-3.rc22
- update to latest upstream, fixes a few bugs

* Mon Jan 08 2007 Tomas Janousek <tjanouse@redhat.com> - 1.0-2.rc17
- update to latest upstream, fixes a few bugs

* Thu Dec 21 2006 Tomas Janousek <tjanouse@redhat.com> - 1.0-1.1.rc15
- reenabled GSSAPI (#220377)

* Tue Dec 05 2006 Tomas Janousek <tjanouse@redhat.com> - 1.0-1.rc15
- update to latest upstream, fixes a few bugs, plus a security
  vulnerability (#216508, CVE-2006-5973)

* Tue Oct 10 2006 Petr Rockai <prockai@redhat.com> - 1.0-0.3.rc7
- fix few inconsistencies in specfile, fixes #198940

* Wed Oct 04 2006 Petr Rockai <prockai@redhat.com> - 1.0-0.2.rc7
- fix default paths in the example mkcert.sh to match configuration
  defaults (fixes #183151)

* Sun Oct 01 2006 Jesse Keating <jkeating@redhat.com> - 1.0-0.1.rc7
- rebuilt for unwind info generation, broken in gcc-4.1.1-21

* Fri Sep 22 2006 Petr Rockai <prockai@redhat.com> - 1.0-0.rc7
- update to latest upstream release candidate, should fix occasional
  hangs and mbox issues... INBOX. namespace is still broken though
- do not run over symlinked certificates in new locations on upgrade

* Tue Aug 15 2006 Petr Rockai <prockai@redhat.com> - 1.0-0.rc2.2
- include /var/lib/dovecot in the package, prevents startup failure
  on new installs

* Mon Jul 17 2006 Petr Rockai <prockai@redhat.com> - 1.0-0.rc2.1
- reenable inotify and see what happens

* Thu Jul 13 2006 Petr Rockai <prockai@redhat.com> - 1.0-0.rc2
- update to latest upstream release candidate
- disable inotify for now, doesn't build -- this needs fixing though

* Wed Jul 12 2006 Jesse Keating <jkeating@redhat.com> - 1.0-0.beta8.2.1
- rebuild

* Thu Jun 08 2006 Petr Rockai <prockai@redhat.com> - 1.0-0.beta8.2
- put back pop3_uidl_format default that got lost
  in the beta2->beta7 upgrade (would cause pop3 to not work
  at all in many situations)

* Thu May 04 2006 Petr Rockai <prockai@redhat.com> - 1.0-0.beta8.1
- upgrade to latest upstream beta release (beta8)
- contains a security fix in mbox handling

* Thu May 04 2006 Petr Rockai <prockai@redhat.com> - 1.0-0.beta7.1
- upgrade to latest upstream beta release
- fixed BR 173048

* Fri Mar 17 2006 Petr Rockai <prockai@redhat.com> - 1.0-0.beta2.8
- fix sqlite detection in upstream configure checks, second part
  of #182240

* Wed Mar  8 2006 Bill Nottingham <notting@redhat.com> - 1.0-0.beta2.7
- fix scriplet noise some more

* Mon Mar  6 2006 Jeremy Katz <katzj@redhat.com> - 1.0-0.beta2.6
- fix scriptlet error (mitr, #184151)

* Mon Feb 27 2006 Petr Rockai <prockai@redhat.com> - 1.0-0.beta2.5
- fix #182240 by looking in lib64 for libs first and then lib
- fix comment #1 in #182240 by copying over the example config files
  to documentation directory

* Fri Feb 10 2006 Jesse Keating <jkeating@redhat.com> - 1.0-0.beta2.4.1
- bump again for double-long bug on ppc(64)

* Thu Feb 09 2006 Petr Rockai <prockai@redhat.com> - 1.0-0.beta2.4
- enable inotify as it should work now (#179431)

* Tue Feb 07 2006 Jesse Keating <jkeating@redhat.com> - 1.0-0.beta2.3.1
- rebuilt for new gcc4.1 snapshot and glibc changes

* Thu Feb 02 2006 Petr Rockai <prockai@redhat.com> - 1.0-0.beta2.3
- change the compiled-in defaults and adjust the default's configfile
  commented-out example settings to match compiled-in defaults,
  instead of changing the defaults only in the configfile, as per #179432
- fix #179574 by providing a default uidl_format for pop3
- half-fix #179620 by having plaintext auth enabled by default... this
  needs more thinking (which one we really want) and documentation
  either way

* Tue Jan 31 2006 Petr Rockai <prockai@redhat.com> - 1.0-0.beta2.2
- update URL in description
- call dovecot --build-ssl-parameters in postinst as per #179430

* Mon Jan 30 2006 Petr Rockai <prockai@redhat.com> - 1.0-0.beta2.1
- fix spec to work with BUILD_DIR != SOURCE_DIR
- forward-port and split pam-nocred patch

* Mon Jan 23 2006 Petr Rockai <prockai@redhat.com> - 1.0-0.beta2
- new upstream version, hopefully fixes #173928, #163550
- fix #168866, use install -p to install documentation

* Fri Dec 09 2005 Jesse Keating <jkeating@redhat.com>
- rebuilt

* Sat Nov 12 2005 Tom Lane <tgl@redhat.com> - 0.99.14-10.fc5
- Rebuild due to mysql update.

* Wed Nov  9 2005 Tomas Mraz <tmraz@redhat.com> - 0.99.14-9.fc5
- rebuilt with new openssl

* Fri Sep 30 2005 Tomas Mraz <tmraz@redhat.com> - 0.99.14-8.fc5
- use include instead of pam_stack in pam config

* Wed Jul 27 2005 John Dennis <jdennis@redhat.com> - 0.99.14-7.fc5
- fix bug #150888, log authenication failures with ip address

* Fri Jul 22 2005 John Dennis <jdennis@redhat.com> - 0.99.14-6.fc5
- fix bug #149673, add dummy PAM_TTY

* Thu Apr 28 2005 John Dennis <jdennis@redhat.com> - 0.99.14-5.fc4
- fix bug #156159 insecure location of restart flag file

* Fri Apr 22 2005 John Dennis <jdennis@redhat.com> - 0.99.14-4.fc4
- openssl moved its certs, CA, etc. from /usr/share/ssl to /etc/pki

* Tue Apr 12 2005 Tom Lane <tgl@redhat.com> 0.99.14-3.fc4
- Rebuild for Postgres 8.0.2 (new libpq major version).

* Mon Mar  7 2005 John Dennis <jdennis@redhat.com> 0.99.14-2.fc4
- bump rev for gcc4 build

* Mon Feb 14 2005 John Dennis <jdennis@redhat.com> - 0.99.14-1.fc4
- fix bug #147874, update to 0.99.14 release
  v0.99.14 2005-02-11  Timo Sirainen <tss at iki.fi>
  - Message address fields are now parsed differently, fixing some
    issues with spaces. Affects only clients which use FETCH ENVELOPE
    command.
  - Message MIME parser was somewhat broken with missing MIME boundaries
  - mbox: Don't allow X-UID headers in mails to override the UIDs we
    would otherwise set. Too large values can break some clients and
    cause other trouble.
  - passwd-file userdb wasn't working
  - PAM crashed with 64bit systems
  - non-SSL inetd startup wasn't working
  - If UID FETCH notices and skips an expunged message, don't return
    a NO reply. It's not needed and only makes clients give error
    messages.

* Wed Feb  2 2005 John Dennis <jdennis@redhat.com> - 0.99.13-4.devel
- fix bug #146198, clean up temp kerberos tickets

* Mon Jan 17 2005 John Dennis <jdennis@redhat.com> 0.99.13-3.devel
- fix bug #145214, force mbox_locks to fcntl only
- fix bug #145241, remove prereq on postgres and mysql, allow rpm auto
  dependency generator to pick up client lib dependency if needed.

* Thu Jan 13 2005 John Dennis <jdennis@redhat.com> 0.99.13-2.devel
- make postgres & mysql conditional build
- remove execute bit on migration example scripts so rpm does not pull
  in additional dependences on perl and perl modules that are not present
  in dovecot proper.
- add REDHAT-FAQ.txt to doc directory

* Thu Jan  6 2005 John Dennis <jdennis@redhat.com> 0.99.13-1.devel
- bring up to date with latest upstream, 0.99.13, bug #143707
  also fix bug #14462, bad dovecot-uid macro name

* Thu Jan  6 2005 John Dennis <jdennis@redhat.com> 0.99.11-10.devel
- fix bug #133618, removed LITERAL+ capability from capability string

* Wed Jan  5 2005 John Dennis <jdennis@redhat.com> 0.99.11-9.devel
- fix bug #134325, stop dovecot during installation

* Wed Jan  5 2005 John Dennis <jdennis@redhat.com> 0.99.11-8.devel
- fix bug #129539, dovecot starts too early,
  set chkconfig to 65 35 to match cyrus-imapd
- also delete some old commented out code from SSL certificate creation

* Thu Dec 23 2004 John Dennis <jdennis@redhat.com> 0.99.11-7.devel
- add UW to Dovecot migration documentation and scripts, bug #139954
  fix SSL documentation and scripts, add missing documentation, bug #139276

* Mon Nov 15 2004 Warren Togami <wtogami@redhat.com> 0.99.11-2.FC4.1
- rebuild against MySQL4

* Thu Oct 21 2004 John Dennis <jdennis@redhat.com>
- fix bug #136623
  Change License field from GPL to LGPL to reflect actual license

* Thu Sep 30 2004 John Dennis <jdennis@redhat.com> 0.99.11-1.FC3.3
- fix bug #124786, listen to ipv6 as well as ipv4

* Wed Sep  8 2004 John Dennis <jdennis@redhat.com> 0.99.11-1.FC3.1
- bring up to latest upstream,
  comments from Timo Sirainen <tss at iki.fi> on release v0.99.11 2004-09-04  
  + 127.* and ::1 IP addresses are treated as secured with
    disable_plaintext_auth = yes
  + auth_debug setting for extra authentication debugging
  + Some documentation and error message updates
  + Create PID file in /var/run/dovecot/master.pid
  + home setting is now optional in static userdb
  + Added mail setting to static userdb
  - After APPENDing to selected mailbox Dovecot didn't always notice the
    new mail immediately which broke some clients
  - THREAD and SORT commands crashed with some mails
  - If APPENDed mail ended with CR character, Dovecot aborted the saving
  - Output streams sometimes sent data duplicated and lost part of it.
    This could have caused various strange problems, but looks like in
    practise it rarely caused real problems.

* Wed Aug  4 2004 John Dennis <jdennis@redhat.com>
- change release field separator from comma to dot, bump build number

* Mon Aug  2 2004 John Dennis <jdennis@redhat.com> 0.99.10.9-1,FC3,1
- bring up to date with latest upstream, fixes include:
- LDAP support compiles now with Solaris LDAP library
- IMAP BODY and BODYSTRUCTURE replies were wrong for MIME parts which
  didn't contain Content-Type header.
- MySQL and PostgreSQL auth didn't reconnect if connection was lost
  to SQL server
- Linking fixes for dovecot-auth with some systems
- Last fix for disconnecting client when downloading mail longer than
  30 seconds actually made it never disconnect client. Now it works
  properly: disconnect when client hasn't read _any_ data for 30
  seconds.
- MySQL compiling got broken in last release
- More PostgreSQL reconnection fixing


* Mon Jul 26 2004 John Dennis <jdennis@redhat.com> 0.99.10.7-1,FC3,1
- enable postgres and mySQL in build
- fix configure to look for mysql in alternate locations
- nuke configure script in tar file, recreate from configure.in using autoconf

- bring up to latest upstream, which included:
- Added outlook-pop3-no-nuls workaround to fix Outlook hang in mails with NULs.
- Config file lines can now contain quoted strings ("value ")
- If client didn't finish downloading a single mail in 30 seconds,
  Dovecot closed the connection. This was supposed to work so that
  if client hasn't read data at all in 30 seconds, it's disconnected.
- Maildir: LIST now doesn't skip symlinks


* Wed Jun 30 2004 John Dennis <jdennis@redhat.com>
- bump rev for build
- change rev for FC3 build

* Fri Jun 25 2004 John Dennis <jdennis@redhat.com> - 0.99.10.6-1
- bring up to date with upstream,
  recent change log comments from Timo Sirainen were:
  SHA1 password support using OpenSSL crypto library
  mail_extra_groups setting
  maildir_stat_dirs setting
  Added NAMESPACE capability and command
  Autocreate missing maildirs (instead of crashing)
  Fixed occational crash in maildir synchronization
  Fixed occational assertion crash in ioloop.c
  Fixed FreeBSD compiling issue
  Fixed issues with 64bit Solaris binary

* Tue Jun 15 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Thu May 27 2004 David Woodhouse <dwmw2@redhat.com> 0.99.10.5-1
- Update to 0.99.10.5 to fix maildir segfaults (#123022)

* Fri May 07 2004 Warren Togami <wtogami@redhat.com> 0.99.10.4-4
- default auth config that is actually usable
- Timo Sirainen (author) suggested functionality fixes
  maildir, imap-fetch-body-section, customflags-fix

* Mon Feb 23 2004 Tim Waugh <twaugh@redhat.com>
- Use ':' instead of '.' as separator for chown.

* Tue Feb 17 2004 Jeremy Katz <katzj@redhat.com> - 0.99.10.4-3
- restart properly if it dies (#115594)

* Fri Feb 13 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Mon Nov 24 2003 Jeremy Katz <katzj@redhat.com> 0.99.10.4-1
- update to 0.99.10.4

* Mon Oct  6 2003 Jeremy Katz <katzj@redhat.com> 0.99.10-7
- another patch from upstream to fix returning invalid data on partial 
  BODY[part] fetches
- patch to avoid confusion of draft/deleted in indexes

* Tue Sep 23 2003 Jeremy Katz <katzj@redhat.com> 0.99.10-6
- add some patches from upstream (#104288)

* Thu Sep  4 2003 Jeremy Katz <katzj@redhat.com> 0.99.10-5
- fix startup with 2.6 with patch from upstream (#103801)

* Tue Sep  2 2003 Jeremy Katz <katzj@redhat.com> 0.99.10-4
- fix assert in search code (#103383)

* Tue Jul 22 2003 Nalin Dahyabhai <nalin@redhat.com> 0.99.10-3
- rebuild

* Thu Jul 17 2003 Bill Nottingham <notting@redhat.com> 0.99.10-2
- don't run by default

* Thu Jun 26 2003 Jeremy Katz <katzj@redhat.com> 0.99.10-1
- 0.99.10

* Mon Jun 23 2003 Jeremy Katz <katzj@redhat.com> 0.99.10-0.2
- 0.99.10-rc2 (includes ssl detection fix)
- a few tweaks from fedora
  - noreplace the config file
  - configure --with-ldap to get LDAP enabled

* Mon Jun 23 2003 Jeremy Katz <katzj@redhat.com> 0.99.10-0.1
- 0.99.10-rc1
- add fix for ssl detection
- add zlib-devel to BuildRequires
- change pam service name to dovecot
- include pam config

* Thu May  8 2003 Jeremy Katz <katzj@redhat.com> 0.99.9.1-1
- update to 0.99.9.1
- add patch from upstream to fix potential bug when fetching with 
  CR+LF linefeeds
- tweak some things in the initscript and config file noticed by the 
  fedora folks

* Sun Mar 16 2003 Jeremy Katz <katzj@redhat.com> 0.99.8.1-2
- fix ssl dir
- own /var/run/dovecot/login with the correct perms
- fix chmod/chown in post

* Fri Mar 14 2003 Jeremy Katz <katzj@redhat.com> 0.99.8.1-1
- update to 0.99.8.1

* Tue Mar 11 2003 Jeremy Katz <katzj@redhat.com> 0.99.8-2
- add a patch to fix quoting problem from CVS

* Mon Mar 10 2003 Jeremy Katz <katzj@redhat.com> 0.99.8-1
- 0.99.8
- add some buildrequires
- fixup to build with openssl 0.9.7
- now includes a pop3 daemon (off by default)
- clean up description and %%preun
- add dovecot user (uid/gid of 97)
- add some buildrequires
- move the ssl cert to %%{_datadir}/ssl/certs
- create a dummy ssl cert in %%post
- own /var/run/dovecot
- make the config file a source so we get default mbox locks of fcntl

* Sun Dec  1 2002 Seth Vidal <skvidal@phy.duke.edu>
- 0.99.4 and fix startup so it starts imap-master not vsftpd :)

* Tue Nov 26 2002 Seth Vidal <skvidal@phy.duke.edu>
- first build
