AC_PREREQ([2.59])

# Be sure to update ABI version also if anything changes that might require
# recompiling plugins. Most importantly that means if any structs are changed.
AC_INIT([Dovecot],[2.3.10.1],[dovecot@dovecot.org])
AC_DEFINE_UNQUOTED([DOVECOT_ABI_VERSION], "2.3.ABIv10($PACKAGE_VERSION)", [Dovecot ABI version])

AC_CONFIG_SRCDIR([src])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign])

AM_MAINTAINER_MODE
PKG_PROG_PKG_CONFIG

ACLOCAL_AMFLAGS='-I $(top_srcdir)/m4'
AC_SUBST(ACLOCAL_AMFLAGS)

AC_ARG_ENABLE(devel-checks,
AS_HELP_STRING([--enable-devel-checks], [Enable some extra expensive checks for developers]),
	if test x$enableval = xyes; then
		AC_DEFINE(DEBUG,, [Build with extra debugging checks])
		want_devel_checks=yes
	fi)

AC_ARG_ENABLE(static-checker,
AS_HELP_STRING([--enable-static-checker], [Enable code to be used when building with static code analyzer]),
	if test x$enableval = xyes; then
		AC_DEFINE(STATIC_CHECKER,, [Building with static code analyzer])
	fi)

AC_ARG_ENABLE(asserts,
AS_HELP_STRING([--enable-asserts], [Enable asserts (default)]),
	if test x$enableval = xno; then
		AC_DEFINE(DISABLE_ASSERTS,, [Disable asserts])
	fi)

AC_ARG_WITH(shared-libs,
AS_HELP_STRING([--with-shared-libs], [Link binaries using shared Dovecot libraries (default)]),
	want_shared_libs=$withval,
	want_shared_libs=yes)
AM_CONDITIONAL(BUILD_SHARED_LIBS, test "$want_shared_libs" = "yes")

AC_ARG_WITH(mem-align,
AS_HELP_STRING([--with-mem-align=BYTES], [Set the memory alignment (default: 8)]),
	mem_align=$withval,
	mem_align=8)

AC_ARG_WITH(ioloop,
AS_HELP_STRING([--with-ioloop=IOLOOP], [Specify the I/O loop method to use (epoll, kqueue, poll; best for the fastest available; default is best)]),
	ioloop=$withval,
	ioloop=best)

AC_ARG_WITH(notify,
AS_HELP_STRING([--with-notify=NOTIFY], [Specify the file system notification method to use (inotify, kqueue, none; default is detected in the above order)]),
	notify=$withval,
	notify=)

AC_ARG_WITH(nss,
AS_HELP_STRING([--with-nss], [Build with NSS module support (auto)]),
  TEST_WITH(nss, $withval),
  want_nss=auto)

AC_ARG_WITH(shadow,
AS_HELP_STRING([--with-shadow], [Build with shadow password support (auto)]),
  TEST_WITH(shadow, $withval),
  want_shadow=auto)

AC_ARG_WITH(pam,
AS_HELP_STRING([--with-pam], [Build with PAM support (auto)]),
  TEST_WITH(pam, $withval),
  want_pam=auto)

AC_ARG_WITH(bsdauth,
AS_HELP_STRING([--with-bsdauth], [Build with BSD authentication support (auto)]),
  TEST_WITH(bsdauth, $withval),
  want_bsdauth=auto)

AC_ARG_WITH(gssapi,
AS_HELP_STRING([--with-gssapi=yes|plugin Build with GSSAPI authentication support]),
  TEST_WITH(gssapi, $withval, plugin),
  want_gssapi=no)

AC_ARG_WITH(sia,
AS_HELP_STRING([--with-sia], [Build with Tru64 SIA support]),
  TEST_WITH(sia, $withval),
  want_sia=no)

AC_ARG_WITH(ldap,
AS_HELP_STRING([--with-ldap=yes|plugin], [Build with LDAP support]),
  TEST_WITH(ldap, $withval, plugin),
  want_ldap=no)

AC_ARG_WITH(libunwind,
AS_HELP_STRING([--with-libunwind], [Build with libunwind support (auto)]),
  TEST_WITH(libunwind, $withval),
  want_libunwind=auto)

AC_ARG_WITH(vpopmail,
AS_HELP_STRING([--with-vpopmail], [Build with vpopmail support (auto)]),
	if test x$withval = xno; then
		want_vpopmail=no
	else
		if test x$withval = xyes || test x$withval = xauto; then
			vpopmail_home="`echo ~vpopmail`"
			want_vpopmail=$withval
		else
			vpopmail_home="$withval"
			want_vpopmail=yes
		fi
	fi, [
		want_vpopmail=no
	])

# Berkeley DB support is more or less broken. Disabled for now.
#AC_ARG_WITH(db,
#AS_HELP_STRING([--with-db], [Build with Berkeley DB support]),
#  TEST_WITH(db, $withval),
#  want_db=no)
want_db=no

AC_ARG_WITH(cdb,
AS_HELP_STRING([--with-cdb], [Build with CDB support]),
  TEST_WITH(cdb, $withval),
  want_cdb=no)

dnl The --with-sql is useful only if Dovecot is being built with all the SQL
dnl drivers as modules. If any SQL driver is built-in, this option is ignored.
AC_ARG_WITH(sql,
AS_HELP_STRING([--with-sql=yes|plugin], [Build with generic SQL support]),
  TEST_WITH(sql, $withval, plugin),
  want_sql=no)

AC_ARG_WITH(pgsql,
AS_HELP_STRING([--with-pgsql], [Build with PostgreSQL driver support]),
  TEST_WITH(pgsql, $withval),
  want_pgsql=no)

AC_ARG_WITH(mysql,
AS_HELP_STRING([--with-mysql], [Build with MySQL driver support]),
  TEST_WITH(mysql, $withval),
  want_mysql=no)

AC_ARG_WITH(sqlite,
AS_HELP_STRING([--with-sqlite], [Build with SQLite3 driver support]),
  TEST_WITH(sqlite, $withval),
  want_sqlite=no)

AC_ARG_WITH(cassandra,
AS_HELP_STRING([--with-cassandra], [Build with Cassandra driver support]),
  TEST_WITH(cassandra, $withval),
  want_cassandra=no)

AC_ARG_WITH(lucene,
AS_HELP_STRING([--with-lucene], [Build with CLucene full text search support]),
  TEST_WITH(lucene, $withval),
  want_lucene=no)
AM_CONDITIONAL(BUILD_LUCENE, test "$want_lucene" = "yes")

AC_ARG_WITH(stemmer,
AS_HELP_STRING([--with-stemmer], [Build with libstemmer support (for FTS) (auto)]),
  TEST_WITH(stemmer, $withval),
  want_stemmer=auto)

AC_ARG_WITH(textcat,
AS_HELP_STRING([--with-textcat], [Build with libtextcat support (for FTS) (auto)]),
  TEST_WITH(textcat, $withval),
  want_textcat=auto)

AC_ARG_WITH(icu,
AS_HELP_STRING([--with-icu], [Build with libicu support (for FTS normalization) (auto)]),
  want_icu=$withval,
  want_icu=auto)

AC_ARG_WITH(solr,
AS_HELP_STRING([--with-solr], [Build with Solr full text search support]),
  TEST_WITH(solr, $withval),
  want_solr=no)

AC_ARG_WITH(sodium,
AS_HELP_STRING([--with-sodium], [Build with libsodium support (enables argon2, default: auto)]),
  TEST_WITH(sodium, $withval),
  want_sodium=auto)

AC_ARG_WITH(zlib,
AS_HELP_STRING([--with-zlib], [Build with zlib compression support (auto)]),
  TEST_WITH(zlib, $withval),
  want_zlib=auto)

AC_ARG_WITH(bzlib,
AS_HELP_STRING([--with-bzlib], [Build with bzlib compression support (auto)]),
  TEST_WITH(bzlib, $withval),
  want_bzlib=auto)

AC_ARG_WITH(lzma,
AS_HELP_STRING([--with-lzma], [Build with LZMA compression support (auto)]),
  TEST_WITH(lzma, $withval),
  want_lzma=auto)

AC_ARG_WITH(lz4,
AS_HELP_STRING([--with-lz4], [Build with LZ4 compression support (auto)]),
  TEST_WITH(lz4, $withval),
  want_lz4=auto)

AC_ARG_WITH(libcap,
AS_HELP_STRING([--with-libcap], [Build with libcap support (Dropping capabilities) (auto)]),
  TEST_WITH(libcap, $withval),
  want_libcap=auto)

AC_ARG_WITH(libwrap,
AS_HELP_STRING([--with-libwrap], [Build with libwrap, ie. TCP-wrappers]),
  TEST_WITH(libwrap, $withval),
  want_libwrap=no)

AC_ARG_WITH(ssl,
AS_HELP_STRING([--with-ssl=gnutls|openssl], [Build with GNUTLS or OpenSSL (default)]),
	if test x$withval = xno; then
		want_gnutls=no
		want_openssl=no
	elif test x$withval = xgnutls; then
		AC_ERROR([GNUTLS support is broken currently])
		want_gnutls=yes
		want_openssl=no
	elif test x$withval = xopenssl; then
		want_gnutls=no
		want_openssl=yes
	elif test x$withval = xyes; then
		want_gnutls=no
		want_openssl=yes
	else
		AC_ERROR([--with-ssl: Invalid value: $withval])
	fi, [
		want_gnutls=no
		want_openssl=auto
	])

AC_ARG_WITH(ssldir,
AS_HELP_STRING([--with-ssldir=DIR], [SSL base directory for certificates (/etc/ssl)]),
	ssldir="$withval",
	ssldir=/etc/ssl
)
AC_SUBST(ssldir)

AC_ARG_WITH(rundir,
AS_HELP_STRING([--with-rundir=DIR], [Runtime data directory (LOCALSTATEDIR/run/dovecot)]),
	rundir="$withval",
	rundir=$localstatedir/run/$PACKAGE
)
AC_SUBST(rundir)

AC_ARG_WITH(statedir,
AS_HELP_STRING([--with-statedir=DIR], [Permanent data directory (LOCALSTATEDIR/lib/dovecot)]),
	statedir="$withval",
	statedir=$localstatedir/lib/$PACKAGE
)
AC_SUBST(statedir)

AC_ARG_WITH([systemdsystemunitdir],
AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files (auto=detect)]), [
	if test "$withval" = "auto"; then
		systemdsystemunitdir=`$PKG_CONFIG --variable=systemdsystemunitdir systemd`
	elif test "$withval" != "no"; then
		systemdsystemunitdir=$withval
	fi
], [])
if test "$systemdsystemunitdir" != ""; then
        AC_SUBST(systemdsystemunitdir)
        AC_DEFINE(HAVE_SYSTEMD,, [Define if you want to use systemd socket activation])
fi
AM_CONDITIONAL(HAVE_SYSTEMD, test "$systemdsystemunitdir" != "")

dovecot_moduledir="$libdir/dovecot"
DC_DOVECOT_MODULEDIR

AC_ARG_WITH(docs,
AS_HELP_STRING([--with-docs], [Install documentation (default)]),
	if test x$withval = xno; then
		want_docs=no
	else
		want_docs=yes
	fi,
	want_docs=yes)
AM_CONDITIONAL(BUILD_DOCS, test "$want_docs" = "yes")

dnl always enable all of the passbs and userdbs that don't require extra libs
want_passwd=yes
want_passwd_file=yes
want_checkpassword=yes
want_prefetch_userdb=yes

AC_ISC_POSIX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX # lucene plugin needs this
AC_HEADER_STDC
AC_C_INLINE
AC_PROG_LIBTOOL
AM_ICONV

# SIZE_MAX is missing without this
CXXFLAGS="$CXXFLAGS -D__STDC_LIMIT_MACROS"

AC_DEFINE_UNQUOTED(DOVECOT_NAME, "$PACKAGE_NAME", [Dovecot name])
AC_DEFINE_UNQUOTED(DOVECOT_STRING, "$PACKAGE_STRING", [Dovecot string])
AC_DEFINE_UNQUOTED(DOVECOT_VERSION, "$PACKAGE_VERSION", [Dovecot version])

AC_DEFINE([DOVECOT_VERSION_MAJOR], regexp(AC_PACKAGE_VERSION, [^\([0-9]+\)\.\([0-9]+\)], [\1]), [Dovecot major version])
AC_DEFINE([DOVECOT_VERSION_MINOR], regexp(AC_PACKAGE_VERSION, [^\([0-9]+\)\.\([0-9]+\)], [\2]), [Dovecot minor version])

AC_CHECK_HEADERS(strings.h stdint.h unistd.h dirent.h malloc.h \
  sys/uio.h sys/sysmacros.h sys/resource.h sys/select.h libgen.h \
  sys/quota.h sys/fs/ufs_quota.h ufs/ufs/quota.h jfs/quota.h \
  quota.h sys/fs/quota_common.h \
  mntent.h sys/mnttab.h sys/event.h sys/time.h sys/mkdev.h linux/dqblk_xfs.h \
  xfs/xqm.h execinfo.h ucontext.h malloc_np.h sys/utsname.h sys/vmount.h \
  sys/utsname.h glob.h linux/falloc.h ucred.h sys/ucred.h crypt.h)

CC_CLANG
AC_LD_WHOLE_ARCHIVE
DC_DOVECOT_HARDENING
DC_DOVECOT_CFLAGS

DOVECOT_NSL
DOVECOT_FDATASYNC
DOVECOT_LIBCAP
DOVECOT_LIBWRAP

DOVECOT_RANDOM
DOVECOT_ARC4RANDOM

AC_DEFINE(PACKAGE_WEBPAGE, "http://www.dovecot.org/", [Support URL])

dnl * after -lsocket and -lnsl tests, inet_aton() may be in them
AC_CHECK_FUNCS(fcntl flock lockf inet_aton sigaction getpagesize madvise \
               strcasecmp stricmp vsyslog writev pread uname unsetenv \
	       setrlimit setproctitle seteuid setreuid setegid setresgid \
	       getmntinfo setpriority quotactl getmntent kqueue kevent \
	       backtrace_symbols walkcontext dirfd clearenv \
	       malloc_usable_size glob fallocate posix_fadvise \
	       getpeereid getpeerucred inotify_init timegm)

DOVECOT_SOCKPEERCRED
DOVECOT_CLOCK_GETTIME

DOVECOT_TYPEOF
DOVECOT_IOLOOP
DOVECOT_NOTIFY

DOVECOT_GLIBC

dnl * OS specific options
DC_PLUGIN_DEPS
case "$host_os" in
	hpux*)
		CFLAGS="$CFLAGS -D_XOPEN_SOURCE -D_XOPEN_SOURCE_EXTENDED"
		# for getting fd_send/fd_recv working:
		LDFLAGS="$LDFLAGS -Wl,+b,:"
		LIBS="-lxnet $LIBS"
		AC_DEFINE(PREAD_BROKEN,, [Define if pread/pwrite implementation is broken])
		;;
	linux*|darwin*)
		AC_DEFINE(PROCTITLE_HACK,, [Define if process title can be changed by modifying argv])
		;;
	*)
		;;
esac

AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(void *)
AC_CHECK_SIZEOF(long long)

AC_SYS_LARGEFILE
AC_CHECK_TYPES(_Bool)

AC_CHECK_TYPE(uoff_t, [
  have_uoff_t=yes
  AC_DEFINE(HAVE_UOFF_T,, [Define if you have a native uoff_t type])
], [
  have_uoff_t=no
])

AC_TYPEOF(off_t, long int long-long)
case "$typeof_off_t" in
  int)
    offt_max=INT_MAX
    uofft_max=UINT_MAX
    uofft_fmt="u"
    if test "$have_uoff_t" != "yes"; then
      AC_DEFINE(UOFF_T_INT,, [Define if off_t is int])
    fi
    offt_bits=`expr 8 \* $ac_cv_sizeof_int`
    ;;
  long)
    offt_max=LONG_MAX
    uofft_max=ULONG_MAX
    uofft_fmt="lu"
    if test "$have_uoff_t" != "yes"; then
      AC_DEFINE(UOFF_T_LONG,, [Define if off_t is long])
    fi
    offt_bits=`expr 8 \* $ac_cv_sizeof_long`
    ;;
  "long long")
    offt_max=LLONG_MAX
    uofft_max=ULLONG_MAX
    uofft_fmt="llu"
    if test "$have_uoff_t" != "yes"; then
      AC_DEFINE(UOFF_T_LONG_LONG,, [Define if off_t is long long])
    fi
    offt_bits=`expr 8 \* $ac_cv_sizeof_long_long`
    ;;
  *)
    AC_MSG_ERROR([Unsupported off_t type])
    ;;
esac

DOVECOT_DIRENT_DTYPE
DOVECOT_OFF_T_MAX
DOVECOT_UOFF_T_MAX

AC_DEFINE_UNQUOTED(PRIuUOFF_T, "$uofft_fmt", [printf() format for uoff_t])

DOVECOT_SIZE_T_SIGNED

AC_DEFINE_UNQUOTED(SSIZE_T_MAX, $ssizet_max, [Maximum value of ssize_t])
AC_DEFINE_UNQUOTED(PRIuSIZE_T, "$sizet_fmt", [printf() format for size_t])

dnl we require inttypes.h for PRIu{8,16,32,64} macros
AC_CHECK_HEADER(inttypes.h,,AC_MSG_ERROR([inttypes.h missing but required]))

dnl some systems don't have stdint.h, but still have some of the types
dnl defined elsewhere
AC_CHECK_HEADER(stdint.h, [
  stdint_include="#include <stdint.h>"
])

AC_CHECKTYPE2(uintmax_t, [$stdint_include])
if test $i_cv_type_uintmax_t = yes; then
  AC_DEFINE(HAVE_UINTMAX_T,, [Define if you have uintmax_t (C99 type)])
fi

dnl use separate check, eg. Solaris 8 has uintmax_t but not uint_fast32_t
AC_CHECKTYPE2(uint_fast32_t, [$stdint_include])
if test $i_cv_type_uint_fast32_t = yes; then
  AC_DEFINE(HAVE_UINT_FAST32_T,, [Define if you have uint_fast32_t (C99 type)])
fi

AC_CHECKTYPE2(socklen_t, [#include <sys/socket.h>])
if test $i_cv_type_socklen_t = yes; then
  AC_DEFINE(HAVE_SOCKLEN_T,, [Define to 'int' if you don't have socklen_t])
fi

AC_DEFINE_UNQUOTED(MEM_ALIGN_SIZE, $mem_align, [Required memory alignment])

dnl * find random source

AC_ARG_WITH(random-source,
AS_HELP_STRING([--with-random-source=file], [Device file to use as random source (default=/dev/urandom)]),
        random_source=$withval,
        random_source=/dev/urandom)

AC_MSG_CHECKING([for $random_source])
if test -c $random_source || test -s $random_source; then
  AC_MSG_RESULT(yes)
  AC_DEFINE_UNQUOTED(DEV_URANDOM_PATH, ["$random_source"], [Path to random source])
  have_random_source=yes
else
  AC_MSG_ERROR([$random_source not found or is not character device - please provide path for random source device])
fi

if test "$have_random_source" != "yes"; then
  AC_CHECK_HEADER(openssl/rand.h, [
    AC_DEFINE(HAVE_OPENSSL_RAND_H,, [Define if you have openssl/rand.h])
    LIBS="$LIBS -lcrypto"
  ])
fi

DOVECOT_TM_GMTOFF
DOVECOT_GMTIME_MAX
DOVECOT_TIME_T

DOVECOT_C_STATIC_ARRAY
DOVECOT_C_FLEXIBLE_ARRAY_MEMBER

DOVECOT_IOVEC

DOVECOT_TYPEOF_DEV_T

DOVECOT_RLIMIT_AS
DOVECOT_RLIMIT_NPROC
DOVECOT_RLIMIT_CORE

DOVECOT_PR_SET_DUMPABLE

DOVECOT_LINUX_MREMAP

DOVECOT_MMAP_WRITE

DOVECOT_FD_PASSING

DOVECOT_SENDFILE

DOVECOT_UNSETENV_RET_INT

DOVECOT_CRYPT_XPG6
DOVECOT_CRYPT

DOVECOT_ST_TIM_TIMESPEC

DOVECOT_FILE_BLOCKDEV

DOVECOT_DQBLK_CURBLOCKS
DOVECOT_DQBLK_CURSPACE

DOVECOT_Q_QUOTACTL

DOVECOT_C99_VSNPRINTF

DOVECOT_VA_COPY
DOVECOT_VA_COPY_BYVAL

DOVECOT_MODULES

DOVECOT_MNTCTL

DOVECOT_SSL

DOVECOT_WANT_UNWIND

dnl **
dnl ** userdb and passdb checks
dnl **

userdb=""
passdb=""
not_userdb=""
not_passdb=""

passdb="$passdb static"
userdb="$userdb static"
dict_drivers=""

dnl *** auth/userdb/dict things
DOVECOT_WANT_LUA
DOVECOT_WANT_PREFETCH
DOVECOT_WANT_PASSWD
DOVECOT_WANT_SHADOW
DOVECOT_WANT_PAM
DOVECOT_WANT_CHECKPASSWORD
DOVECOT_WANT_BSDAUTH
DOVECOT_WANT_GSSAPI
DOVECOT_WANT_SIA
DOVECOT_WANT_LDAP
DOVECOT_WANT_DB
DOVECOT_WANT_CDB
DOVECOT_WANT_PGSQL
DOVECOT_WANT_MYSQL
DOVECOT_WANT_SODIUM
DOVECOT_WANT_SQLITE
DOVECOT_WANT_CASSANDRA
DOVECOT_WANT_VPOPMAIL

DOVECOT_SQL

AM_CONDITIONAL([AUTH_LUA_PLUGIN], [test "x$with_lua_plugin" = "xyes"])
AM_CONDITIONAL([HAVE_LUA], [test "x$with_luajit" = "xyes" || test "x$with_lua" = "xyes"])
AS_IF([test "x$with_luajit" = "xyes" || test "x$with_lua" = "xyes"],
  AS_IF([test "x$with_lua_plugin" = "xyes"],
      [userdb="$userdb lua (plugin)"; passdb="$passdb lua (plugin)"],
      [userdb="$userdb lua"; passdb="$passdb lua"],
  ), [])

if test $have_modules = yes; then
  AC_DEFINE(HAVE_MODULES,, [Define if you have dynamic module support])
  AC_SUBST(MODULE_LIBS)

  # shrext_cmds comes from libtool.m4
  module=yes eval MODULE_SUFFIX=$shrext_cmds
  if test "$MODULE_SUFFIX" = ""; then
    # too old libtool?
    MODULE_SUFFIX=.so
  fi
  AC_DEFINE_UNQUOTED(MODULE_SUFFIX,"$MODULE_SUFFIX", [Dynamic module suffix])
  AC_SUBST(MODULE_SUFFIX)
fi

AC_SUBST(AUTH_CFLAGS)
AC_SUBST(AUTH_LIBS)
AC_SUBST(SQL_CFLAGS)
AC_SUBST(SQL_LIBS)
AC_SUBST(MYSQL_CFLAGS)
AC_SUBST(MYSQL_LIBS)
AC_SUBST(PGSQL_CFLAGS)
AC_SUBST(PGSQL_LIBS)
AC_SUBST(SQLITE_CFLAGS)
AC_SUBST(SQLITE_LIBS)
AC_SUBST(CASSANDRA_CFLAGS)
AC_SUBST(CASSANDRA_LIBS)

AC_SUBST(DICT_LIBS)
AC_SUBST(CDB_LIBS)
AC_SUBST(dict_drivers)

AC_C_BIGENDIAN

DOVECOT_IPV6

dnl **
dnl ** storage classes
dnl **

CORE_LIBS='$(top_builddir)/src/lib-dovecot/libdovecot.la'
STORAGE_LIB='$(top_builddir)/src/lib-storage/libdovecot-storage.la'

LINKED_STORAGE_LDADD=
AC_SUBST(LINKED_STORAGE_LDADD)

dnl **
dnl ** Shared libraries usage
dnl **

LIBDOVECOT_LA_LIBS='\
	$(top_builddir)/src/lib-dict-extra/libdict_extra.la \
	$(top_builddir)/src/lib-oauth2/liboauth2.la \
	$(top_builddir)/src/lib-smtp/libsmtp.la \
	$(top_builddir)/src/lib-program-client/libprogram_client.la \
	$(top_builddir)/src/lib-master/libmaster.la \
	$(top_builddir)/src/lib-settings/libsettings.la \
	$(top_builddir)/src/lib-old-stats/libold_stats.la \
	$(top_builddir)/src/lib-http/libhttp.la \
	$(top_builddir)/src/lib-fs/libfs.la \
	$(top_builddir)/src/lib-dict/libdict.la \
	$(top_builddir)/src/lib-dns/libdns.la \
	$(top_builddir)/src/lib-imap/libimap.la \
	$(top_builddir)/src/lib-mail/libmail.la \
	$(top_builddir)/src/lib-sasl/libsasl.la \
	$(top_builddir)/src/lib-auth/libauth.la \
	$(top_builddir)/src/lib-charset/libcharset.la \
	$(top_builddir)/src/lib-ssl-iostream/libssl_iostream.la \
	$(top_builddir)/src/lib-dcrypt/libdcrypt.la \
	$(top_builddir)/src/lib-test/libtest.la \
	$(top_builddir)/src/lib/liblib.la'
# This is used in dovecot-config, which is grepped in dovecot.m4,
# so it needs to be in a single line.
LIBDOVECOT_LA_LIBS=`echo "$LIBDOVECOT_LA_LIBS" | tr -d '\t\n\\\\'`

if test "$want_shared_libs" = "yes"; then
  LIBDOVECOT_DEPS='$(top_builddir)/src/lib-dovecot/libdovecot.la'
  LIBDOVECOT="$LIBDOVECOT_DEPS \$(MODULE_LIBS)"
  LIBDOVECOT_STORAGE_DEPS='$(top_builddir)/src/lib-storage/libdovecot-storage.la $(top_builddir)/src/lib-imap-storage/libimap-storage.la'
  LIBDOVECOT_LOGIN='$(top_builddir)/src/login-common/libdovecot-login.la'
  LIBDOVECOT_LDA='$(top_builddir)/src/lib-lda/libdovecot-lda.la'
else
  LIBDOVECOT_DEPS="$LIBDOVECOT_LA_LIBS"
  LIBDOVECOT="$LIBDOVECOT_DEPS \$(LIBICONV) \$(MODULE_LIBS)"
  LIBDOVECOT_STORAGE_DEPS='$(top_builddir)/src/lib-storage/libstorage.la'
  LIBDOVECOT_LOGIN='$(top_builddir)/src/login-common/liblogin.la'
  LIBDOVECOT_LDA='$(top_builddir)/src/lib-lda/liblda.la'
fi
if test $want_ldap != no; then
  LIBDOVECOT_LDAP='$(top_builddir)/src/lib-ldap/libdovecot-ldap.la'
else
  LIBDOVECOT_LDAP=''
fi
LIBDOVECOT_STORAGE="$LIBDOVECOT_STORAGE_DEPS"
LIBDOVECOT_DSYNC='$(top_builddir)/src/doveadm/dsync/libdovecot-dsync.la'
LIBDOVECOT_SQL='$(top_builddir)/src/lib-sql/libsql.la'
LIBDOVECOT_COMPRESS='$(top_builddir)/src/lib-compression/libcompression.la'
LIBDOVECOT_LIBFTS='$(top_builddir)/src/lib-fts/libfts.la'
AC_SUBST(LIBDOVECOT)
AC_SUBST(LIBDOVECOT_LA_LIBS)
AC_SUBST(LIBDOVECOT_DEPS)
AC_SUBST(LIBDOVECOT_STORAGE)
AC_SUBST(LIBDOVECOT_STORAGE_DEPS)
AC_SUBST(LIBDOVECOT_LOGIN)
AC_SUBST(LIBDOVECOT_SQL)
AC_SUBST(LIBDOVECOT_COMPRESS)
AC_SUBST(LIBDOVECOT_DSYNC)
AC_SUBST(LIBDOVECOT_LDA)
AC_SUBST(LIBDOVECOT_LDAP)
AC_SUBST(LIBDOVECOT_LIBFTS)
AC_SUBST(LIBDOVECOT_LIBFTS_DEPS)

dnl **
dnl ** SQL drivers
dnl **

build_pgsql=no
build_mysql=no
build_sqlite=no
build_cassandra=no
for driver in $sql_drivers; do
  if test "$driver" = "pgsql"; then
    AC_DEFINE(BUILD_PGSQL,, [Built-in PostgreSQL support])
    build_pgsql=yes
  elif test "$driver" = "mysql"; then
    AC_DEFINE(BUILD_MYSQL,, [Built-in MySQL support])
    build_mysql=yes
  elif test "$driver" = "sqlite"; then
    AC_DEFINE(BUILD_SQLITE,, [Built-in SQLite support])
    build_sqlite=yes
  elif test "$driver" = "cassandra"; then
    AC_DEFINE(BUILD_CASSANDRA,, [Built-in Cassandra support])
    build_cassandra=yes
  fi
done
if test $build_pgsql = no; then
  not_sql_drivers="$not_sql_drivers pgsql"
fi
if test $build_mysql = no; then
  not_sql_drivers="$not_sql_drivers mysql"
fi
if test $build_sqlite = no; then
  not_sql_drivers="$not_sql_drivers sqlite"
fi
if test $build_cassandra = no; then
  not_sql_drivers="$not_sql_drivers cassandra"
fi

AC_SUBST(sql_drivers)
AM_CONDITIONAL(BUILD_PGSQL, test "$build_pgsql" = "yes")
AM_CONDITIONAL(BUILD_MYSQL, test "$build_mysql" = "yes")
AM_CONDITIONAL(BUILD_SQLITE, test "$build_sqlite" = "yes")
AM_CONDITIONAL(BUILD_CASSANDRA, test "$build_cassandra" = "yes")
AM_CONDITIONAL(SQL_PLUGINS, test "$want_sql" = "plugin")

dnl **
dnl ** Plugins
dnl **

COMPRESS_LIBS=

DOVECOT_WANT_ZLIB
DOVECOT_WANT_BZLIB
DOVECOT_WANT_LZMA
DOVECOT_WANT_LZ4

AC_SUBST(COMPRESS_LIBS)

AM_CONDITIONAL(BUILD_ZLIB_PLUGIN, test "$have_compress_lib" = "yes")

DOVECOT_RPCGEN
DOVECOT_QUOTA

dnl
dnl ** Full text search
dnl

fts=" squat"
not_fts=""

DOVECOT_WANT_SOLR
DOVECOT_WANT_CLUCENE
DOVECOT_WANT_STEMMER
DOVECOT_WANT_TEXTCAT

DOVECOT_WANT_ICU

DOVECOT_WANT_APPARMOR

if test $have_lucene = no; then
  not_fts="$not_fts lucene"
fi
if test $have_solr = no; then
  not_fts="$not_fts solr"
fi

dnl **
dnl ** Settings
dnl **

dnl get a list of setting .[ch] files, but list .h files first
FILES1=`find $srcdir/src -name '*settings.[[ch]]'|grep "$srcdir/src/lib-" | sed 's/^\(.*\)\(.\)$/\2 \1\2/' | grep -E -v 'lib-(master|smtp).*c$' | sort -r | sed s/^..//`
FILES2=`find $srcdir/src -name '*settings.[[ch]]'|grep -v "$srcdir/src/lib-" | sed 's/^\(.*\)\(.\)$/\2 \1\2/' | grep -v all-settings | sort -r | sed s/^..//`
SETTING_FILES=`echo $FILES1 $FILES2 | sed -e s,$srcdir/src,./src,g -e 's,./src,$(top_srcdir)/src,g'`
AC_SUBST(SETTING_FILES)

dnl **
dnl ** capabilities
dnl **

dnl IDLE doesn't really belong to banner. It's there just to make Blackberries
dnl happy, because otherwise BIS server disables push email.
capability_banner="IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE"
capability="$capability_banner SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY STATUS=SIZE"
AC_DEFINE_UNQUOTED(CAPABILITY_STRING, "$capability", [IMAP capabilities])
AC_DEFINE_UNQUOTED(CAPABILITY_BANNER_STRING, "$capability_banner", [IMAP capabilities advertised in banner])

CFLAGS="$CFLAGS $EXTRA_CFLAGS"
BINARY_LDFLAGS="$PIE_LDFLAGS $RELRO_LDFLAGS"
BINARY_CFLAGS="$PIE_CFLAGS"

AC_SUBST(BINARY_CFLAGS)
AC_SUBST(BINARY_LDFLAGS)

NOPLUGIN_LDFLAGS="-no-undefined"
if test "$with_gnu_ld" = yes; then
  NOPLUGIN_LDFLAGS="$NOPLUGIN_LDFLAGS -Wl,--as-needed"
fi
LDFLAGS="\$(NOPLUGIN_LDFLAGS) $LDFLAGS $EXTRA_LDFLAGS"
AC_SUBST(NOPLUGIN_LDFLAGS)

DC_CC_WRAPPER
DC_PANDOC

if test "$docdir" = ""; then
  dnl docdir supported only by autoconf v2.59c and later
  docdir='${datadir}/doc/${PACKAGE_TARNAME}'
fi
AC_SUBST(docdir)

DC_DOVECOT_TEST_WRAPPER
AC_SUBST(abs_top_builddir)

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
Makefile
doc/Makefile
doc/man/Makefile
doc/wiki/Makefile
doc/example-config/Makefile
doc/example-config/conf.d/Makefile
src/Makefile
src/lib/Makefile
src/lib-sql/Makefile
src/lib-auth/Makefile
src/lib-charset/Makefile
src/lib-compression/Makefile
src/lib-dcrypt/Makefile
src/lib-dict/Makefile
src/lib-dict-backend/Makefile
src/lib-dict-extra/Makefile
src/lib-dns/Makefile
src/lib-fs/Makefile
src/lib-fts/Makefile
src/lib-http/Makefile
src/lib-oauth2/Makefile
src/lib-imap/Makefile
src/lib-imap-storage/Makefile
src/lib-imap-client/Makefile
src/lib-imap-urlauth/Makefile
src/lib-index/Makefile
src/lib-lda/Makefile
src/lib-ldap/Makefile
src/lib-lua/Makefile
src/lib-mail/Makefile
src/lib-master/Makefile
src/lib-ntlm/Makefile
src/lib-program-client/Makefile
src/lib-otp/Makefile
src/lib-dovecot/Makefile
src/lib-sasl/Makefile
src/lib-settings/Makefile
src/lib-smtp/Makefile
src/lib-ssl-iostream/Makefile
src/lib-old-stats/Makefile
src/lib-test/Makefile
src/lib-storage/Makefile
src/lib-storage/list/Makefile
src/lib-storage/index/Makefile
src/lib-storage/index/imapc/Makefile
src/lib-storage/index/pop3c/Makefile
src/lib-storage/index/maildir/Makefile
src/lib-storage/index/mbox/Makefile
src/lib-storage/index/dbox-common/Makefile
src/lib-storage/index/dbox-multi/Makefile
src/lib-storage/index/dbox-single/Makefile
src/lib-storage/index/cydir/Makefile
src/lib-storage/index/raw/Makefile
src/lib-storage/index/shared/Makefile
src/anvil/Makefile
src/auth/Makefile
src/config/Makefile
src/doveadm/Makefile
src/doveadm/dsync/Makefile
src/lda/Makefile
src/log/Makefile
src/lmtp/Makefile
src/dict/Makefile
src/director/Makefile
src/dns/Makefile
src/indexer/Makefile
src/ipc/Makefile
src/imap/Makefile
src/imap-hibernate/Makefile
src/imap-login/Makefile
src/imap-urlauth/Makefile
src/login-common/Makefile
src/master/Makefile
src/pop3/Makefile
src/pop3-login/Makefile
src/submission/Makefile
src/submission-login/Makefile
src/replication/Makefile
src/replication/aggregator/Makefile
src/replication/replicator/Makefile
src/stats/Makefile
src/old-stats/Makefile
src/util/Makefile
src/plugins/Makefile
src/plugins/acl/Makefile
src/plugins/imap-acl/Makefile
src/plugins/autocreate/Makefile
src/plugins/expire/Makefile
src/plugins/fs-compress/Makefile
src/plugins/fts/Makefile
src/plugins/fts-lucene/Makefile
src/plugins/fts-solr/Makefile
src/plugins/fts-squat/Makefile
src/plugins/last-login/Makefile
src/plugins/lazy-expunge/Makefile
src/plugins/listescape/Makefile
src/plugins/mail-filter/Makefile
src/plugins/mail-log/Makefile
src/plugins/mail-lua/Makefile
src/plugins/mailbox-alias/Makefile
src/plugins/notify/Makefile
src/plugins/notify-status/Makefile
src/plugins/push-notification/Makefile
src/plugins/pop3-migration/Makefile
src/plugins/quota/Makefile
src/plugins/quota-clone/Makefile
src/plugins/imap-quota/Makefile
src/plugins/replication/Makefile
src/plugins/snarf/Makefile
src/plugins/old-stats/Makefile
src/plugins/imap-old-stats/Makefile
src/plugins/trash/Makefile
src/plugins/virtual/Makefile
src/plugins/welcome/Makefile
src/plugins/zlib/Makefile
src/plugins/imap-zlib/Makefile
src/plugins/mail-crypt/Makefile
src/plugins/var-expand-crypt/Makefile
src/plugins/apparmor/Makefile
src/plugins/charset-alias/Makefile
stamp.h
dovecot-config.in])

AC_OUTPUT

if test "$want_sql" = "plugin"; then
  sql_drivers="$sql_drivers (plugins)"
fi

not_passdb=`echo "$not_passdb"|sed 's/ / -/g'`
not_userdb=`echo "$not_userdb"|sed 's/ / -/g'`
not_sql_drivers=`echo "$not_sql_drivers"|sed 's/ / -/g'`
not_fts=`echo "$not_fts"|sed 's/ / -/g'`

echo
echo "Install prefix . : $prefix"
echo "File offsets ... : ${offt_bits}bit"
echo "I/O polling .... : $ioloop"
echo "I/O notifys .... : $have_notify"
echo "SSL ............ : $have_ssl"
echo "GSSAPI ......... : $have_gssapi"
echo "passdbs ........ :$passdb"
echo "CFLAGS ......... : $CFLAGS"
if test "$not_passdb" != ""; then
  echo "                 :$not_passdb"
fi
echo "userdbs ........ :$userdb"
if test "$not_userdb" != ""; then
  echo "                 :$not_userdb"
fi
echo "SQL drivers .... :$sql_drivers"
if test "$not_sql_drivers" != ""; then
  echo "                 :$not_sql_drivers"
fi
echo "Full text search :$fts"
if test "$not_fts" != ""; then
  echo "                 :$not_fts"
fi
