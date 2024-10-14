AC_PREREQ([2.69])

m4_define([dovecot_VERSION],
    m4_esyscmd_s([build-aux/git-version-gen]))))

m4_define([dovecot_ABI_VERSION],
    m4_esyscmd_s([build-aux/git-abi-version-gen]))))

# Be sure to update ABI version also if anything changes that might require
# recompiling plugins. Most importantly that means if any structs are changed.
AC_INIT([Dovecot], m4_defn([dovecot_VERSION]), [dovecot@dovecot.org])
AC_DEFINE([DOVECOT_ABI_VERSION], m4_quote(m4_defn([dovecot_ABI_VERSION])), [Dovecot ABI version])

AC_CONFIG_SRCDIR([src])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([foreign tar-ustar])
AM_SILENT_RULES([yes])

AM_MAINTAINER_MODE
PKG_PREREQ([0.28])
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

AC_ARG_ENABLE([pro-build],
  [AS_HELP_STRING([--enable-pro-build], [Enable pro build related defines])],
  [is_pro_build=yes],
  [is_pro_build=no]
)

experimental_capabilities=""
AC_ARG_ENABLE(experimental-mail-utf8,
AS_HELP_STRING([--enable-experimental-mail-utf8], [Enable experimental support for SMTPUTF8 and UTF8=ACCEPT]),
	AS_IF([test x$enableval = xyes], [
	       AC_DEFINE([EXPERIMENTAL_MAIL_UTF8],, [Build with SMTPUTF8 and UTF8=ACCEPT support])
	       experimental_capabilities="${experimental_capabilities} UTF8=ACCEPT"
	])
)

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

AC_ARG_WITH(ldap,
AS_HELP_STRING([--with-ldap=yes|plugin], [Build with LDAP support]),
  TEST_WITH(ldap, $withval, plugin),
  want_ldap=no)

AC_ARG_WITH(libunwind,
AS_HELP_STRING([--with-libunwind], [Build with libunwind support (auto)]),
  TEST_WITH(libunwind, $withval),
  want_libunwind=auto)

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

AC_ARG_WITH(flatcurve,
AS_HELP_STRING([--with-flatcurve], [Build with Flatcurve (Xapian) full text search support (auto)]),
  TEST_WITH(flatcurve, $withval),
  want_flatcurve=auto)

AC_ARG_WITH(sodium,
AS_HELP_STRING([--with-sodium], [Build with libsodium support (enables argon2, default: auto)]),
  TEST_WITH(sodium, $withval),
  want_sodium=auto)

AC_ARG_WITH(bzlib,
AS_HELP_STRING([--with-bzlib], [Build with bzlib compression support (auto)]),
  TEST_WITH(bzlib, $withval),
  want_bzlib=auto)

AC_ARG_WITH(lz4,
AS_HELP_STRING([--with-lz4], [Build with LZ4 compression support (auto)]),
  TEST_WITH(lz4, $withval),
  want_lz4=auto)

AC_ARG_WITH(zstd,
AS_HELP_STRING([--with-zstd], [Build with ZSTD compression support (auto)]),
  TEST_WITH(zstd, $withval),
  want_zstd=auto)

AC_ARG_WITH(libcap,
AS_HELP_STRING([--with-libcap], [Build with libcap support (Dropping capabilities) (auto)]),
  TEST_WITH(libcap, $withval),
  want_libcap=auto)

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

AC_ARG_WITH([systemd],
   AS_HELP_STRING([--with-systemd], [Build with systemd support (default=auto)]),
   want_systemd="$withval",
   want_systemd="auto"
)

AC_ARG_WITH([lua],
AS_HELP_STRING([--with-lua=yes|auto|plugin], [Build with Lua bindings (default=auto)]),
  TEST_WITH(lua, $withval, plugin),
  want_lua=auto)

DOVECOT_WANT_SYSTEMD

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
AM_CONDITIONAL(INSTALL_DOCS, test "$want_docs" = "yes")

dnl always enable all of the passbs and userdbs that don't require extra libs
want_passwd=yes
want_passwd_file=yes
want_prefetch_userdb=yes

AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX # lucene plugin needs this
AC_CHECK_TOOL([FLEX],[flex],[:])
AC_CHECK_TOOL([BISON],[bison],[:])
AM_MISSING_PROG([WGET], [wget])

AS_IF([test "$BISON" = ":" && test ! -e "$srcdir/src/lib/event-filter-parser.h"],
  AC_MSG_ERROR([Bison is required when building from git])
])
AS_IF([test "$FLEX" = ":" && test ! -e "$srcdir/src/lib/event-filter-lexer.c"],
  AC_MSG_ERROR([flex is required when building from git])
])
AC_C_INLINE
LT_INIT
AM_ICONV

# SIZE_MAX is missing without this
CXXFLAGS="$CXXFLAGS -D__STDC_LIMIT_MACROS"

if test "$is_pro_build" = "yes"; then
  SET_PRO_DEFINES
  DOVECOT_CONFIG_VERSION=3.0.0
  AC_SUBST(DOVECOT_ASSET_URL, "doc.dovecotpro.com")
  AC_SUBST(DOVECOT_PRO_BUILD, 1)
else
  AC_DEFINE_UNQUOTED(DOVECOT_NAME, "$PACKAGE_NAME", [Dovecot name])
  AC_SUBST(DOVECOT_ASSET_URL, "doc.dovecot.org")
  AC_SUBST(DOVECOT_PRO_BUILD, 0)
  DOVECOT_CONFIG_VERSION=2.4.0
fi
AC_DEFINE_UNQUOTED(DOVECOT_CONFIG_VERSION, "$DOVECOT_CONFIG_VERSION", [Dovecot configuration version])
AC_SUBST(DOVECOT_CONFIG_VERSION)

AC_DEFINE_UNQUOTED(DOVECOT_STRING, "$PACKAGE_STRING", [Dovecot string])
AC_DEFINE_UNQUOTED(DOVECOT_VERSION, "$PACKAGE_VERSION", [Dovecot version])

AC_DEFINE([DOVECOT_VERSION_MAJOR], regexp(AC_PACKAGE_VERSION, [^\([0-9]+\)\.\([0-9]+\)], [\1]), [Dovecot major version])
AC_DEFINE([DOVECOT_VERSION_MINOR], regexp(AC_PACKAGE_VERSION, [^\([0-9]+\)\.\([0-9]+\)], [\2]), [Dovecot minor version])
AC_DEFINE([DOVECOT_VERSION_MICRO], regexp(AC_PACKAGE_VERSION, [^\([0-9]+\)\.\([0-9]+\).\([0-9]+\)], [\3]), [Dovecot micro version])

AC_SUBST(DOVECOT_ASSET_VERSION, regexp(AC_PACKAGE_VERSION, [^\([0-9]+\)\.\([0-9]+\).\([0-9]+\)], [\1.\2.\3]))
AS_IF([test $DOVECOT_ASSET_VERSION = "0.0.0"], [
  AC_SUBST([DOVECOT_ASSET_VERSION], "main")
])

AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
],[
#if DOVECOT_VERSION_MICRO > 0
#endif
])], [], AC_DEFINE([DOVECOT_VERSION_MICRO], [0], [Dovecot micro version]))

AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
],[
#if DOVECOT_VERSION_MAJOR > 0 && DOVECOT_VERSION_MINOR > 0
#endif
])], [], AC_MSG_ERROR([Version macros broken]))

AC_CHECK_HEADERS(strings.h stdint.h unistd.h dirent.h malloc.h \
  sys/uio.h sys/sysmacros.h sys/resource.h sys/select.h \
  sys/quota.h sys/fs/ufs_quota.h ufs/ufs/quota.h jfs/quota.h \
  quota.h sys/fs/quota_common.h \
  mntent.h sys/mnttab.h sys/event.h sys/time.h sys/mkdev.h linux/dqblk_xfs.h \
  xfs/xqm.h execinfo.h ucontext.h malloc_np.h sys/utsname.h sys/vmount.h \
  sys/utsname.h glob.h linux/falloc.h ucred.h sys/ucred.h crypt.h)

CC_CLANG
CC_STRICT_BOOL
AC_LD_WHOLE_ARCHIVE
DC_DOVECOT_HARDENING
DC_DOVECOT_FUZZER
DC_DOVECOT_CFLAGS

DOVECOT_NSL
DOVECOT_LIBCAP

DOVECOT_RANDOM
DOVECOT_ARC4RANDOM

AC_DEFINE(PACKAGE_WEBPAGE, "https://www.dovecot.org/", [Support URL])

AC_CHECK_FUNCS(flock pread setproctitle setresgid \
	       getmntinfo setpriority quotactl getmntent kqueue kevent \
	       backtrace_symbols walkcontext dirfd clearenv \
	       malloc_usable_size glob fallocate posix_fadvise \
	       getpeereid getpeerucred inotify_init timegm)

AC_CHECK_HEADERS([valgrind/valgrind.h])

DOVECOT_SOCKPEERCRED

DOVECOT_TYPEOF
DOVECOT_IOLOOP
DOVECOT_NOTIFY
AS_CASE(
   ["$notify"],
   [none],   [BUILD_IMAP_HIBERNATE=0],
   [kqueue], [BUILD_IMAP_HIBERNATE=0],
   [BUILD_IMAP_HIBERNATE=1])
AS_IF([test "x$BUILD_IMAP_HIBERNATE" = x0],
   [AC_DEFINE([IGNORE_IMAP_HIBERNATE_SERVICE],, [Ignore imap-hibernate service])])
AM_CONDITIONAL([BUILD_IMAP_HIBERNATE], [test "x$BUILD_IMAP_HIBERNATE" = x1])

DOVECOT_GLIBC

DOVECOT_SCHED

dnl * OS specific options
DC_PLUGIN_DEPS
case "$host_os" in
	linux*|darwin*)
		AC_DEFINE(PROCTITLE_HACK,, [Define if process title can be changed by modifying argv])
		;;
	*)
		;;
esac

dnl these macros - additionally to the HAVE_<type> values - cache the
dnl result in `$ac_cv_sizeof_<type>`, which are used in the AC_TYPEOF
dnl macro and the off_t-specific checks
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(void *)
AC_CHECK_SIZEOF(long long)
AC_CHECK_SIZEOF(size_t)

AC_SYS_LARGEFILE

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

dnl we require inttypes.h for PRIu{8,16,32,64} macros
AC_CHECK_HEADER(inttypes.h,,AC_MSG_ERROR([inttypes.h missing but required]))

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

AC_C_FLEXIBLE_ARRAY_MEMBER

DOVECOT_IOVEC

DOVECOT_RLIMIT_AS
DOVECOT_RLIMIT_NPROC
DOVECOT_RLIMIT_CORE

DOVECOT_PR_SET_DUMPABLE

DOVECOT_LINUX_MREMAP

DOVECOT_MMAP_WRITE

DOVECOT_FD_PASSING
DOVECOT_FACCESSAT2

DOVECOT_SENDFILE

DOVECOT_CRYPT_XPG6
DOVECOT_CRYPT

DOVECOT_ST_TIM_TIMESPEC

DOVECOT_FILE_BLOCKDEV

DOVECOT_DQBLK_CURBLOCKS
DOVECOT_DQBLK_CURSPACE

DOVECOT_Q_QUOTACTL

DOVECOT_VA_COPY

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
DOVECOT_WANT_PAM
DOVECOT_WANT_BSDAUTH
DOVECOT_WANT_GSSAPI
DOVECOT_WANT_LDAP
DOVECOT_WANT_CDB
DOVECOT_WANT_PGSQL
DOVECOT_WANT_MYSQL
DOVECOT_WANT_SODIUM
DOVECOT_WANT_SQLITE
DOVECOT_WANT_CASSANDRA

DOVECOT_SQL

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

AC_SUBST(DICT_LIBS)
AC_SUBST(CDB_LIBS)
AC_SUBST(dict_drivers)

AC_C_BIGENDIAN

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
	$(top_builddir)/src/lib-doveadm/libdoveadm.la \
	$(top_builddir)/src/lib-dict-extra/libdict_extra.la \
	$(top_builddir)/src/lib-oauth2/liboauth2.la \
	$(top_builddir)/src/lib-smtp/libsmtp.la \
	$(top_builddir)/src/lib-program-client/libprogram_client.la \
	$(top_builddir)/src/lib-master/libmaster.la \
	$(top_builddir)/src/lib-login/liblogin.la \
	$(top_builddir)/src/lib-settings/libsettings.la \
	$(top_builddir)/src/lib-http/libhttp.la \
	$(top_builddir)/src/lib-fs/libfs.la \
	$(top_builddir)/src/lib-dict/libdict.la \
	$(top_builddir)/src/lib-dns/libdns.la \
	$(top_builddir)/src/lib-imap/libimap.la \
	$(top_builddir)/src/lib-mail/libmail.la \
	$(top_builddir)/src/lib-sasl/libsasl.la \
	$(top_builddir)/src/lib-auth/libauth.la \
	$(top_builddir)/src/lib-otp/libotp.la \
	$(top_builddir)/src/lib-auth-client/libauth-client.la \
	$(top_builddir)/src/lib-charset/libcharset.la \
	$(top_builddir)/src/lib-ssl-iostream/libssl_iostream.la \
	$(top_builddir)/src/lib-dcrypt/libdcrypt.la \
	$(top_builddir)/src/lib-json/libjson.la \
	$(top_builddir)/src/lib-test/libtest.la \
	$(top_builddir)/src/lib/liblib.la'
# This is used in dovecot-config, which is grepped in dovecot.m4,
# so it needs to be in a single line.
LIBDOVECOT_LA_LIBS=`echo "$LIBDOVECOT_LA_LIBS" | tr -d '\t\n\\\\'`

LIBDOVECOT_LUA=''

if test "$want_shared_libs" = "yes"; then
  LIBDOVECOT_DEPS='$(top_builddir)/src/lib-dovecot/libdovecot.la'
  LIBDOVECOT="$LIBDOVECOT_DEPS \$(MODULE_LIBS)"
  LIBDOVECOT_STORAGE_DEPS='$(top_builddir)/src/lib-storage/libdovecot-storage.la $(top_builddir)/src/lib-imap-storage/libimap-storage.la'
  LIBDOVECOT_LOGIN='$(top_builddir)/src/login-common/libdovecot-login.la'
  LIBDOVECOT_LDA='$(top_builddir)/src/lib-lda/libdovecot-lda.la'
  if test $want_lua != no; then
    LIBDOVECOT_LUA='$(top_builddir)/src/lib-lua/libdovecot-lua.la'
  fi
else
  LIBDOVECOT_DEPS="$LIBDOVECOT_LA_LIBS"
  LIBDOVECOT="$LIBDOVECOT_DEPS \$(LIBICONV) \$(MODULE_LIBS)"
  LIBDOVECOT_STORAGE_DEPS='$(top_builddir)/src/lib-storage/libstorage.la'
  LIBDOVECOT_LOGIN='$(top_builddir)/src/login-common/liblogin.la'
  LIBDOVECOT_LDA='$(top_builddir)/src/lib-lda/liblda.la'
  if test $want_lua != no; then
    LIBDOVECOT_LUA='$(top_builddir)/src/lib-lua/libdlua.la'
  fi
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

LIBDOVECOT_OPENSSL='$(top_builddir)/src/lib-ssl-iostream/libssl_iostream_openssl.la'
LIBDOVECOT_OPENSSL_DEPS="$LIBDOVECOT_OPENSSL"

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
AC_SUBST(LIBDOVECOT_LUA)
AC_SUBST(LIBDOVECOT_LUA_DEPS)
AC_SUBST(LIBDOVECOT_OPENSSL)
AC_SUBST(LIBDOVECOT_OPENSSL_DEPS)

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

DOVECOT_ZLIB
DOVECOT_WANT_BZLIB
DOVECOT_WANT_LZ4
DOVECOT_WANT_ZSTD

AC_SUBST(COMPRESS_LIBS)

DOVECOT_RPCGEN
DOVECOT_QUOTA

dnl
dnl ** Full text search
dnl

fts=""
not_fts=""

DOVECOT_WANT_SOLR
DOVECOT_WANT_FLATCURVE
DOVECOT_WANT_STEMMER
DOVECOT_WANT_TEXTCAT

DOVECOT_WANT_ICU

DOVECOT_WANT_APPARMOR

if test $have_solr = no; then
  not_fts="$not_fts solr"
fi

dnl **
dnl ** Settings
dnl **

libdovecot_dirs=`echo "$LIBDOVECOT_LA_LIBS" | $SED -e "s:\\$(top_builddir):$srcdir:g" -e 's:/[[^/]]*\\.la::g'`

libdovecot_headers=
libdovecot_c_files=
non_libdovecot_headers=
non_libdovecot_c_files=
all_files=`find $srcdir/src -name '*.[[ch]]' | $GREP -v '/src/config/all-settings.c' | $GREP -v '/src/lib-settings/' | $GREP -v '/test-' | xargs $EGREP '(struct setting_parser_info [[a-z]])|(struct service_settings [[a-z]])|(<settings checks>)' | $SED 's/:.*//' | sort | uniq`
for file in $all_files; do
  dir=`echo "$file" | $SED 's:/[[^/]]*$::'`
  if echo "$libdovecot_dirs" | $GREP "$dir" >/dev/null; then
    dnl lib-dovecot
    if echo "$file" | $GREP '\.h$' >/dev/null; then
      libdovecot_headers="$libdovecot_headers $file"
    else
      libdovecot_c_files="$libdovecot_c_files $file"
    fi
  else
    dnl not lib-dovecot
    if echo "$file" | $GREP '\.h$' >/dev/null; then
      non_libdovecot_headers="$non_libdovecot_headers $file"
    else
      non_libdovecot_c_files="$non_libdovecot_c_files $file"
    fi
  fi
done

dnl libdovecot is linked to doveconf/config binaries, so don't duplicate the .c
dnl file contents. However, we still need to scan the .c files for any
dnl setting_parser_infos that aren't elsewhere.

# list headers first, C files last
SETTING_FILES=`echo $libdovecot_headers $non_libdovecot_headers $non_libdovecot_c_files | $SED -e s,$srcdir/src,./src,g -e 's,./src,$(top_srcdir)/src,g'`
SETTING_LINKED_FILES=`echo $libdovecot_c_files | $SED -e s,$srcdir/src,./src,g -e 's,./src,$(top_srcdir)/src,g'`
AC_SUBST(SETTING_FILES)
AC_SUBST(SETTING_LINKED_FILES)

dnl **
dnl ** capabilities
dnl **

dnl IDLE doesn't really belong to banner. It's there just to make Blackberries
dnl happy, because otherwise BIS server disables push email.
capability_banner="IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE"
capability="$capability_banner SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY PREVIEW STATUS=SIZE SAVEDATE COMPRESS=DEFLATE INPROGRESS${experimental_capabilities}"
AC_DEFINE_UNQUOTED(CAPABILITY_STRING, "$capability", [IMAP capabilities])
AC_DEFINE_UNQUOTED(CAPABILITY_BANNER_STRING, "$capability_banner", [IMAP capabilities advertised in banner])

CFLAGS="$CFLAGS $EXTRA_CFLAGS"
CXXFLAGS="$CXXFLAGS $EXTRA_CFLAGS"
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

if test "$docdir" = ""; then
  dnl docdir supported only by autoconf v2.59c and later
  docdir='${datadir}/doc/${PACKAGE_TARNAME}'
fi
AC_SUBST(docdir)

AS_IF([test "$AR_FLAGS" = "cru"], [AR_FLAGS="cr"], [])
AC_SUBST([AR_FLAGS])

DC_DOVECOT_TEST_WRAPPER
AC_SUBST(abs_top_builddir)

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
Makefile
doc/Makefile
doc/man/Makefile
doc/example-config/Makefile
doc/example-config/conf.d/Makefile
src/Makefile
src/lib/Makefile
src/lib-sql/Makefile
src/lib-auth/Makefile
src/lib-auth-client/Makefile
src/lib-charset/Makefile
src/lib-compression/Makefile
src/lib-dcrypt/Makefile
src/lib-dict/Makefile
src/lib-dict-backend/Makefile
src/lib-dict-extra/Makefile
src/lib-dns/Makefile
src/lib-doveadm/Makefile
src/lib-fs/Makefile
src/lib-fts/Makefile
src/lib-http/Makefile
src/lib-oauth2/Makefile
src/lib-pop3/Makefile
src/lib-imap/Makefile
src/lib-imap-storage/Makefile
src/lib-imap-client/Makefile
src/lib-imap-urlauth/Makefile
src/lib-index/Makefile
src/lib-json/Makefile
src/lib-lda/Makefile
src/lib-ldap/Makefile
src/lib-lua/Makefile
src/lib-mail/Makefile
src/lib-master/Makefile
src/lib-login/Makefile
src/lib-program-client/Makefile
src/lib-otp/Makefile
src/lib-dovecot/Makefile
src/lib-sasl/Makefile
src/lib-settings/Makefile
src/lib-smtp/Makefile
src/lib-ssl-iostream/Makefile
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
src/dns/Makefile
src/indexer/Makefile
src/imap/Makefile
src/imap-hibernate/Makefile
src/imap-login/Makefile
src/imap-urlauth/Makefile
src/imap-urlauth-login/Makefile
src/login-common/Makefile
src/master/Makefile
src/pop3/Makefile
src/pop3-login/Makefile
src/submission/Makefile
src/submission-login/Makefile
src/stats/Makefile
src/util/Makefile
src/plugins/Makefile
src/plugins/acl/Makefile
src/plugins/imap-acl/Makefile
src/plugins/fs-compress/Makefile
src/plugins/fts/Makefile
src/plugins/fts-flatcurve/Makefile
src/plugins/fts-solr/Makefile
src/plugins/last-login/Makefile
src/plugins/lazy-expunge/Makefile
src/plugins/listescape/Makefile
src/plugins/mail-log/Makefile
src/plugins/mail-lua/Makefile
src/plugins/notify/Makefile
src/plugins/notify-status/Makefile
src/plugins/push-notification/Makefile
src/plugins/pop3-migration/Makefile
src/plugins/quota/Makefile
src/plugins/quota-clone/Makefile
src/plugins/imap-quota/Makefile
src/plugins/trash/Makefile
src/plugins/virtual/Makefile
src/plugins/welcome/Makefile
src/plugins/mail-compress/Makefile
src/plugins/mail-crypt/Makefile
src/plugins/var-expand-crypt/Makefile
src/plugins/apparmor/Makefile
src/plugins/charset-alias/Makefile
stamp.h
build-aux/run-test.sh
dovecot-config.in])

AC_OUTPUT

if test "$want_sql" = "plugin"; then
  sql_drivers="$sql_drivers (plugins)"
fi

not_passdb=`echo "$not_passdb"|$SED 's/ / -/g'`
not_userdb=`echo "$not_userdb"|$SED 's/ / -/g'`
not_sql_drivers=`echo "$not_sql_drivers"|$SED 's/ / -/g'`
not_fts=`echo "$not_fts"|$SED 's/ / -/g'`

echo
echo "Install prefix . : $prefix"
echo "File offsets ... : ${offt_bits}bit"
echo "I/O polling .... : $ioloop"
echo "I/O notifys .... : $have_notify"
echo "SSL ............ : openssl"
echo "GSSAPI ......... : $have_gssapi"
echo "passdbs ........ :$passdb"
if test "$not_passdb" != ""; then
  echo "                 :$not_passdb"
fi
echo "userdbs ........ :$userdb"
if test "$not_userdb" != ""; then
  echo "                 :$not_userdb"
fi
echo "CFLAGS ......... : $CFLAGS"

if test "$systemdsystemunitdir" != ""; then
  echo "SYSTEMD ........ : $systemdservicetype - $systemdsystemunitdir/dovecot.service";
else
  echo "SYSTEMD ........ : $systemdservicetype - (no unit file)"
fi

echo "SQL drivers .... :$sql_drivers"
if test "$not_sql_drivers" != ""; then
  echo "                 :$not_sql_drivers"
fi
echo "Full text search :$fts"
if test "$not_fts" != ""; then
  echo "                 :$not_fts"
fi
