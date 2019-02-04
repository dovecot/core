AC_PREREQ([2.59])

# Be sure to update ABI version also if anything changes that might require
# recompiling plugins. Most importantly that means if any structs are changed.
AC_INIT([Dovecot],[2.2.36.1],[dovecot@dovecot.org])
AC_DEFINE_UNQUOTED([DOVECOT_ABI_VERSION], "2.2.ABIv36($PACKAGE_VERSION)", [Dovecot ABI version])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_SRCDIR([src])

AM_INIT_AUTOMAKE([foreign])

AM_MAINTAINER_MODE
PKG_PROG_PKG_CONFIG

ACLOCAL_AMFLAGS='-I $(top_srcdir)'
AC_SUBST(ACLOCAL_AMFLAGS)

dnl TEST_WITH(name, value, [plugin])
AC_DEFUN([TEST_WITH], [
  want=want_`echo $1|sed s/-/_/g`
  if test $2 = yes || test $2 = no || test $2 = auto; then
    eval $want=$2
  elif test $2 = plugin; then
    if test "$3" = plugin; then
      eval $want=plugin
    else
      AC_ERROR([--with-$1=plugin not supported])
    fi
  elif `echo $2|grep '^/' >/dev/null`; then
    AC_ERROR([--with-$1=path not supported. You may want to use instead:
CPPFLAGS=-I$2/include LDFLAGS=-L$2/lib ./configure --with-$1])
  else
    AC_ERROR([--with-$1: Unknown value: $2])
  fi
])

AC_ARG_ENABLE(devel-checks,
AS_HELP_STRING([--enable-devel-checks], [Enable some extra expensive checks for developers]),
	if test x$enableval = xyes; then
		AC_DEFINE(DEBUG,, [Build with extra debugging checks])
		want_devel_checks=yes
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

AC_ARG_WITH(gc,
AS_HELP_STRING([--with-gc], [Use Boehm garbage collector]),
  TEST_WITH(gc, $withval),
  want_gc=no)

AC_ARG_WITH(storages,
AS_HELP_STRING([--with-storages], [Build with specified mail storage formats (mdbox sdbox maildir mbox cydir imapc pop3c)]), [
	if test "$withval" = "yes" || test "$withval" = "no"; then
		AC_MSG_ERROR([--with-storages needs storage list as parameter])
	fi
	mail_storages="shared `echo "$withval"|sed 's/,/ /g'`" ],
	mail_storages="shared mdbox sdbox maildir mbox cydir imapc pop3c")
AC_SUBST(mail_storages)
mail_storages="$mail_storages raw fail"
# drop duplicates
duplicates=`(for i in $mail_storages; do echo $i; done)|sort|uniq -d|xargs echo`
if test "$duplicates" != ""; then
  AC_ERROR([Duplicate --with-storages: $duplicates])
fi

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
  sys/utsname.h glob.h linux/falloc.h ucred.h sys/ucred.h)

dnl * clang check
have_clang=no
if $CC -dM -E -x c /dev/null | grep __clang__ > /dev/null 2>&1; then
  have_clang=yes
fi

dnl * gcc specific options
if test "x$ac_cv_c_compiler_gnu" = "xyes"; then
	# -Wcast-qual -Wcast-align -Wconversion -Wunreachable-code # too many warnings
	# -Wstrict-prototypes -Wredundant-decls # may give warnings in some systems
	# -Wmissing-format-attribute -Wmissing-noreturn -Wwrite-strings # a couple of warnings
	CFLAGS="$CFLAGS -Wall -W -Wmissing-prototypes -Wmissing-declarations -Wpointer-arith -Wchar-subscripts -Wformat=2 -Wbad-function-cast"

	if test "$have_clang" = "yes"; then
	  AC_TRY_COMPILE([
	  #if __clang_major__ > 3 || (__clang_major__ == 3 && __clang_minor__ >= 3)
	  #  error new clang
	  #endif
	  ],,,[
	    # clang 3.3+ unfortunately this gives warnings with hash.h
	    CFLAGS="$CFLAGS -Wno-duplicate-decl-specifier"
	  ])
	else
	  # This is simply to avoid warning when building strftime() wrappers..
	  CFLAGS="$CFLAGS -fno-builtin-strftime"
	fi

	AC_TRY_COMPILE([
	#if __GNUC__ < 4
	#  error old gcc
	#endif
	],,[
	  # gcc4
	  CFLAGS="$CFLAGS -Wstrict-aliasing=2"
	])

	# Use std=gnu99 if we have new enough gcc
	old_cflags=$CFLAGS
	CFLAGS="-std=gnu99"
	AC_TRY_COMPILE([
	],, [
	  CFLAGS="$CFLAGS $old_cflags"
	], [
	  CFLAGS="$old_cflags"
	])
fi
if test "$have_clang" = "yes"; then
  # clang specific options
  if test "$want_devel_checks" = "yes"; then
    # FIXME: enable once md[45], sha[12] can be compiled without
    #CFLAGS="$CFLAGS -fsanitize=integer,undefined -ftrapv"
    :
  fi
fi

dnl **
dnl ** just some generic stuff...
dnl **

AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(inet_addr, nsl)
AC_SEARCH_LIBS(fdatasync, rt, [
  AC_DEFINE(HAVE_FDATASYNC,, [Define if you have fdatasync()])
])

if test $want_libcap != no; then
  AC_CHECK_LIB(cap, cap_init, [
    AC_DEFINE(HAVE_LIBCAP,, [libcap is installed for cap_init()])
    LIBCAP="-lcap"
    AC_SUBST(LIBCAP)
  ], [
    if test "$want_libcap" = "yes"; then
      AC_ERROR([Can't build with libcap support: libcap not found])
    fi
  ])
fi

have_libwrap=no
if test $want_libwrap != no; then
  AC_CHECK_HEADER(tcpd.h, [
    old_LIBS=$LIBS

    AC_CACHE_CHECK([whether we have libwrap],i_cv_have_libwrap,[
      AC_TRY_COMPILE([
	#include <tcpd.h>
	int allow_severity = 0;
	int deny_severity = 0;
      ], [
	request_init((void *)0);
      ], [
	i_cv_have_libwrap=yes
      ], [
	i_cv_have_libwrap=no
      ])
    ])
    if test $i_cv_have_libwrap = yes; then
      AC_DEFINE(HAVE_LIBWRAP,, [Define if you have libwrap])
      LIBWRAP_LIBS=-lwrap
      AC_SUBST(LIBWRAP_LIBS)
      have_libwrap=yes
    else
      if test "$want_libwrap" = "yes"; then
	AC_ERROR([Can't build with libwrap support: libwrap not found])
      fi
    fi
    LIBS=$old_LIBS
  ], [
    if test "$want_libwrap" = "yes"; then
      AC_ERROR([Can't build with libwrap support: tcpd.h not found])
    fi
  ])
fi
AM_CONDITIONAL(TCPWRAPPERS, test "$have_libwrap" = "yes")

AC_DEFINE(PACKAGE_WEBPAGE, "http://www.dovecot.org/", [Support URL])

dnl * after -lsocket and -lnsl tests, inet_aton() may be in them
AC_CHECK_FUNCS(fcntl flock lockf inet_aton sigaction getpagesize madvise \
               strcasecmp stricmp vsyslog writev pread uname unsetenv \
	       setrlimit setproctitle seteuid setreuid setegid setresgid \
	       getmntinfo setpriority quotactl getmntent kqueue kevent \
	       backtrace_symbols walkcontext dirfd clearenv \
	       malloc_usable_size glob fallocate posix_fadvise \
	       getpeereid getpeerucred inotify_init timegm)

AC_CHECK_TYPES([struct sockpeercred],,,[
#include <sys/types.h>
#include <sys/socket.h>
])

AC_SEARCH_LIBS(clock_gettime, rt, [
  AC_DEFINE(HAVE_CLOCK_GETTIME,, [Define if you have the clock_gettime function])
])

AC_CACHE_CHECK([for typeof],i_cv_have_typeof,[
  AC_TRY_COMPILE([
  ], [
    int foo;
    typeof(foo) bar;
  ], [
    i_cv_have_typeof=yes
  ], [
    i_cv_have_typeof=no
  ])
])
if test $i_cv_have_typeof = yes; then
  AC_DEFINE(HAVE_TYPEOF,, [Define if you have typeof()])
fi

dnl * I/O loop function
have_ioloop=no

if test "$ioloop" = "best" || test "$ioloop" = "epoll"; then
  AC_CACHE_CHECK([whether we can use epoll],i_cv_epoll_works,[
    AC_TRY_RUN([
      #include <sys/epoll.h>
  
      int main()
      {
	return epoll_create(5) < 1;
      }
    ], [
      i_cv_epoll_works=yes
    ], [
      i_cv_epoll_works=no
    ])
  ])
  if test $i_cv_epoll_works = yes; then
    AC_DEFINE(IOLOOP_EPOLL,, [Implement I/O loop with Linux 2.6 epoll()])
    have_ioloop=yes
    ioloop=epoll
  else
    if test "$ioloop" = "epoll" ; then
      AC_MSG_ERROR([epoll ioloop requested but epoll_create() is not available])
    fi
  fi
fi

if test "$ioloop" = "best" || test "$ioloop" = "kqueue"; then
    if test "$ac_cv_func_kqueue" = yes && test "$ac_cv_func_kevent" = yes; then
      AC_DEFINE(IOLOOP_KQUEUE,, [Implement I/O loop with BSD kqueue()])
      ioloop=kqueue
      have_ioloop=yes
    elif test "$ioloop" = "kqueue"; then
      AC_MSG_ERROR([kqueue ioloop requested but kqueue() is not available])
    fi
fi

if test "$ioloop" = "best" || test "$ioloop" = "poll"; then
  AC_CHECK_FUNC(poll, [
    AC_DEFINE(IOLOOP_POLL,, [Implement I/O loop with poll()])
    ioloop=poll
    have_ioloop=yes
  ])
fi

if test "$have_ioloop" = "no"; then
  AC_DEFINE(IOLOOP_SELECT,, [Implement I/O loop with select()])
  ioloop="select"
fi

have_notify=none

if test "$notify" = "" || test "$notify" = "inotify" ; then
  dnl * inotify?
  AC_MSG_CHECKING([whether we can use inotify])
  if test "$ac_cv_func_inotify_init" = yes; then
    have_notify=inotify
    notify=inotify
    AC_MSG_RESULT("yes")
    AC_DEFINE(IOLOOP_NOTIFY_INOTIFY,, [Use Linux inotify])
  else
    AC_MSG_RESULT("no")
    if test "$notify" = "inotify"; then
      AC_MSG_ERROR([inotify requested but not available])
      notify=""
    fi
  fi
fi

if (test "$notify" = "" && test "$ioloop" = kqueue) || test "$notify" = "kqueue"; then
  dnl * BSD kqueue() notify
  AC_MSG_CHECKING([whether we can use BSD kqueue() notify])
  if test "$ac_cv_func_kqueue" = yes && test "$ac_cv_func_kevent" = yes ; then
    have_notify=kqueue
    notify=kqueue
    AC_MSG_RESULT("yes")
    AC_DEFINE(IOLOOP_NOTIFY_KQUEUE,, [Use BSD kqueue directory changes notificaton])
  else 
    AC_MSG_RESULT("no")
    if test "$notify" = "kqueue" ; then
      AC_MSG_ERROR([kqueue notify requested but kqueue() is not available])
      notify=""
    fi
  fi
fi

if test "$have_notify" = "none"; then
  AC_DEFINE(IOLOOP_NOTIFY_NONE,, [No special notify support])
fi

AC_CACHE_CHECK([whether we have glibc],i_cv_have_glibc,[
  AC_TRY_COMPILE([
    #include <stdlib.h>
    #ifdef __GLIBC__
      we have glibc
    #endif
  ],, [
    i_cv_have_glibc=no
  ], [
    i_cv_have_glibc=yes
  ])
])
if test "$i_cv_have_glibc" = "yes"; then
  AC_DEFINE(PREAD_WRAPPERS,, [Define if pread/pwrite needs _XOPEN_SOURCE 500])
fi

dnl * Old glibcs have broken posix_fallocate(). Make sure not to use it.
dnl * It may also be broken in AIX.
AC_CACHE_CHECK([whether posix_fallocate() works],i_cv_posix_fallocate_works,[
  AC_TRY_RUN([
    #define _XOPEN_SOURCE 600
    #include <stdio.h>
    #include <stdlib.h>
    #include <fcntl.h>
    #include <unistd.h>
    #if defined(__GLIBC__) && (__GLIBC__ < 2 || __GLIBC_MINOR__ < 7)
      possibly broken posix_fallocate
    #endif
    int main() {
      int fd = creat("conftest.temp", 0600);
      int ret;
      if (fd == -1) {
	perror("creat()");
	return 2;
      }
      ret = posix_fallocate(fd, 1024, 1024) < 0 ? 1 : 0;
      unlink("conftest.temp");
      return ret;
    }
  ], [
    i_cv_posix_fallocate_works=yes
  ], [
    i_cv_posix_fallocate_works=no
  ])
])
if test $i_cv_posix_fallocate_works = yes; then
  AC_DEFINE(HAVE_POSIX_FALLOCATE,, [Define if you have a working posix_fallocate()])
fi

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

AC_DEFUN([AC_TYPEOF], [
  dnl * first check if we can get the size with redefining typedefs

  order="$2"
  if test "$2" = ""; then
    order="int long long-long"
  fi

  result=""
  visible="unknown"
  AC_MSG_CHECKING([type of $1])
  AC_CACHE_VAL(i_cv_typeof_$1,[
  if test "x$ac_cv_c_compiler_gnu" = "xyes"; then
    dnl * try with printf() + -Werror
    old_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS -Werror"

    for type in $order; do
      case "$type" in
        int)
	  fmt="%d"
	  ;;
        unsigned-int)
	  fmt="%u"
	  ;;
        long)
	  fmt="%ld"
	  ;;
        unsigned-long)
	  fmt="%lu"
	  ;;
        long-long)
	  fmt="%lld"
	  ;;
        unsigned-long-long)
	  fmt="%llu"
	  ;;
	*)
	  fmt=""
	  ;;
      esac

      if test "$fmt" != ""; then
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
	  #include <sys/types.h>
	  #include <stdio.h>
	]], [[
	  printf("$fmt", ($1)0);
	]])],[
	  if test "$result" != ""; then
	    dnl * warning check isn't working
	    result=""
	    visible="unknown"
	    break
	  fi
	  result="`echo $type|sed 's/-/ /g'`"
	  visible="$result"
	],[])
      fi
    done
    CFLAGS="$old_CFLAGS"
  fi

  if test "$result" = ""; then
    for type in $order; do
      type="`echo $type|sed 's/-/ /g'`"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
	#include <sys/types.h>
	typedef $type $1;
      ]], [[]])],[
	if test "$result" != ""; then
	  dnl * compiler allows redefining to anything
	  result=""
	  visible="unknown"
	  break
	fi
	result="$type"
	visible="$type"
      ],[])
    done
  fi

  if test "$result" = ""; then
    dnl * check with sizes

    dnl * older autoconfs don't include sys/types.h, so do it manually
    AC_RUN_IFELSE([AC_LANG_SOURCE([[
      #include <stdio.h>
      #include <sys/types.h>
      int main() {
	FILE *f=fopen("conftestval", "w");
	if (!f) exit(1);
	fprintf(f, "%d\n", sizeof($1));
	exit(0);
      }
    ]])],[
      size=`cat conftestval`
      rm -f conftestval

      for type in $order; do
        actype="ac_cv_sizeof_`echo $type|sed 's/-/_/g'`"
        if test "$size" = "`eval echo \\$$actype`"; then
	  result="`echo $type|sed 's/-/ /g'`"
	  visible="`expr $size \* 8`bit (using $result)"
	  break
	fi
      done
      if test "$result" = ""; then
        result=unknown
	visible="`expr $size \* 8`bit (unknown type)"
      fi
    ],[],[])
  fi
  i_cv_typeof_$1=$result/$visible
  ])

  typeof_$1=`echo $i_cv_typeof_$1 | sed s,/.*$,,`
  visible=`echo $i_cv_typeof_$1 | sed s,^.*/,,`
  AC_MSG_RESULT($visible)
])

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
    uofft_fmt="u"
    if test "$have_uoff_t" != "yes"; then
      AC_DEFINE(UOFF_T_INT,, [Define if off_t is int])
    fi
    offt_bits=`expr 8 \* $ac_cv_sizeof_int`
    ;;
  long)
    offt_max=LONG_MAX
    uofft_fmt="lu"
    if test "$have_uoff_t" != "yes"; then
      AC_DEFINE(UOFF_T_LONG,, [Define if off_t is long])
    fi
    offt_bits=`expr 8 \* $ac_cv_sizeof_long`
    ;;
  "long long")
    offt_max=LLONG_MAX
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

dnl * Do we have struct dirent->d_type
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
  #include <dirent.h>
]], [[
  struct dirent d;
  d.d_type = DT_DIR;
]])],[
  AC_DEFINE(HAVE_DIRENT_D_TYPE,, [Define if you have struct dirent->d_type])
],[])

dnl * Do we have OFF_T_MAX?
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
  #include <limits.h>
  #include <sys/types.h>
]], [[
  off_t i = OFF_T_MAX;
]])],[
  :
],[
  AC_DEFINE_UNQUOTED(OFF_T_MAX, $offt_max, [Maximum value of off_t])
])

AC_DEFINE_UNQUOTED(PRIuUOFF_T, "$uofft_fmt", [printf() format for uoff_t])

dnl * make sure size_t isn't signed. we'd probably work fine with it, but
dnl * it's more likely vulnerable to buffer overflows. Anyway, C99 specifies
dnl * that it's unsigned and only some old systems define it as signed.
AC_CACHE_CHECK([whether size_t is signed],i_cv_signed_size_t,[
  AC_RUN_IFELSE([AC_LANG_SOURCE([[
    #include <sys/types.h>
    #include <stdlib.h>
    int main() {
      /* return 0 if we're signed */
      exit((size_t)(int)-1 <= 0 ? 0 : 1);
    }
  ]])],[
    i_cv_signed_size_t=yes

    echo
    echo "Your system's size_t is a signed integer, Dovecot isn't designed to"
    echo "support it. It probably works just fine, but it's less resistant to"
    echo "buffer overflows. If you're not worried about this and still want to"
    echo "compile Dovecot, set ignore_signed_size=1 environment."
  
    if test "$ignore_signed_size" = ""; then
      AC_MSG_ERROR([aborting])
    fi
    echo "..ignoring as requested.."
  ],[
    i_cv_signed_size_t=no
  ],[])
])
dnl Note: we check size_t rather than ssize_t here, because on OSX 10.2
dnl ssize_t = int and size_t = unsigned long. We're mostly concerned about
dnl printf format here, so check the size_t one.
AC_TYPEOF(size_t, unsigned-int unsigned-long unsigned-long-long)
case "$typeof_size_t" in
  "unsigned long")
    ssizet_max=LONG_MAX
    sizet_fmt="lu"
    ;;
  "unsigned long long")
    ssizet_max=LLONG_MAX
    sizet_fmt="llu"
    ;;
  *)
    dnl older systems didn't have ssize_t, default to int
    ssizet_max=INT_MAX
    sizet_fmt="u"

    if test "$typeof_size_t" = ""; then
      AC_DEFINE(size_t, unsigned int, [Define to 'unsigned int' if you don't have it])
      AC_DEFINE(ssize_t, int, [Define to 'int' if you don't have it])
    fi
    ;;
esac

AC_DEFINE_UNQUOTED(SSIZE_T_MAX, $ssizet_max, [Maximum value of ssize_t])
AC_DEFINE_UNQUOTED(PRIuSIZE_T, "$sizet_fmt", [printf() format for size_t])

AC_DEFUN([AC_CHECKTYPE2], [
  AC_MSG_CHECKING([for $1])
  AC_CACHE_VAL(i_cv_type_$1,
  [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
  #include <sys/types.h>
  $2]], [[$1 t;]])],[i_cv_type_$1=yes],[i_cv_type_$1=no])])
  AC_MSG_RESULT($i_cv_type_$1)
])
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
AC_MSG_CHECKING([for /dev/urandom])
if test -c /dev/urandom || test -s /dev/urandom; then
  AC_MSG_RESULT(yes)
  AC_DEFINE(DEV_URANDOM_PATH, "/dev/urandom", [Path to /dev/urandom])
  have_random_source=yes
else
  AC_MSG_RESULT(no)
fi

if test "$have_random_source" != "yes"; then
  AC_CHECK_HEADER(openssl/rand.h, [
    AC_DEFINE(HAVE_OPENSSL_RAND_H,, [Define if you have openssl/rand.h])
    LIBS="$LIBS -lcrypto"
  ])
fi

dnl * do we have tm_gmtoff
AC_MSG_CHECKING([for tm_gmtoff])
AC_CACHE_VAL(i_cv_field_tm_gmtoff,
[AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <time.h>]],
[[struct tm *tm; return tm->tm_gmtoff;]])],
[i_cv_field_tm_gmtoff=yes],
[i_cv_field_tm_gmtoff=no])])
if test $i_cv_field_tm_gmtoff = yes; then
	AC_DEFINE(HAVE_TM_GMTOFF,, [Define if you have struct tm->tm_gmtoff])
fi
AC_MSG_RESULT($i_cv_field_tm_gmtoff)

dnl * how large time_t values does gmtime() accept?
AC_CACHE_CHECK([how large time_t values gmtime() accepts],i_cv_gmtime_max_time_t,[
  AC_RUN_IFELSE([AC_LANG_SOURCE([[
    #include <stdio.h>
    #include <time.h>
    int main() {
      FILE *f;
      int bits;
  
      for (bits = 1; bits < sizeof(time_t)*8; bits++) {
	time_t t = ((time_t)1 << bits) - 1;
	if (gmtime(&t) == NULL) {
	  bits--;
	  break;
	}
      }
      if (bits > 40) {
	/* Solaris 9 breaks after 55 bits. Perhaps other systems break earlier.
	   Let's just do the same as Cyrus folks and limit it to 40 bits. */
	bits = 40;
      }
  
      f = fopen("conftest.temp", "w");
      if (f == NULL) {
	perror("fopen()");
	return 1;
      }
      fprintf(f, "%d", bits);
      fclose(f);
      return 0;
    }
  ]])],[
    i_cv_gmtime_max_time_t=`cat conftest.temp`
    rm -f conftest.temp
  ], [
    printf "check failed, assuming "
    i_cv_gmtime_max_time_t=31
  ],[])
])
AC_DEFINE_UNQUOTED(TIME_T_MAX_BITS, $i_cv_gmtime_max_time_t, [max. time_t bits gmtime() can handle])

AC_CACHE_CHECK([whether time_t is signed],i_cv_signed_time_t,[
  AC_RUN_IFELSE([AC_LANG_SOURCE([[
    #include <sys/types.h>
    #include <stdlib.h>
    int main() {
      /* return 0 if we're signed */
      exit((time_t)(int)-1 <= 0 ? 0 : 1);
    }
  ]])],[
    i_cv_signed_time_t=yes
  ], [
    i_cv_signed_time_t=no
  ])
])
if test $i_cv_signed_time_t = yes; then
  AC_DEFINE(TIME_T_SIGNED,, [Define if your time_t is signed])
fi

AC_CACHE_CHECK([if we can use C99 static in array sizes],i_cv_c99_static_arrays,[
  AC_TRY_COMPILE([
    void foo(unsigned char [static 20]);
  ], [
  ], [
    i_cv_c99_static_arrays=yes
  ], [
    i_cv_c99_static_arrays=no
  ])
])

if test $i_cv_c99_static_arrays = yes; then
  static_value=static
else
  static_value=
fi
AC_DEFINE_UNQUOTED(STATIC_ARRAY, $static_value, [C99 static array])

dnl Our implementation of AC_C_FLEXIBLE_ARRAY_MEMBER.
dnl Use it until autoconf 2.61+ becomes more widely used
AC_CACHE_CHECK([if we can use C99-like flexible array members],i_cv_c99_flex_arrays,[
  AC_TRY_COMPILE([
    struct foo {
      int x;
      char y[];
    };
  ], [
    struct foo foo;
  ], [
    i_cv_c99_flex_arrays=yes
  ], [
    i_cv_c99_flex_arrays=no
  ])
])

if test $i_cv_c99_flex_arrays = yes; then
  flexible_value=
else
  flexible_value=1
fi
AC_DEFINE_UNQUOTED(FLEXIBLE_ARRAY_MEMBER, $flexible_value, [How to define flexible array members in structs])

dnl * do we have struct iovec
AC_MSG_CHECKING([for struct iovec])
AC_CACHE_VAL(i_cv_struct_iovec,
[AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>]],
[[struct iovec *iovec;]])],
[i_cv_struct_iovec=yes],
[i_cv_struct_iovec=no])])

if test $i_cv_struct_iovec = yes; then
	AC_DEFINE(HAVE_STRUCT_IOVEC,, [Define if you have struct iovec])
fi
AC_MSG_RESULT($i_cv_struct_iovec)

dnl * is dev_t an integer or something else?
AC_CACHE_CHECK([whether dev_t is struct],i_cv_dev_t_struct,[
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #include <sys/types.h>
    struct test { dev_t a; };
    static struct test t = { 0 };
  ]],
  [[ ]])], [
    i_cv_dev_t_struct=no
  ],[
    i_cv_dev_t_struct=yes
  ])
])
if test $i_cv_dev_t_struct = yes; then
  AC_DEFINE(DEV_T_STRUCT,, [Define if your dev_t is a structure instead of integer type])
fi

dnl * Do we have RLIMIT_AS?
AC_CACHE_CHECK([whether RLIMIT_AS exists],i_cv_have_rlimit_as,[
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #include <sys/types.h>
    #include <sys/time.h>
    #include <sys/resource.h>
  ]], [[
    struct rlimit r;
    getrlimit(RLIMIT_AS, &r);
  ]])],[
    i_cv_have_rlimit_as=yes
  ], [
    i_cv_have_rlimit_as=no
  ])
])

if test $i_cv_have_rlimit_as = yes; then
  AC_DEFINE(HAVE_RLIMIT_AS,, [Define if you have RLIMIT_AS for setrlimit()])
fi

dnl * Do we have RLIMIT_NPROC?
AC_CACHE_CHECK([whether RLIMIT_NPROC exists],i_cv_have_rlimit_nproc,[
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #include <sys/types.h>
    #include <sys/time.h>
    #include <sys/resource.h>
  ]], [[
    struct rlimit r;
    getrlimit(RLIMIT_NPROC, &r);
  ]])],[
    i_cv_have_rlimit_nproc=yes
  ],[
    i_cv_have_rlimit_nproc=no
  ])
])

if test $i_cv_have_rlimit_nproc = yes; then
  AC_DEFINE(HAVE_RLIMIT_NPROC,, [Define if you have RLIMIT_NPROC for setrlimit()])
fi

dnl * Do we have RLIMIT_CORE?
AC_CACHE_CHECK([whether RLIMIT_CORE exists],i_cv_have_rlimit_core,[
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #include <sys/types.h>
    #include <sys/time.h>
    #include <sys/resource.h>
  ]], [[
    struct rlimit r;
    getrlimit(RLIMIT_CORE, &r);
  ]])],[
    i_cv_have_rlimit_core=yes
  ],[
    i_cv_have_rlimit_core=no
  ])
])

if test $i_cv_have_rlimit_core = yes; then
  AC_DEFINE(HAVE_RLIMIT_CORE,, [Define if you have RLIMIT_CORE for getrlimit()])
fi

AC_CACHE_CHECK([whether PR_SET_DUMPABLE exists],i_cv_have_pr_set_dumpable,[
  AC_TRY_LINK([
    #include <sys/prctl.h>
  ], [
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
  ], [
    i_cv_have_pr_set_dumpable=yes
  ], [
    i_cv_have_pr_set_dumpable=no
  ])
])
if test $i_cv_have_pr_set_dumpable = yes; then
  AC_DEFINE(HAVE_PR_SET_DUMPABLE,, [Define if you have prctl(PR_SET_DUMPABLE)])
fi

dnl * Linux compatible mremap()
AC_CACHE_CHECK([Linux compatible mremap()],i_cv_have_linux_mremap,[
  AC_TRY_LINK([
    #include <unistd.h>
    #define __USE_GNU
    #include <sys/mman.h>
  ], [
    mremap(0, 0, 0, MREMAP_MAYMOVE);
  ], [
    i_cv_have_linux_mremap=yes
  ], [
    i_cv_have_linux_mremap=no
  ])
])
if test $i_cv_have_linux_mremap = yes; then
  AC_DEFINE(HAVE_LINUX_MREMAP,, [Define if you have Linux-compatible mremap()])
fi

dnl * If mmap() plays nicely with write()
AC_CACHE_CHECK([whether shared mmaps get updated by write()s],i_cv_mmap_plays_with_write,[
  AC_TRY_RUN([
    #include <stdio.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/mman.h>
    #include <string.h>
    int main() {
      /* return 0 if we're signed */
      int f = open("conftest.mmap", O_RDWR|O_CREAT|O_TRUNC, 0600);
      void *mem;
      if (f == -1) {
	perror("open()");
	return 1;
      }
      unlink("conftest.mmap");
  
      write(f, "1", 2);
      mem = mmap(NULL, 2, PROT_READ|PROT_WRITE, MAP_SHARED, f, 0);
      if (mem == MAP_FAILED) {
	perror("mmap()");
	return 1;
      }
      strcpy(mem, "2");
      msync(mem, 2, MS_SYNC);
      lseek(f, 0, SEEK_SET);
      write(f, "3", 2);
    
      return strcmp(mem, "3") == 0 ? 0 : 1;
    }
  ], [
    i_cv_mmap_plays_with_write=yes
  ], [
    i_cv_mmap_plays_with_write=no
  ])
])
if test $i_cv_mmap_plays_with_write = no; then
  AC_DEFINE(MMAP_CONFLICTS_WRITE,, [Define if shared mmaps don't get updated by write()s])
fi

dnl * see if fd passing works
AC_CACHE_CHECK([whether fd passing works],i_cv_fd_passing,[
  for i in 1 2; do
    old_cflags="$CFLAGS"
    CFLAGS="$CFLAGS -I$srcdir/src/lib $srcdir/src/lib/fdpass.c"
    if test $i = 2; then
      CFLAGS="$CFLAGS -DBUGGY_CMSG_MACROS"
    fi
  
    AC_TRY_RUN([
      #include <sys/types.h>
      #include <sys/socket.h>
      #include <sys/wait.h>
      #include <sys/stat.h>
      #include <unistd.h>
      #include <fcntl.h>
      #include "fdpass.h"
      
      int nopen(void)
      {
	      int i, n;
	      struct stat sb;
	      for (i = n = 0; i < 256; i++)
		  if (fstat(i, &sb) == 0) n++;
	      return n;
      }
      int main(void)
      {
	      int fd[2], send_fd, recv_fd, status, n1, n2;
	      struct stat st, st2;
	      char data;
      
	      send_fd = creat("conftest.fdpass", 0600);
	      if (send_fd == -1) return 2;
	      unlink("conftest.fdpass");
	      if (fstat(send_fd, &st) < 0) return 2;
	      if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) return 2;
	      n1 = nopen();
      
	      switch (fork()) {
	      case -1:
		      return 2;
	      case 0:
		      alarm(1);
		      if (fd_send(fd[0], send_fd, &data, 1) != 1) return 2;
		      return 0;
	      default:
		      alarm(2);
		      if (wait(&status) == -1)
			return 2;
		      if (status != 0)
			return status;
		      if (fd_read(fd[1], &data, 1, &recv_fd) != 1) return 1;
		      if (fstat(recv_fd, &st2) < 0) return 2;
		      /* nopen check is for making sure that only a single fd
		         was received */
		      n2 = nopen();
		      return st.st_ino == st2.st_ino && n2 == n1 + 1 ? 0 : 1;
	      }
      }
    ], [
      CFLAGS=$old_cflags
      if test $i = 2; then
	i_cv_fd_passing=buggy_cmsg_macros
      else
        i_cv_fd_passing=yes
      fi
      break
    ], [
      dnl no, try with BUGGY_CMSG_MACROS
      CFLAGS=$old_cflags
      i_cv_fd_passing=no
    ])
  done
]);

case "$host_os" in
darwin[[1-9]].*)
	if test "$i_cv_fd_passing" = "yes"; then
		i_cv_fd_passing=buggy_cmsg_macros
	fi
	;;
esac

if test $i_cv_fd_passing = buggy_cmsg_macros; then
  AC_DEFINE(BUGGY_CMSG_MACROS,, [Define if you have buggy CMSG macros])
fi
if test $i_cv_fd_passing = no; then
  AC_ERROR([fd passing is required for Dovecot to work])
fi

dnl * Solaris compatible sendfile()
AC_CHECK_LIB(sendfile, sendfile, [
  LIBS="$LIBS -lsendfile"
  AC_DEFINE(HAVE_SOLARIS_SENDFILE,, [Define if you have Solaris-compatible sendfile()])
], [
  dnl * Linux compatible sendfile() - don't check if Solaris one was found.
  dnl * This seems to pass with Solaris for some reason..
  AC_CACHE_CHECK([Linux compatible sendfile()],i_cv_have_linux_sendfile,[
    AC_TRY_LINK([
      #undef _FILE_OFFSET_BITS
      #include <sys/types.h>
      #include <sys/socket.h>
      #include <sys/sendfile.h>
    ], [
      sendfile(0, 0, (void *) 0, 0);
    ], [
      i_cv_have_linux_sendfile=yes
    ], [
      i_cv_have_linux_sendfile=no
    ])
  ])
  if test $i_cv_have_linux_sendfile = yes; then
    AC_DEFINE(HAVE_LINUX_SENDFILE,, [Define if you have Linux-compatible sendfile()])
  fi

  dnl * FreeBSD compatible sendfile()
  AC_CACHE_CHECK([FreeBSD compatible sendfile()],i_cv_have_freebsd_sendfile,[
    AC_TRY_LINK([
      #include <sys/types.h>
      #include <sys/socket.h>
      #include <sys/uio.h>
    ], [
      struct sf_hdtr hdtr;
      sendfile(0, 0, 0, 0, &hdtr, (void *) 0, 0);
    ], [
      i_cv_have_freebsd_sendfile=yes
    ], [
      i_cv_have_freebsd_sendfile=no
    ])
  ])
  if test $i_cv_have_freebsd_sendfile = yes; then
    AC_DEFINE(HAVE_FREEBSD_SENDFILE,, [Define if you have FreeBSD-compatible sendfile()])
  fi
])

AC_CACHE_CHECK([if unsetenv returns int],i_cv_unsetenv_ret_int,[
  AC_TRY_COMPILE([
    #include <stdlib.h>
  ], [
    if (unsetenv("env") < 0) ;
  ], [
    i_cv_unsetenv_ret_int=yes
  ], [
    i_cv_unsetenv_ret_int=no
  ])
])
if test $i_cv_unsetenv_ret_int = yes; then
  AC_DEFINE(UNSETENV_RET_INT,, [Define if unsetenv() returns int])
fi

dnl * Check for crypt() if unistd.h compiles with _XOPEN_SOURCE + _XPG6
dnl * Add other macros there too "just in case".
AC_CACHE_CHECK([if we should use _XPG6 macro for crypt()],i_cv_use_xpg6_crypt,[
  AC_TRY_COMPILE([
    #define _XOPEN_SOURCE 4
    #define _XOPEN_SOURCE_EXTENDED 1
    #define _XOPEN_VERSION 4
    #define _XPG4_2
    #define _XPG6
    #include <unistd.h>
  ], [
    crypt("a", "b");
  ], [
    i_cv_use_xpg6_crypt=yes
  ], [
    i_cv_use_xpg6_crypt=no
  ])
])
if test $i_cv_use_xpg6_crypt = yes; then
  AC_DEFINE(CRYPT_USE_XPG6,, [Define if _XPG6 macro is needed for crypt()])
fi

AC_CACHE_CHECK([if struct stat has st_?tim timespec fields],i_cv_have_st_tim_timespec,[
  AC_TRY_COMPILE([
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <unistd.h>
  ], [
    struct stat st;
    unsigned long x = st.st_mtim.tv_nsec;
  
    return 0;
  ], [
    i_cv_have_st_tim_timespec=yes
  ], [
    i_cv_have_st_tim_timespec=no
  ])
])
if test $i_cv_have_st_tim_timespec = yes; then
  AC_DEFINE(HAVE_STAT_XTIM,, [Define if you have st_?tim timespec fields in struct stat])
fi

AC_CACHE_CHECK([if struct stat has st_?timespec fields],i_cv_have_st_timespec,[
  AC_TRY_COMPILE([
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <unistd.h>
  ], [
    struct stat st;
    unsigned long x = st.st_mtimespec.tv_nsec;
  
    return 0;
  ], [
    i_cv_have_st_timespec=yes
  ], [
    i_cv_have_st_timespec=no
  ])
])
if test $i_cv_have_st_timespec = yes; then
  AC_DEFINE(HAVE_STAT_XTIMESPEC,, [Define if you have st_?timespec fields in struct stat])
fi

dnl * Check if statvfs() can be used to find out block device for files
AC_CACHE_CHECK([if statvfs.f_mntfromname exists],i_cv_have_statvfs_f_mntfromname,[
  AC_TRY_COMPILE([
    #include <sys/types.h>
    #include <sys/statvfs.h>
  ], [
    struct statvfs buf;
    char *p = buf.f_mntfromname;
  
    statvfs(".", &buf);
  ], [
    i_cv_have_statvfs_f_mntfromname=yes
  ], [
    i_cv_have_statvfs_f_mntfromname=no
  ])
])
if test $i_cv_have_statvfs_f_mntfromname = yes; then
  AC_DEFINE(HAVE_STATVFS_MNTFROMNAME,, [Define if you have statvfs.f_mntfromname])
fi

dnl * Check if statfs() can be used to find out block device for files
AC_CACHE_CHECK([if statfs.f_mntfromname exists],i_cv_have_statfs_f_mntfromname,[
  AC_TRY_COMPILE([
    #include <sys/param.h>
    #include <sys/mount.h>
  ], [
    struct statfs buf;
    char *p = buf.f_mntfromname;
  
    statfs(".", &buf);
  ], [
    i_cv_have_statfs_f_mntfromname=yes
  ], [
    i_cv_have_statfs_f_mntfromname=no
  ])
])
if test $i_cv_have_statfs_f_mntfromname = yes; then
  AC_DEFINE(HAVE_STATFS_MNTFROMNAME,, [Define if you have statfs.f_mntfromname])
fi

dnl * Check if we have struct dqblk.dqb_curblocks
AC_CACHE_CHECK([if struct dqblk.dqb_curblocks exists],i_cv_have_dqblk_dqb_curblocks,[
  AC_TRY_COMPILE([
    #include <sys/types.h>
    #include "$srcdir/src/plugins/quota/quota-fs.h"
  ], [
    struct dqblk dqblk;
    unsigned int x = dqblk.dqb_curblocks;
  ], [
    i_cv_have_dqblk_dqb_curblocks=yes
  ], [
    i_cv_have_dqblk_dqb_curblocks=no
  ])
])
if test $i_cv_have_dqblk_dqb_curblocks = yes; then
  AC_DEFINE(HAVE_STRUCT_DQBLK_CURBLOCKS,, [Define if struct sqblk.dqb_curblocks exists])
fi

dnl * Check if we have struct dqblk.dqb_curspace
AC_CACHE_CHECK([if struct dqblk.dqb_curspace exists],i_cv_have_dqblk_dqb_curspace,[
  AC_TRY_COMPILE([
    #include <sys/types.h>
    #include "$srcdir/src/plugins/quota/quota-fs.h"
  ], [
    struct dqblk dqblk;
    unsigned int x = dqblk.dqb_curspace;
  ], [
    i_cv_have_dqblk_dqb_curspace=yes
  ], [
    i_cv_have_dqblk_dqb_curspace=no
  ])
])
if test $i_cv_have_dqblk_dqb_curspace = yes; then
  AC_DEFINE(HAVE_STRUCT_DQBLK_CURSPACE,, [Define if struct sqblk.dqb_curspace exists])
fi

dnl * Check if we have Q_QUOTACTL ioctl (Solaris)
AC_CACHE_CHECK([if Q_QUOTACTL ioctl exists],i_cv_have_ioctl_q_quotactl,[
  AC_TRY_COMPILE([
    #include <sys/types.h>
    #include <sys/fs/ufs_quota.h>
  ], [
    struct quotctl ctl;
    ioctl(0, Q_QUOTACTL, &ctl);
  ], [
    i_cv_have_ioctl_q_quotactl=yes
  ], [
    i_cv_have_ioctl_q_quotactl=no
  ])
])

if test $i_cv_have_ioctl_q_quotactl = yes; then
  AC_DEFINE(HAVE_Q_QUOTACTL,, [Define if Q_QUOTACTL exists])
fi

dnl ***
dnl *** C99 vsnprintf()?
dnl ***

AC_CACHE_CHECK([for C99 vsnprintf()],i_cv_c99_vsnprintf,[
  AC_RUN_IFELSE([AC_LANG_SOURCE([[
  #include <stdio.h>
  #include <stdarg.h>
  static int f(const char *fmt, ...) {
    va_list args;
    char buf[13];
    int ret;

    va_start(args, fmt);
    ret = vsnprintf(buf, 11, fmt, args) != 12 || buf[11-1] != '\0';
    va_end(args);
    return ret;
  }
  int main() {
    return f("hello %s%d", "world", 1);
  }]])],
  [i_cv_c99_vsnprintf=yes],
  [i_cv_c99_vsnprintf=no])
])
if test $i_cv_c99_vsnprintf = no; then
  AC_DEFINE(HAVE_OLD_VSNPRINTF,, [Define if you don't have C99 compatible vsnprintf() call])
fi

dnl ***
dnl *** va_copy checks (from GLIB)
dnl ***

AC_CACHE_CHECK([for an implementation of va_copy()],lib_cv_va_copy,[
	AC_RUN_IFELSE([AC_LANG_SOURCE([[
	#include <stdarg.h>
	#include <stdlib.h>
	void f (int i, ...) {
	va_list args1, args2;
	va_start (args1, i);
	va_copy (args2, args1);
	if (va_arg (args2, int) != 42 || va_arg (args1, int) != 42)
	  exit (1);
	va_end (args1); va_end (args2);
	}
	int main() {
	  f (0, 42);
	  return 0;
	}]])],
	[lib_cv_va_copy=yes],
	[lib_cv_va_copy=no],[])
])
AC_CACHE_CHECK([for an implementation of __va_copy()],lib_cv___va_copy,[
	AC_RUN_IFELSE([AC_LANG_SOURCE([[
	#include <stdarg.h>
	#include <stdlib.h>
	void f (int i, ...) {
	va_list args1, args2;
	va_start (args1, i);
	__va_copy (args2, args1);
	if (va_arg (args2, int) != 42 || va_arg (args1, int) != 42)
	  exit (1);
	va_end (args1); va_end (args2);
	}
	int main() {
	  f (0, 42);
	  return 0;
	}]])],
	[lib_cv___va_copy=yes],
	[lib_cv___va_copy=no],[])
])

if test "x$lib_cv_va_copy" = "xyes"; then
  va_copy_func=va_copy
else if test "x$lib_cv___va_copy" = "xyes"; then
  va_copy_func=__va_copy
fi
fi

if test -n "$va_copy_func"; then
  AC_DEFINE_UNQUOTED(VA_COPY,$va_copy_func,[A 'va_copy' style function])
fi

AC_CACHE_CHECK([whether va_lists can be copied by value],lib_cv_va_val_copy,[
	AC_RUN_IFELSE([AC_LANG_SOURCE([[
	#include <stdarg.h>
	#include <stdlib.h>
	void f (int i, ...) {
	va_list args1, args2;
	va_start (args1, i);
	args2 = args1;
	if (va_arg (args2, int) != 42 || va_arg (args1, int) != 42)
	  exit (1);
	va_end (args1); va_end (args2);
	}
	int main() {
	  f (0, 42);
	  return 0;
	}]])],
	[lib_cv_va_val_copy=yes],
	[lib_cv_va_val_copy=no],[])
])

if test "x$lib_cv_va_val_copy" = "xno"; then
  AC_DEFINE(VA_COPY_AS_ARRAY,1, ['va_lists' cannot be copied as values])
fi

dnl * dynamic modules?
have_modules=no
AC_CHECK_FUNC(dlopen, [
  have_modules=yes
  MODULE_LIBS="-export-dynamic"
], [
  AC_CHECK_LIB(dl, dlopen, [
    have_modules=yes
    MODULE_LIBS="-export-dynamic -ldl"
    DLLIB=-ldl
  ])
])

dnl **
dnl ** AIX mntctl
dnl **

if test $ac_cv_header_sys_vmount_h = yes; then
  AC_MSG_CHECKING([for reasonable mntctl buffer size])
  AC_RUN_IFELSE([AC_LANG_SOURCE([[
    #include <stdio.h>
    #include <stdlib.h>
    #include <sys/vmount.h>
    int main() {
      int size,count; char *m;
      FILE *f=fopen("conftestval", "w");
      if (!f) exit(1);
      if ((count=mntctl(MCTL_QUERY,sizeof(size),&size))!=0 || !(m=malloc(size)) ||
          (count=mntctl(MCTL_QUERY,size,m))<=0) exit(1);
        fprintf(f, "%d\n",(size * (count + 5))/count & ~1); /* 5 mounts more */
        exit(0);
    }
  ]])],[
    size=`cat conftestval`
    rm -f conftestval
    AC_DEFINE_UNQUOTED(STATIC_MTAB_SIZE,$size, [reasonable mntctl buffer size])
    AC_MSG_RESULT($size)
  ],[
    AC_MSG_RESULT(default)
  ])
fi


dnl **
dnl ** SSL
dnl **

have_ssl=no
build_dcrypt_openssl=no

if test $want_openssl != no && test $have_ssl = no; then
  if test "$PKG_CONFIG" != "" && $PKG_CONFIG --exists openssl 2>/dev/null; then
    PKG_CHECK_MODULES(SSL, openssl)
    CFLAGS="$CFLAGS $SSL_CFLAGS"
    have_openssl=yes
  else
    # openssl 0.9.8 wants -ldl and it's required if there's only .a lib
    AC_CHECK_LIB(ssl, SSL_read, [
      AC_CHECK_HEADERS(openssl/ssl.h openssl/err.h, [
        SSL_LIBS="-lssl -lcrypto $DLLIB"
        AC_SUBST(SSL_LIBS)
	have_openssl=yes
      ], [
	if test $want_openssl = yes; then
	  AC_ERROR([Can't build with OpenSSL: openssl/ssl.h or openssl/err.h not found])
	fi
      ])
    ], [
      if test $want_openssl = yes; then
        AC_ERROR([Can't build with OpenSSL: libssl not found])
      fi
    ], -lcrypto $DLLIB)
  fi
  if test "$have_openssl" = "yes"; then
    AC_DEFINE(HAVE_OPENSSL,, [Build with OpenSSL support])
    have_ssl="yes (OpenSSL)"
    build_dcrypt_openssl="no"

    AC_MSG_CHECKING([if OpenSSL version is 1.0.2 or better])

    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      #include <openssl/opensslv.h>
      #if OPENSSL_VERSION_NUMBER < 0x10002000L
      #error "fail-compile"
      #endif]], [[ return 0; ]])], [ssl_version_ge_102=true], [ssl_version_ge_102=false])
    AC_MSG_RESULT([$ssl_version_ge_102])

    # SSL_clear_options introduced in openssl 0.9.8m but may be backported to
    # older versions in "enterprise" OS releases; originally implemented as a
    # macro but as a function in more recent openssl versions
    AC_CACHE_CHECK([whether SSL_clear_options exists],i_cv_have_ssl_clear_options,[
      old_LIBS=$LIBS
      LIBS="$LIBS -lssl"
      AC_TRY_LINK([
	#include <openssl/ssl.h>
      ], [
	SSL *ssl;
	long options;
	SSL_clear_options(ssl, options);
      ], [
	i_cv_have_ssl_clear_options=yes
      ], [
	i_cv_have_ssl_clear_options=no
      ])
      LIBS=$old_LIBS
    ])
    if test $i_cv_have_ssl_clear_options = yes; then
      AC_DEFINE(HAVE_SSL_CLEAR_OPTIONS,, [Define if you have SSL_clear_options])
    fi

    # New style mem functions? Should be in v1.1+
    AC_CACHE_CHECK([whether CRYPTO_set_mem_functions has new style parameters],i_cv_have_ssl_new_mem_funcs,[
      old_LIBS=$LIBS
      LIBS="$LIBS -lssl"
      AC_TRY_LINK([
	#include <openssl/ssl.h>
	int CRYPTO_set_mem_functions(
		void *(*m) (size_t, const char *, int),
		void *(*r) (void *, size_t, const char *, int),
		void (*f) (void *, const char *, int));
      ], [
      ], [
	i_cv_have_ssl_new_mem_funcs=yes
      ], [
	i_cv_have_ssl_new_mem_funcs=no
      ])
      LIBS=$old_LIBS
    ])
    if test $i_cv_have_ssl_new_mem_funcs = yes; then
      AC_DEFINE(HAVE_SSL_NEW_MEM_FUNCS,, [Define if CRYPTO_set_mem_functions has new style parameters])
    fi

    # SSL_CTX_set_min_proto_version is also a macro so AC_CHECK_LIB fails here.
    AC_CACHE_CHECK([whether SSL_CTX_set_min_proto_version exists],i_cv_have_ssl_ctx_set_min_proto_version,[
      old_LIBS=$LIBS
      LIBS="$LIBS -lssl"
      AC_TRY_LINK([
        #include <openssl/ssl.h>
      ], [
        SSL_CTX_set_min_proto_version((void*)0, 0);
      ], [
        i_cv_have_ssl_ctx_set_min_proto_version=yes
      ], [
        i_cv_have_ssl_ctx_set_min_proto_version=no
      ])
      LIBS=$old_LIBS
    ])
    if test $i_cv_have_ssl_ctx_set_min_proto_version = yes; then
      AC_DEFINE(HAVE_SSL_CTX_SET_MIN_PROTO_VERSION,, [Define if you have SSL_CTX_set_min_proto_version])
    fi

    AC_CHECK_LIB(ssl, ERR_remove_thread_state, [
      AC_DEFINE(HAVE_OPENSSL_ERR_REMOVE_THREAD_STATE,, [Define if you have ERR_remove_thread_state])
    ],, $SSL_LIBS)
    AC_CHECK_LIB(ssl, OPENSSL_thread_stop, [
      AC_DEFINE(HAVE_OPENSSL_AUTO_THREAD_DEINIT,, [Define if OpenSSL performs thread cleanup automatically])
    ],, $SSL_LIBS)
    AC_CHECK_LIB(ssl, OPENSSL_cleanup, [
      AC_DEFINE(HAVE_OPENSSL_CLEANUP,, [OpenSSL supports OPENSSL_cleanup()])
    ],, $SSL_LIBS)
    AC_CHECK_LIB(ssl, SSL_get_current_compression, [
      AC_DEFINE(HAVE_SSL_COMPRESSION,, [Build with OpenSSL compression])
    ],, $SSL_LIBS)
    AC_CHECK_LIB(ssl, SSL_get_servername, [
      AC_DEFINE(HAVE_SSL_GET_SERVERNAME,, [Build with TLS hostname support])
    ],, $SSL_LIBS)
    AC_CHECK_LIB(ssl, SSL_COMP_free_compression_methods, [
      AC_DEFINE(HAVE_SSL_COMP_FREE_COMPRESSION_METHODS,, [Build with SSL_COMP_free_compression_methods() support])
    ],, $SSL_LIBS)
    AC_CHECK_LIB(ssl, RSA_generate_key_ex, [
      AC_DEFINE(HAVE_RSA_GENERATE_KEY_EX,, [Build with RSA_generate_key_ex() support])
    ],, $SSL_LIBS)
    AC_CHECK_LIB(ssl, ASN1_STRING_get0_data, [
      AC_DEFINE(HAVE_ASN1_STRING_GET0_DATA,, [Build with ASN1_STRING_get0_data() support])
    ],, $SSL_LIBS)
    AC_CHECK_LIB(ssl, HMAC_CTX_new, [
      AC_DEFINE(HAVE_HMAC_CTX_NEW,, [Build with HMAC_CTX_new() support])
    ],, $SSL_LIBS)
    AC_CHECK_LIB(ssl, EVP_MD_CTX_new, [
      AC_DEFINE(HAVE_EVP_MD_CTX_NEW,, [Build with EVP_MD_CTX_new() support])
    ],, $SSL_LIBS)
    AC_CHECK_LIB(ssl, OBJ_length, [
      AC_DEFINE(HAVE_OBJ_LENGTH,, [Build with OBJ_length() support])
    ],, $SSL_LIBS)
    AC_CHECK_LIB(ssl, EVP_PKEY_get0_RSA, [
      AC_DEFINE(HAVE_EVP_PKEY_get0,, [Build with EVP_PKEY_get0_*() support])
    ],, $SSL_LIBS)
    AC_CHECK_LIB(ssl, [EVP_PKEY_CTX_new_id], [have_evp_pkey_ctx_new_id="yes"],, $SSL_LIBS)
    AC_CHECK_LIB(ssl, [EC_KEY_new], [have_ec_key_new="yes"],, $SSL_LIBS)
    if test "$have_evp_pkey_ctx_new_id" = "yes" && test "$have_ec_key_new" = "yes"; then
      build_dcrypt_openssl="yes"
    else
      AC_MSG_WARN([No ECC support in OpenSSL - not enabling dcrypt])
    fi
  fi
fi
AM_CONDITIONAL([SSL_VERSION_GE_102], [test x$ssl_version_ge_102 = xtrue])

AM_CONDITIONAL(BUILD_OPENSSL, test "$have_openssl" = "yes")
AM_CONDITIONAL(BUILD_DCRYPT_OPENSSL, test "$build_dcrypt_openssl" = "yes")

if test $want_gnutls != no && test $have_ssl = no; then
  AC_CHECK_LIB(gnutls, gnutls_global_init, [
    AC_CHECK_HEADER(gnutls/gnutls.h, [
      AC_DEFINE(HAVE_GNUTLS,, [Build with GNUTLS support])
      SSL_LIBS="-lgnutls -lgcrypt"
      AC_SUBST(SSL_LIBS)
      have_ssl="yes (GNUTLS)"
      have_gnutls=yes
    ], [
      if test $want_gnutls = yes; then
	AC_ERROR([Can't build with GNUTLS: gnutls/gnutls.h not found])
      fi
    ])
  ], [
    if test $want_gnutls = yes; then
      AC_ERROR([Can't build with GNUTLS: libgnutls not found])
    fi
  ], -lgcrypt)
fi

if test "$have_ssl" != "no"; then
	AC_DEFINE(HAVE_SSL,, [Build with SSL/TLS support])
fi

dnl **
dnl ** Garbage Collector
dnl ** 

if test $want_gc != no; then
  AC_CHECK_LIB(gc, GC_malloc, [
    AC_CHECK_HEADERS(gc/gc.h gc.h)
    AC_DEFINE(USE_GC,, [Define if you want to use Boehm GC])
    LIBS="$LIBS -lgc"
  ], [
    if test $want_gc = yes; then
      AC_ERROR([Can't build with GC: libgc not found])
    fi
  ])
fi

dnl **
dnl ** userdb and passdb checks
dnl **

userdb=""
passdb=""
not_userdb=""
not_passdb=""

passdb="$passdb static"
userdb="$userdb static"

if test $want_prefetch_userdb != no; then
        AC_DEFINE(USERDB_PREFETCH,, [Build with prefetch userdb support])
	userdb="$userdb prefetch"
else
	not_userdb="$not_userdb prefetch"
fi

if test $want_passwd != no; then
        AC_DEFINE(USERDB_PASSWD,, [Build with passwd support])
        AC_DEFINE(PASSDB_PASSWD,, [Build with passwd support])
	userdb="$userdb passwd"
	passdb="$passdb passwd"
else
	not_passdb="$not_passdb passwd"
	not_userdb="$not_userdb passwd"
fi

if test $want_passwd_file != no; then
        AC_DEFINE(USERDB_PASSWD_FILE,, [Build with passwd-file support])
        AC_DEFINE(PASSDB_PASSWD_FILE,, [Build with passwd-file support])
	userdb="$userdb passwd-file"
	passdb="$passdb passwd-file"
else
	not_passdb="$not_passdb passwd-file"
	not_userdb="$not_userdb passwd-file"
fi

have_shadow=no
if test $want_shadow != no; then
  AC_CHECK_FUNC(getspnam, [
    AC_CHECK_HEADER(shadow.h, [
      AC_DEFINE(PASSDB_SHADOW,, [Build with shadow support])
      have_shadow=yes
    ], [
      if test $want_shadow = yes; then
        AC_ERROR([Can't build with shadow support: shadow.h not found])
      fi
    ])
  ], [
    if test $want_shadow = yes; then
      AC_ERROR([Can't build with shadow support: getspnam() not found])
    fi
  ])
fi
if test $have_shadow = no; then
  not_passdb="$not_passdb shadow"
else
  passdb="$passdb shadow"
fi

if test $want_pam != no; then
	AC_CHECK_LIB(pam, pam_start, [
		have_pam=no
		AC_CHECK_HEADER(security/pam_appl.h, [
			AC_DEFINE(HAVE_SECURITY_PAM_APPL_H,,
				  [Define if you have security/pam_appl.h])
			have_pam=yes
		])

		AC_CHECK_HEADER(pam/pam_appl.h, [
			AC_DEFINE(HAVE_PAM_PAM_APPL_H,,
				  [Define if you have pam/pam_appl.h])
			have_pam=yes
		])
	], [
	  if test $want_pam = yes; then
	    AC_ERROR([Can't build with PAM support: libpam not found])
	  fi
	])
fi

if test "$have_pam" = "yes"; then
  AUTH_LIBS="$AUTH_LIBS -lpam"
  AC_DEFINE(PASSDB_PAM,, [Build with PAM support])
  passdb="$passdb pam"

  AC_CHECK_LIB(pam, pam_setcred, [
    AC_DEFINE(HAVE_PAM_SETCRED,, [Define if you have pam_setcred()])
  ])
elif test $want_pam = yes; then
  AC_ERROR([Can't build with PAM support: pam_appl.h not found])
else
  not_passdb="$not_passdb pam"
fi

if test $want_checkpassword != no; then
        AC_DEFINE(PASSDB_CHECKPASSWORD,, [Build with checkpassword passdb support])
        AC_DEFINE(USERDB_CHECKPASSWORD,, [Build with checkpassword userdb support])
	passdb="$passdb checkpassword"
	userdb="$userdb checkpassword"
else
	not_passdb="$not_passdb checkpassword"
	not_userdb="$not_userdb checkpassword"
fi

have_bsdauth=no
if test $want_bsdauth != no; then
	AC_CHECK_FUNC(auth_userokay, [
		AC_DEFINE(PASSDB_BSDAUTH,, [Build with BSD authentication support])
		have_bsdauth=yes
	], [
	  if test $want_bsdauth = yes; then
	    AC_ERROR([Can't build with BSD authentication support: auth_userokay() not found])
	  fi
	])
fi
if test $have_bsdauth = no; then
  not_passdb="$not_passdb bsdauth"
else
  passdb="$passdb bsdauth"
fi

have_gssapi=no
if test $want_gssapi != no; then
	AC_CHECK_PROG(KRB5CONFIG, krb5-config, krb5-config, NO)
	if test $KRB5CONFIG != NO; then
		if ! $KRB5CONFIG --version gssapi 2>/dev/null > /dev/null; then
		  # krb5-config doesn't support gssapi.
		  KRB5_LIBS="`$KRB5CONFIG --libs`"
		  KRB5_CFLAGS=`$KRB5CONFIG --cflags`
		  AC_CHECK_LIB(gss, gss_acquire_cred, [
		    # Solaris
		    KRB5_LIBS="$KRB5_LIBS -lgss"
		  ], [
		    # failed
		    KRB5_LIBS=
		  ], $KRB5_LIBS)
		else
		  KRB5_LIBS=`$KRB5CONFIG --libs gssapi`
		  KRB5_CFLAGS=`$KRB5CONFIG --cflags gssapi`
		fi
		if test "$KRB5_LIBS" != ""; then
			AC_SUBST(KRB5_LIBS)
			AC_SUBST(KRB5_CFLAGS)
			
			# Although krb5-config exists, all systems still don't
			# have gssapi.h
			old_CFLAGS=$CFLAGS
			CFLAGS="$CFLAGS $KRB5_CFLAGS"
			AC_CHECK_HEADER([gssapi/gssapi.h], [
				AC_DEFINE(HAVE_GSSAPI_GSSAPI_H,, [GSSAPI headers in gssapi/gssapi.h])
				have_gssapi=yes
			])
			AC_CHECK_HEADER([gssapi.h], [
				AC_DEFINE(HAVE_GSSAPI_H,, [GSSAPI headers in gssapi.h])
				have_gssapi=yes
			])
			if test $have_gssapi != no; then
				if test $want_gssapi = plugin; then
					have_gssapi=plugin
				fi
				AC_DEFINE(HAVE_GSSAPI,, [Build with GSSAPI support])
				AC_CHECK_HEADERS(gssapi/gssapi_ext.h gssapi_krb5.h gssapi/gssapi_krb5.h)
				AC_CHECK_LIB(gss, __gss_userok, [
					AC_DEFINE(HAVE___GSS_USEROK,,
						[Define if you have __gss_userok()])
					KRB5_LIBS="$KRB5_LIBS -lgss"
				],, $KRB5_LIBS)

				# MIT has a #define for Heimdal acceptor_identity, but it's way too
				# difficult to test for it..
				old_LIBS=$LIBS
				LIBS="$LIBS $KRB5_LIBS"
				AC_CHECK_FUNCS(gsskrb5_register_acceptor_identity krb5_gss_register_acceptor_identity)

				# does the kerberos library support SPNEGO?
				AC_CACHE_CHECK([whether GSSAPI supports SPNEGO],i_cv_gssapi_spnego,[
				  AC_TRY_RUN([
				    #ifdef HAVE_GSSAPI_H
				    #  include <gssapi.h>
				    #else
				    #  include <gssapi/gssapi.h>
				    #endif
				    #include <krb5.h>
				    #include <string.h>
				    int main(void) {
				      OM_uint32 minor_status;
				      gss_OID_set mech_set;
				      unsigned char spnego_oid[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };
				      unsigned int i;
    
				      gss_indicate_mechs(&minor_status, &mech_set);
				      for (i = 0; i < mech_set->count; i++) {
					if (mech_set->elements[i].length == 6 &&
					    memcmp(mech_set->elements[i].elements,
						   spnego_oid, 6) == 0)
					      return 0;
				      }
				      return 1;
				    }
				  ], [
				    i_cv_gssapi_spnego=yes
				  ], [
				    i_cv_gssapi_spnego=no
				  ])
				])
				if test "$i_cv_gssapi_spnego" = "yes"; then
				  AC_DEFINE(HAVE_GSSAPI_SPNEGO,, [GSSAPI supports SPNEGO])
				fi
				LIBS=$old_LIBS

				if test $want_gssapi != plugin; then
				  AUTH_LIBS="$AUTH_LIBS $KRB5_LIBS"
				  AUTH_CFLAGS="$AUTH_CFLAGS $KRB5_CFLAGS"
				  AC_DEFINE(BUILTIN_GSSAPI,, [GSSAPI support is built in])
				else
				  have_gssapi_plugin=yes
				fi
			else
			  if test $want_gssapi != auto; then
			    AC_ERROR([Can't build with GSSAPI support: gssapi.h not found])
			  fi
			fi
			CFLAGS=$old_CFLAGS
		fi
	else
	  if test $want_gssapi != auto; then
	    AC_ERROR([Can't build with GSSAPI support: krb5-config not found])
	  fi
	fi
fi
AM_CONDITIONAL(GSSAPI_PLUGIN, test "$have_gssapi_plugin" = "yes")

have_sia=no
if test $want_sia != no; then
	AC_CHECK_FUNC(sia_validate_user, [
		AC_DEFINE(PASSDB_SIA,, [Build with Tru64 SIA support])
		AUTH_LIBS="$AUTH_LIBS -depth_ring_search"
		have_sia=yes
	], [
	  if test $want_sia = yes; then
	    AC_ERROR([Can't build with SIA support: sia_validate_user() not found])
	  fi
	])
fi

if test $have_sia = no; then
  not_passdb="$not_passdb sia"
else
  passdb="$passdb sia"
fi

have_ldap=no
if test $want_ldap != no; then
	AC_CHECK_LIB(ldap, ldap_init, [
		AC_CHECK_HEADER(ldap.h, [
			AC_CHECK_LIB(ldap, ldap_initialize, [
				AC_DEFINE(LDAP_HAVE_INITIALIZE,, [Define if you have ldap_initialize])
			])
			AC_CHECK_LIB(ldap, ldap_start_tls_s, [
				AC_DEFINE(LDAP_HAVE_START_TLS_S,, [Define if you have ldap_start_tls_s])
			])
			LDAP_LIBS="-lldap"
			AC_CHECK_LIB(ldap, ber_free, [
			  # do nothing, default is to add -lldap to LIBS
			  :
			], [
			  AC_CHECK_LIB(lber, ber_free, [
			    LDAP_LIBS="$LDAP_LIBS -llber"
			  ])
			])
			AC_SUBST(LDAP_LIBS)
			if test $want_ldap != plugin; then
				AUTH_LIBS="$AUTH_LIBS $LDAP_LIBS"
		        	AC_DEFINE(BUILTIN_LDAP,, [LDAP support is built in])
			fi

        		AC_DEFINE(USERDB_LDAP,, [Build with LDAP support])
		        AC_DEFINE(PASSDB_LDAP,, [Build with LDAP support])
			AC_CHECK_HEADERS(sasl.h sasl/sasl.h)
			have_ldap=yes
		], [
		  if test $want_ldap != auto; then
		    AC_ERROR([Can't build with LDAP support: ldap.h not found])
		  fi
		])
	], [
	  if test $want_ldap != auto; then
	    AC_ERROR([Can't build with LDAP support: libldap not found])
	  fi
	])
fi

if test $have_ldap = no; then
  not_passdb="$not_passdb ldap"
  not_userdb="$not_userdb ldap"
else
  userdb="$userdb ldap"
  passdb="$passdb ldap"
  if test $want_ldap = plugin; then
    have_ldap_plugin=yes
    userdb="$userdb (plugin)"
    passdb="$passdb (plugin)"
  fi
fi
AM_CONDITIONAL(LDAP_PLUGIN, test "$have_ldap_plugin" = "yes")
AM_CONDITIONAL(HAVE_LDAP, test "$want_ldap" != "no")
dict_drivers=

if test $want_db != no; then
  AC_CACHE_CHECK([db_env_create in -ldb],i_cv_have_db_env_create,[
    old_LIBS=$LIBS
    LIBS="$LIBS -ldb"
    AC_TRY_LINK([
      #include <db.h>
    ], [
      db_env_create(0, 0);
    ], [
      i_cv_have_db_env_create=yes
    ], [
      i_cv_have_db_env_create=no
    ])
    LIBS=$old_LIBS
  ])
  if test $i_cv_have_db_env_create = yes; then
    AC_CHECK_HEADER(db.h, [
      DICT_LIBS="$DICT_LIBS -ldb"
      dict_drivers="$dict_drivers db"
      AC_DEFINE(BUILD_DB,, [Build with Berkeley DB support])
    ], [
      if test $want_db = yes; then
        AC_ERROR([Can't build with db support: db.h not found])
      fi
    ])
  else
    if test $want_db = yes; then
      AC_ERROR([Can't build with db support: libdb not found])
    fi
  fi
fi

if test $want_cdb != no; then
  AC_CHECK_LIB(cdb, cdb_init, [
    AC_CHECK_HEADER(cdb.h, [
      DICT_LIBS="$DICT_LIBS -lcdb"
      dict_drivers="$dict_drivers cdb"
      AC_DEFINE(BUILD_CDB,, [Build with CDB support])
    ], [
      if test $want_cdb = yes; then
        AC_ERROR([Can't build with CDB support: cdb.h not found])
      fi
    ])
  ], [
    if test $want_cdb = yes; then
      AC_ERROR([Can't build with CDB support: libcdb not found])
    fi
  ])
fi

if test $want_pgsql != no; then
  AC_CHECK_PROG(PG_CONFIG, pg_config, pg_config, NO)
  if test $PG_CONFIG = NO; then
    # based on code from PHP
    for i in /usr /usr/local /usr/local/pgsql; do
      for j in include include/pgsql include/postgres include/postgresql ""; do
	if test -r "$i/$j/libpq-fe.h"; then
	  PGSQL_INCLUDE=$i/$j
	fi
      done
      for lib in lib lib64; do
	for j in $lib $lib/pgsql $lib/postgres $lib/postgresql ""; do
	  if test -f "$i/$j/libpq.so" || test -f "$i/$j/libpq.a"; then
	    PGSQL_LIBDIR=$i/$j
	  fi
	done
      done
    done
  else
    PGSQL_INCLUDE="`$PG_CONFIG --includedir`"
    PGSQL_LIBDIR="`$PG_CONFIG --libdir`"  
  fi

  old_LIBS=$LIBS
  if test "$PGSQL_LIBDIR" != ""; then
    LIBS="$LIBS -L$PGSQL_LIBDIR"
  fi

  AC_CHECK_LIB(pq, PQconnectdb, [
	  AC_CHECK_LIB(pq, PQescapeStringConn, [
		  AC_DEFINE(HAVE_PQESCAPE_STRING_CONN,, [Define if libpq has PQescapeStringConn function])
	  ])
	  old_CPPFLAGS=$CPPFLAGS
	  if test "$PGSQL_INCLUDE" != ""; then
		  CPPFLAGS="$CPPFLAGS -I$PGSQL_INCLUDE"
	  fi
	  AC_CHECK_HEADER(libpq-fe.h, [
		  if test "$PGSQL_INCLUDE" != ""; then
			  PGSQL_CFLAGS="$PGSQL_CFLAGS -I$PGSQL_INCLUDE"
		  fi
		  if test "$PGSQL_LIBDIR" != ""; then
			  PGSQL_LIBS="$PGSQL_LIBS -L$PGSQL_LIBDIR"
		  fi
		  PGSQL_LIBS="$PGSQL_LIBS -lpq"
		  AC_DEFINE(HAVE_PGSQL,, [Build with PostgreSQL support])
		  found_sql_drivers="$found_sql_drivers pgsql"
	  ], [
	    if test $want_pgsql = yes; then
	      AC_ERROR([Can't build with PostgreSQL support: libpq-fe.h not found])
	    fi
	  ])
	  CPPFLAGS=$old_CPPFLAGS
  ], [
    if test $want_pgsql = yes; then
      AC_ERROR([Can't build with PostgreSQL support: libpq not found])
    fi
  ])
  LIBS=$old_LIBS
fi

have_mysql=no
if test $want_mysql != no; then
  AC_CHECK_PROG(MYSQL_CONFIG, mysql_config, mysql_config, NO)
  if test $MYSQL_CONFIG = NO; then
	# based on code from PHP
	MYSQL_LIBS="-lmysqlclient -lz -lm"
	for i in /usr /usr/local /usr/local/mysql; do
		for j in include include/mysql ""; do
			if test -r "$i/$j/mysql.h"; then
				MYSQL_INCLUDE="-I$i/$j"
			fi
		done
		for j in lib lib/mysql lib64 lib64/mysql ""; do
			if test -f "$i/$j/libmysqlclient.so" || test -f "$i/$j/libmysqlclient.a"; then
				MYSQL_LIBS="-L$i/$j -lmysqlclient -lz -lm"
			fi
		done
	done
  else
    MYSQL_INCLUDE="`$MYSQL_CONFIG --include`"
    MYSQL_LIBS="`$MYSQL_CONFIG --libs`"
  fi

  old_LIBS=$LIBS
  if test "$MYSQL_LIBS" != ""; then
    LIBS="$LIBS $MYSQL_LIBS"
  fi

  mysql_lib=""
  LIBS="$LIBS -lz -lm"
  AC_CHECK_LIB(mysqlclient, mysql_init, [
		old_CPPFLAGS=$CPPFLAGS
		if test "$MYSQL_INCLUDE" != ""; then
			CPPFLAGS="$CPPFLAGS $MYSQL_INCLUDE"
		fi
		AC_CHECK_HEADER(mysql.h, [
			if test "$MYSQL_INCLUDE" != ""; then
				MYSQL_CFLAGS="$MYSQL_CFLAGS $MYSQL_INCLUDE"
			fi

			AC_CHECK_LIB(mysqlclient, mysql_ssl_set, [
				AC_DEFINE(HAVE_MYSQL_SSL,, [Define if your MySQL library has SSL functions])
				if test "x$have_openssl" = "yes"; then
				  ssl_define="#define HAVE_OPENSSL"
				else
				  ssl_define=""
				fi
				AC_TRY_COMPILE([
				  $ssl_define
				  #include <mysql.h>
				], [
				  mysql_ssl_set(0, 0, 0, 0, 0, 0);
				], [
					AC_DEFINE(HAVE_MYSQL_SSL_CIPHER,, [Define if your MySQL library supports setting cipher])

					AC_TRY_COMPILE([
					  $ssl_define
					  #include <mysql.h>
					], [
					  int i = MYSQL_OPT_SSL_VERIFY_SERVER_CERT;
					], [
						AC_DEFINE(HAVE_MYSQL_SSL_VERIFY_SERVER_CERT,, [Define if your MySQL library supports verifying the name in the SSL certificate])
					])
				])
			])
			
			have_mysql=yes
			AC_DEFINE(HAVE_MYSQL,, [Build with MySQL support])
			found_sql_drivers="$found_sql_drivers mysql"
		], [
		  if test $want_mysql = yes; then
		    AC_ERROR([Can't build with MySQL support: mysql.h not found])
		  fi
		])
		CPPFLAGS=$old_CPPFLAGS
  ], [
    if test $want_mysql = yes; then
      AC_ERROR([Can't build with MySQL support: libmysqlclient not found])
    fi
  ])

  if test $have_mysql != yes; then
    MYSQL_LIBS=
    MYSQL_CFLAGS=
  fi
  LIBS=$old_LIBS
fi

if test $want_sqlite != no; then
	AC_CHECK_LIB(sqlite3, sqlite3_open, [
		AC_CHECK_HEADER(sqlite3.h, [
			SQLITE_LIBS="$SQLITE_LIBS -lsqlite3"

			AC_DEFINE(HAVE_SQLITE,, [Build with SQLite3 support])
			found_sql_drivers="$found_sql_drivers sqlite"
		], [
		  if test $want_sqlite = yes; then
		    AC_ERROR([Can't build with SQLite support: sqlite3.h not found])
		  fi
		])
	], [
	  if test $want_sqlite = yes; then
	    AC_ERROR([Can't build with SQLite support: libsqlite3 not found])
	  fi
	])
fi

if test $want_cassandra != no; then
	AC_CHECK_LIB(cassandra, cass_session_new, [
		AC_CHECK_HEADER(cassandra.h, [
			CASSANDRA_LIBS="$CASSANDRA_LIBS -lcassandra"

			AC_DEFINE(HAVE_CASSANDRA,, [Build with Cassandra support])
			found_sql_drivers="$found_sql_drivers cassandra"
                        AC_CHECK_LIB(cassandra, cass_cluster_set_constant_speculative_execution_policy, [
                          AC_DEFINE(HAVE_CASSANDRA_SPECULATIVE_POLICY, 1, [Cassandra supports speculative execution policy])
                        ])
		], [
		  if test $want_cassandra = yes; then
		    AC_ERROR([Can't build with Cassandra support: cassandra.h not found])
		  fi
		])
	], [
	  if test $want_cassandra = yes; then
	    AC_ERROR([Can't build with Cassandra support: libcassandra not found])
	  fi
	])
fi
	
SQL_CFLAGS="$MYSQL_CFLAGS $PGSQL_CFLAGS $SQLITE_CFLAGS $CASSANDRA_CFLAGS"
if test "$want_sql" != "plugin"; then
	SQL_LIBS="$MYSQL_LIBS $PGSQL_LIBS $SQLITE_LIBS $CASSANDRA_LIBS"
else
	AC_DEFINE(SQL_DRIVER_PLUGINS,, [Build SQL drivers as plugins])
fi
sql_drivers=
not_sql_drivers=

if test "$found_sql_drivers" != "" || test "$want_sql" != "no"; then
	sql_drivers="$found_sql_drivers"

	AC_DEFINE(PASSDB_SQL,, [Build with SQL support])
	AC_DEFINE(USERDB_SQL,, [Build with SQL support])
	AUTH_LIBS="$AUTH_LIBS $SQL_LIBS"
	passdb="$passdb sql"
	userdb="$userdb sql"
else
	not_passdb="$not_passdb sql"
	not_userdb="$not_userdb sql"
fi

have_vpopmail=no
if test $want_vpopmail != no; then
	vpop_etc="$vpopmail_home/etc"
	AC_MSG_CHECKING([for vpopmail configuration at $vpop_etc/lib_deps])
	if ! test -f $vpop_etc/lib_deps; then
		AC_MSG_RESULT(not found)
		vpop_etc="$vpopmail_home"
		AC_MSG_CHECKING([for vpopmail configuration at $vpop_etc/lib_deps])
	fi
	if test -f $vpop_etc/lib_deps; then
		AUTH_CFLAGS="$AUTH_CFLAGS `cat $vpop_etc/inc_deps` $CFLAGS"
		AUTH_LIBS="$AUTH_LIBS `cat $vpop_etc/lib_deps`"
		AC_DEFINE(USERDB_VPOPMAIL,, [Build with vpopmail support])
		AC_DEFINE(PASSDB_VPOPMAIL,, [Build with vpopmail support])
		AC_MSG_RESULT(found)
		have_vpopmail=yes
	else
		AC_MSG_RESULT(not found)
		if test $want_vpopmail = yes; then
		  AC_ERROR([Can't build with vpopmail support: $vpop_etc/lib_deps not found])
		fi
	fi
fi

if test $have_vpopmail = no; then
  not_passdb="$not_passdb vpopmail"
  not_userdb="$not_userdb vpopmail"
else
  userdb="$userdb vpopmail"
  passdb="$passdb vpopmail"
fi

AC_CHECK_FUNC(crypt,, [
  AC_CHECK_LIB(crypt, crypt, [
    AUTH_LIBS="-lcrypt $AUTH_LIBS"
    CRYPT_LIBS="-lcrypt"
  ], [
    AC_MSG_ERROR([crypt() wasn't found])
  ])
])
AC_SUBST(CRYPT_LIBS)

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

have_nss=no
if test $want_nss != no; then
  if test $have_modules != yes; then
    if test $want_nss = yes; then
      AC_ERROR([Can't build with NSS support: Dynamic modules not supported])
    fi
  else
    AC_CACHE_CHECK([for NSS support],i_cv_have_nss,[
      AC_TRY_COMPILE([
	#include <nss.h>
      ], [
	enum nss_status status = NSS_STATUS_TRYAGAIN;
      ], [
	i_cv_have_nss=yes
      ], [
	i_cv_have_nss=no
      ])
    ])
    if test $i_cv_have_nss = yes; then
      AC_DEFINE(USERDB_NSS,, [Build with NSS module support])
      have_nss=yes
    else
      if test $want_nss = yes; then
	AC_ERROR([Can't build with NSS support: nss.h not found or not usable])
      fi
    fi
  fi
fi

if test $have_nss = no; then
  not_userdb="$not_userdb nss"
else
  userdb="$userdb nss"
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

dnl **
dnl ** Endianess
dnl **

dnl At least Apple's gcc supports __BIG_ENDIAN__ and __LITTLE_ENDIAN__
dnl defines. Use them if possible to allow cross-compiling.
AC_CACHE_CHECK([if __BIG_ENDIAN__ or __LITTLE_ENDIAN__ is defined],i_cv_have___big_endian__,[
  AC_TRY_COMPILE([
    #if !(__BIG_ENDIAN__ || __LITTLE_ENDIAN__)
    #error nope
    #endif
  ], [
  ], [
    i_cv_have___big_endian__=yes
  ], [
    i_cv_have___big_endian__=no
  ])
])
if test $i_cv_have___big_endian__ = yes; then
  AC_DEFINE(WORDS_BIGENDIAN, __BIG_ENDIAN__, [Define if your CPU is big endian])
else
  AC_C_BIGENDIAN
fi

dnl **
dnl ** IPv6 support
dnl **

have_ipv6=no
AC_MSG_CHECKING([for IPv6])
AC_CACHE_VAL(i_cv_type_in6_addr,
[AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>]],
[[struct in6_addr i;]])],
[i_cv_type_in6_addr=yes],
[i_cv_type_in6_addr=no])])
if test $i_cv_type_in6_addr = yes; then
	AC_DEFINE(HAVE_IPV6,, [Build with IPv6 support])
	have_ipv6=yes
fi
AC_MSG_RESULT($i_cv_type_in6_addr)

dnl **
dnl ** storage classes
dnl **

maildir_libs='$(top_builddir)/src/lib-storage/index/maildir/libstorage_maildir.la'
mbox_libs='$(top_builddir)/src/lib-storage/index/mbox/libstorage_mbox.la'
dbox_common_libs='$(top_builddir)/src/lib-storage/index/dbox-common/libstorage_dbox_common.la'
sdbox_libs='$(top_builddir)/src/lib-storage/index/dbox-single/libstorage_dbox_single.la'
mdbox_libs='$(top_builddir)/src/lib-storage/index/dbox-multi/libstorage_dbox_multi.la'
cydir_libs='$(top_builddir)/src/lib-storage/index/cydir/libstorage_cydir.la'
imapc_libs='$(top_builddir)/src/lib-storage/index/imapc/libstorage_imapc.la $(top_builddir)/src/lib-imap-client/libimap_client.la'
pop3c_libs='$(top_builddir)/src/lib-storage/index/pop3c/libstorage_pop3c.la'
raw_libs='$(top_builddir)/src/lib-storage/index/raw/libstorage_raw.la'
shared_libs='$(top_builddir)/src/lib-storage/index/shared/libstorage_shared.la'

CORE_LIBS='$(top_builddir)/src/lib-dovecot/libdovecot.la'
STORAGE_LIB='$(top_builddir)/src/lib-storage/libdovecot-storage.la'

LINKED_STORAGE_LIBS=

mailbox_list_drivers="maildir imapdir fs index none shared"
have_sdbox=no
have_mdbox=no
for storage in $mail_storages; do
  LINKED_STORAGE_LIBS="$LINKED_STORAGE_LIBS `eval echo \\$${storage}_libs`"
  if test $storage = sdbox; then
    have_sdbox=yes
  fi
  if test $storage = mdbox; then
    have_mdbox=yes
  fi
  if test $storage = sdbox || test $storage = mdbox; then
    LINKED_STORAGE_LIBS="$LINKED_STORAGE_LIBS $dbox_common_libs"
    dbox_common_libs=""
  fi
  if test $storage = imapc; then
    mailbox_list_drivers="$mailbox_list_drivers imapc"
  fi
done
LINKED_STORAGE_LDADD=
AC_SUBST(LINKED_STORAGE_LIBS)
AC_SUBST(LINKED_STORAGE_LDADD)
AC_SUBST(mailbox_list_drivers)
AC_DEFINE_UNQUOTED(MAIL_STORAGES, "$mail_storages", [List of compiled in mail storages])

if test $have_sdbox = yes; then
  # create alias for sdbox
  mail_storages="$mail_storages dbox"
fi
if test $have_mdbox = yes; then
  mail_storages="$mail_storages mdbox_deleted"
fi

dnl **
dnl ** Shared libraries usage
dnl **

LIBDOVECOT_LA_LIBS='$(top_builddir)/src/lib-dict-extra/libdict_extra.la $(top_builddir)/src/lib-oauth2/liboauth2.la $(top_builddir)/src/lib-program-client/libprogram_client.la $(top_builddir)/src/lib-master/libmaster.la $(top_builddir)/src/lib-settings/libsettings.la $(top_builddir)/src/lib-stats/libstats.la $(top_builddir)/src/lib-http/libhttp.la $(top_builddir)/src/lib-fs/libfs.la $(top_builddir)/src/lib-dict/libdict.la $(top_builddir)/src/lib-smtp/libsmtp.la $(top_builddir)/src/lib-dns/libdns.la $(top_builddir)/src/lib-imap/libimap.la $(top_builddir)/src/lib-mail/libmail.la $(top_builddir)/src/lib-sasl/libsasl.la $(top_builddir)/src/lib-auth/libauth.la $(top_builddir)/src/lib-charset/libcharset.la $(top_builddir)/src/lib-ssl-iostream/libssl_iostream.la $(top_builddir)/src/lib-dcrypt/libdcrypt.la $(top_builddir)/src/lib-test/libtest.la $(top_builddir)/src/lib/liblib.la'
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
if test "$want_zlib" != "no"; then
  AC_CHECK_HEADER(zlib.h, [
    have_zlib=yes
    have_compress_lib=yes
    AC_DEFINE(HAVE_ZLIB,, [Define if you have zlib library])
    COMPRESS_LIBS="$COMPRESS_LIBS -lz"
  ], [
    if test "$want_zlib" = "yes"; then
      AC_ERROR([Can't build with zlib support: zlib.h not found])
    fi
  ])
fi

if test "$want_bzlib" != "no"; then
  AC_CHECK_HEADER(bzlib.h, [
    AC_CHECK_LIB(bz2, BZ2_bzdopen, [
      have_bzlib=yes
      have_compress_lib=yes
      AC_DEFINE(HAVE_BZLIB,, [Define if you have bzlib library])
      COMPRESS_LIBS="$COMPRESS_LIBS -lbz2"
    ], [
      if test "$want_bzlib" = "yes"; then
	AC_ERROR([Can't build with bzlib support: libbz2 not found])
      fi
    ])
  ], [
    if test "$want_bzlib" = "yes"; then
      AC_ERROR([Can't build with bzlib support: bzlib.h not found])
    fi
  ])
fi

if test "$want_lzma" != "no"; then
  AC_CHECK_HEADER(lzma.h, [
    AC_CHECK_LIB(lzma, lzma_stream_decoder, [
      have_lzma=yes
      have_compress_lib=yes
      AC_DEFINE(HAVE_LZMA,, [Define if you have lzma library])
      COMPRESS_LIBS="$COMPRESS_LIBS -llzma"
    ], [
      if test "$want_lzma" = "yes"; then
	AC_ERROR([Can't build with lzma support: liblzma not found])
      fi
    ])
  ], [
    if test "$want_lzma" = "yes"; then
      AC_ERROR([Can't build with lzma support: lzma.h not found])
    fi
  ])
fi
AC_SUBST(COMPRESS_LIBS)

if test "$want_lz4" != "no"; then
  AC_CHECK_HEADER(lz4.h, [
    AC_CHECK_LIB(lz4, LZ4_compress, [
      have_lz4=yes
      have_compress_lib=yes
      AC_DEFINE(HAVE_LZ4,, [Define if you have lz4 library])
      COMPRESS_LIBS="$COMPRESS_LIBS -llz4"
    ], [
      if test "$want_lz4" = "yes"; then
	AC_ERROR([Can't build with lz4 support: liblz4 not found])
      fi
    ])
    AC_CHECK_LIB(lz4, LZ4_compress_default, [
      AC_DEFINE(HAVE_LZ4_COMPRESS_DEFAULT,,
	[Define if you have LZ4_compress_default])
    ], [
    ])
  ], [
    if test "$want_lz4" = "yes"; then
      AC_ERROR([Can't build with lz4 support: lz4.h not found])
    fi
  ])
fi
AC_SUBST(COMPRESS_LIBS)

AM_CONDITIONAL(BUILD_ZLIB_PLUGIN, test "$have_compress_lib" = "yes")

RPCGEN=${RPCGEN-rpcgen}
if ! $RPCGEN -c /dev/null > /dev/null; then
  RPCGEN=
fi
AC_SUBST(RPCGEN)

have_rquota=no
if test -f /usr/include/rpcsvc/rquota.x && test -n "$RPCGEN"; then
  AC_DEFINE(HAVE_RQUOTA,, [Define if you wish to retrieve quota of NFS mounted mailboxes])
  have_rquota=yes
fi
AM_CONDITIONAL(HAVE_RQUOTA, test "$have_rquota" = "yes")

QUOTA_LIBS=""
AC_SEARCH_LIBS(quota_open, quota, [
  AC_DEFINE(HAVE_QUOTA_OPEN,, [Define if you have quota_open()])
  QUOTA_LIBS="-lquota"
])
AC_SUBST(QUOTA_LIBS)

dnl
dnl ** Full text search
dnl

fts=" squat"
not_fts=""

have_solr=no
if test "$want_solr" != "no"; then
  dnl need libexpat
  AC_CHECK_LIB(expat, XML_Parse, [
    AC_CHECK_HEADER(expat.h, [
      have_solr=yes
      fts="$fts solr"
    ], [
      if test $want_solr = yes; then
        AC_ERROR([Can't build with Solr support: expat.h not found])
      fi
    ])
  ], [
    if test $want_solr = yes; then
      AC_ERROR([Can't build with Solr support: libexpat not found])
    fi
  ])
fi
AM_CONDITIONAL(BUILD_SOLR, test "$have_solr" = "yes")

have_lucene=no
if test "$want_lucene" = "yes"; then
  PKG_CHECK_MODULES(CLUCENE, libclucene-core,, [
    # no pkg-config file for clucene. fallback to defaults.
    # FIXME: we should verify here that this actually works..
    CLUCENE_LIBS="-lclucene-shared -lclucene-core"
  ])
  have_lucene=yes
  fts="$fts lucene"
fi

if test $want_stemmer != no; then
  AC_CHECK_LIB(stemmer, sb_stemmer_new, [
    have_fts_stemmer=yes
    AC_DEFINE(HAVE_FTS_STEMMER,, [Define if you want stemming support for FTS])
  ], [
    if test $want_stemmer = yes; then
      AC_ERROR([Can't build with stemmer support: libstemmer not found])
    fi
  ])
fi
AM_CONDITIONAL(BUILD_FTS_STEMMER, test "$have_fts_stemmer" = "yes")

if test $want_textcat != no; then
  if test "$PKG_CONFIG" != "" && $PKG_CONFIG --exists libexttextcat 2>/dev/null; then
    PKG_CHECK_MODULES(LIBEXTTEXTCAT, libexttextcat)
    TEXTCAT_DATADIR=`$PKG_CONFIG --variable=pkgdatadir libexttextcat`
    AC_DEFINE(HAVE_FTS_EXTTEXTCAT,, [Define if you want exttextcat support for FTS])
    have_fts_exttextcat=yes
    # Debian Wheezy workaround - LIBEXTTEXTCAT_CFLAGS include path is wrong:
    AC_CHECK_HEADERS(libexttextcat/textcat.h)
  else
    AC_CHECK_LIB(exttextcat, special_textcat_Init, [
      have_fts_exttextcat=yes
      AC_CHECK_HEADERS(libexttextcat/textcat.h)
      LIBEXTTEXTCAT_LIBS=-lexttextcat
      AC_DEFINE(HAVE_FTS_EXTTEXTCAT,, [Define if you want exttextcat support for FTS])
      TEXTCAT_DATADIR="/usr/share/libexttextcat"
      AC_SUBST(LIBEXTTEXTCAT_LIBS)
    ], [
      AC_CHECK_LIB(textcat, special_textcat_Init, [
	have_fts_textcat=yes
        TEXTCAT_DATADIR="/usr/share/libtextcat"
        AC_CHECK_HEADERS(libtextcat/textcat.h)
      ])
    ])
    if test $want_textcat = yes && test "$have_fts_exttextcat" != yes && test "$have_fts_textcat" != yes; then
      AC_ERROR([Can't build with textcat support: libtextcat or libexttextcat not found])
    fi
  fi
  if test "$have_fts_exttextcat" = yes || test "$have_fts_textcat" = yes; then
    AC_DEFINE(HAVE_FTS_TEXTCAT,, [Define if you want textcat support for FTS])
    AC_DEFINE_UNQUOTED(TEXTCAT_DATADIR, "$TEXTCAT_DATADIR", [Points to textcat pkgdatadir containing the language files])
  fi
fi
AM_CONDITIONAL(BUILD_FTS_TEXTCAT, test "$have_fts_textcat" = "yes")
AM_CONDITIONAL(BUILD_FTS_EXTTEXTCAT, test "$have_fts_exttextcat" = "yes")

if test "$want_icu" != "no"; then
  if test "$PKG_CONFIG" != "" && $PKG_CONFIG --exists icu-i18n 2>/dev/null; then
    PKG_CHECK_MODULES(LIBICU, icu-i18n)
    have_icu=yes
    AC_DEFINE(HAVE_LIBICU,, [Define if you want ICU normalization support for FTS])
  elif test "$want_icu" = "yes"; then
    AC_ERROR([Can't build with libicu support: libicu-i18n not found])
  fi
fi
AM_CONDITIONAL(BUILD_LIBICU, test "$have_icu" = "yes")

DOVECOT_WANT_APPARMOR

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
FILES1=`find $srcdir/src -name '*settings.[[ch]]'|grep "$srcdir/src/lib-" | sed 's/^\(.*\)\(.\)$/\2 \1\2/' | grep -v 'lib-master.*c$' | sort -r | sed s/^..//`
FILES2=`find $srcdir/src -name '*settings.[[ch]]'|grep -v "$srcdir/src/lib-" | sed 's/^\(.*\)\(.\)$/\2 \1\2/' | grep -v all-settings | sort -r | sed s/^..//`
SETTING_FILES=`echo $FILES1 $FILES2 | sed -e s,$srcdir/src,./src,g -e 's,./src,$(top_srcdir)/src,g'`
AC_SUBST(SETTING_FILES)

dnl **
dnl ** capabilities
dnl **

dnl IDLE doesn't really belong to banner. It's there just to make Blackberries
dnl happy, because otherwise BIS server disables push email.
capability_banner="IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE"
capability="$capability_banner SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY"
AC_DEFINE_UNQUOTED(CAPABILITY_STRING, "$capability", [IMAP capabilities])
AC_DEFINE_UNQUOTED(CAPABILITY_BANNER_STRING, "$capability_banner", [IMAP capabilities advertised in banner])

CFLAGS="$CFLAGS $EXTRA_CFLAGS"
NOPLUGIN_LDFLAGS="-no-undefined"
if test "$with_gnu_ld" = yes; then
  NOPLUGIN_LDFLAGS="$NOPLUGIN_LDFLAGS -Wl,--as-needed"
fi
LDFLAGS="\$(NOPLUGIN_LDFLAGS) $LDFLAGS"
AC_SUBST(NOPLUGIN_LDFLAGS)

DC_CC_WRAPPER

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
src/lib-stats/Makefile
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
src/lib-storage/register/Makefile
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
src/replication/Makefile
src/replication/aggregator/Makefile
src/replication/replicator/Makefile
src/ssl-params/Makefile
src/stats/Makefile
src/util/Makefile
src/plugins/Makefile
src/plugins/acl/Makefile
src/plugins/imap-acl/Makefile
src/plugins/autocreate/Makefile
src/plugins/dict-ldap/Makefile
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
src/plugins/stats/Makefile
src/plugins/imap-stats/Makefile
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
echo "dcrypt ..........: $build_dcrypt_openssl"

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
