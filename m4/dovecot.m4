dnl dovecot.m4 - Check presence of dovecot -*-Autoconf-*-
dnl
dnl   Copyright (C) 2010 Dennis Schridde
dnl
dnl This file is free software; the authors give
dnl unlimited permission to copy and/or distribute it, with or without
dnl modifications, as long as this notice is preserved.

# serial 45

dnl
dnl Check for support for D_FORTIFY_SOURCE=2
dnl

AC_DEFUN([AC_CC_D_FORTIFY_SOURCE],[
    AC_REQUIRE([gl_UNKNOWN_WARNINGS_ARE_ERRORS])
    AS_IF([test "$enable_hardening" = yes], [
      case "$host" in
        *)
          gl_COMPILER_OPTION_IF([-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2], [
            AM_CFLAGS="$AM_CFLAGS -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2"
            ],
            [],
            [AC_LANG_PROGRAM()]
          )
        ;;
      esac
    ])
])

dnl * gcc specific options
AC_DEFUN([DC_DOVECOT_CFLAGS],[
  m4_version_prereq(2.70, [AC_PROG_CC], [AC_PROG_CC_C99])

  AS_IF([test "$ac_prog_cc_stdc" = "c89" || test "$ac_prog_cc_std" = "no" || test "$ac_cv_prog_cc_c99" = "no"], [
    AC_MSG_ERROR(C99 capable compiler required)
  ])

  AC_MSG_CHECKING([Which $CC -std flag to use])
  old_cflags=$CFLAGS
  std=
  for mystd in gnu11 gnu99 c11 c99; do
    CFLAGS="-std=$mystd"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM()
    ], [
      AM_CFLAGS="$AM_CFLAGS $CFLAGS"
      std=$mystd
      break
    ])
  done
  AC_MSG_RESULT($std)
  CFLAGS="$old_cflags"

  AS_IF([test "x$ac_cv_c_compiler_gnu" = "xyes"], [
    dnl -Wcast-qual -Wcast-align -Wconversion -Wunreachable-code # too many warnings
    dnl -Wstrict-prototypes -Wredundant-decls # may give warnings in some systems
    dnl -Wmissing-format-attribute -Wmissing-noreturn -Wwrite-strings # a couple of warnings
    AM_CFLAGS="$AM_CFLAGS -Wall -W -Wmissing-prototypes -Wmissing-declarations -Wpointer-arith -Wchar-subscripts -Wformat=2 -Wbad-function-cast"

    AS_IF([test "$have_clang" = "yes"], [
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      #if __clang_major__ > 3 || (__clang_major__ == 3 && __clang_minor__ >= 3)
      #  error new clang
      #endif
      ]], [[]])],[],[
        dnl clang 3.3+ unfortunately this gives warnings with hash.h
        AM_CFLAGS="$AM_CFLAGS -Wno-duplicate-decl-specifier"
      ])
    ], [
      dnl This is simply to avoid warning when building strftime() wrappers..
      AM_CFLAGS="$AM_CFLAGS -fno-builtin-strftime"
    ])

    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      #if __GNUC__ < 4
      #  error old gcc
      #endif
      ]], [[]])],[
        dnl gcc4
        AM_CFLAGS="$AM_CFLAGS -Wstrict-aliasing=2"
      ],[])

    old_cflags=$CFLAGS
    CFLAGS="$CFLAGS -Werror"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      const unsigned char foo[4] __attribute__((nonstring)) = "1234";
      ]], [[]])],[
        AC_DEFINE(HAVE_ATTR_NONSTRING,, [define if you have nonstring attribute])
      ])
    CFLAGS="$old_cflags"
  ])
])

AC_DEFUN([AC_LD_WHOLE_ARCHIVE], [
    LD_WHOLE_ARCHIVE=
    LD_NO_WHOLE_ARCHIVE=
    AC_MSG_CHECKING([for linker option to include whole archive])
    ld_help="`$CC -Wl,-help 2>&1`"
    case "$ld_help" in
        *"--whole-archive"*)
            LD_WHOLE_ARCHIVE="--whole-archive"
            LD_NO_WHOLE_ARCHIVE="--no-whole-archive"
        ;;
    esac
    AS_IF([test "x$LD_WHOLE_ARCHIVE" != "x"],
      [AC_MSG_RESULT([-Wl,$LD_WHOLE_ARCHIVE])],
      [AC_MSG_RESULT([not supported])]
    )
    AC_SUBST([LD_WHOLE_ARCHIVE])
    AC_SUBST([LD_NO_WHOLE_ARCHIVE])
    AM_CONDITIONAL([HAVE_WHOLE_ARCHIVE], [test "x$LD_WHOLE_ARCHIVE" != "x"])
])

dnl
dnl Check for -z now and -z relro linker flags
dnl
dnl Copyright (C) 2013 Red Hat, Inc.
dnl
dnl This library is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU Lesser General Public
dnl License as published by the Free Software Foundation; either
dnl version 2.1 of the License, or (at your option) any later version.
dnl
dnl This library is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl Lesser General Public License for more details.
dnl
dnl You should have received a copy of the GNU Lesser General Public
dnl License along with this library.  If not, see
dnl <http://www.gnu.org/licenses/>.
dnl

AC_DEFUN([AC_LD_RELRO],[
    RELRO_LDFLAGS=
    AS_IF([test "$enable_hardening" = yes], [
      AC_MSG_CHECKING([for how to force completely read-only GOT table])
      ld_help=`$CC -Wl,-help 2>&1`
      case $ld_help in
          *"-z relro"*) RELRO_LDFLAGS="-Wl,-z -Wl,relro" ;;
      esac
      case $ld_help in
          *"-z now"*) RELRO_LDFLAGS="$RELRO_LDFLAGS -Wl,-z -Wl,now" ;;
      esac
      AS_IF([test "x$RELRO_LDFLAGS" != "x"],
        [AC_MSG_RESULT([$RELRO_LDFLAGS])],
        [AC_MSG_RESULT([unknown])]
      )
   ])
   AC_SUBST([RELRO_LDFLAGS])
])

dnl
dnl Check for support for position independent executables
dnl
dnl Copyright (C) 2013 Red Hat, Inc.
dnl
dnl This library is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU Lesser General Public
dnl License as published by the Free Software Foundation; either
dnl version 2.1 of the License, or (at your option) any later version.
dnl
dnl This library is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl Lesser General Public License for more details.
dnl
dnl You should have received a copy of the GNU Lesser General Public
dnl License along with this library.  If not, see
dnl <http://www.gnu.org/licenses/>.
dnl

AC_DEFUN([AC_CC_PIE],[
    AC_REQUIRE([gl_UNKNOWN_WARNINGS_ARE_ERRORS])
    PIE_CFLAGS=
    PIE_LDFLAGS=

    AS_IF([test "$enable_hardening" = yes], [
      OLD_CFLAGS=$CFLAGS
      case "$host" in
        *-*-mingw* | *-*-msvc* | *-*-cygwin* )
           ;; dnl All code is position independent on Win32 target
        *)
          CFLAGS="-fPIE -DPIE"
          gl_COMPILER_OPTION_IF([-pie], [
            PIE_CFLAGS="-fPIE -DPIE"
            PIE_LDFLAGS="-pie"
            ], [
              dnl some versions of clang require -Wl,-pie instead of -pie
              gl_COMPILER_OPTION_IF([[-Wl,-pie]], [
                PIE_CFLAGS="-fPIE -DPIE"
                PIE_LDFLAGS="-Wl,-pie"
                ], [AC_MSG_RESULT([not supported])],
                [AC_LANG_PROGRAM()]
              )
            ],
            [AC_LANG_PROGRAM()]
          )
      esac
      CFLAGS=$OLD_CFLAGS
    ])
    AC_SUBST([PIE_CFLAGS])
    AC_SUBST([PIE_LDFLAGS])
])

dnl
dnl Check for support for Retpoline
dnl

AC_DEFUN([AC_CC_RETPOLINE],[
    AC_ARG_WITH(retpoline,
       AS_HELP_STRING([--with-retpoline=<choice>], [Retpoline mitigation choice (default: keep)]),
            with_retpoline=$withval,
            with_retpoline=keep)

    AC_REQUIRE([gl_UNKNOWN_WARNINGS_ARE_ERRORS])
    AS_IF([test "$enable_hardening" = yes], [
      case "$host" in
        *)
          gl_COMPILER_OPTION_IF([-mfunction-return=$with_retpoline],
            [AM_CFLAGS="$AM_CFLAGS -mfunction-return=$with_retpoline"],
            [],
            [AC_LANG_PROGRAM()]
          )
          gl_COMPILER_OPTION_IF([-mindirect-branch=$with_retpoline], [
            AM_CFLAGS="$AM_CFLAGS -mindirect-branch=$with_retpoline"
            ],
            [],
            [AC_LANG_PROGRAM()]
          )
      esac
    ])
])

dnl
dnl Check for support for -fstack-protector or -strong
dnl

AC_DEFUN([AC_CC_F_STACK_PROTECTOR],[
    AC_REQUIRE([gl_UNKNOWN_WARNINGS_ARE_ERRORS])
    AS_IF([test "$enable_hardening" = yes], [
      case "$host" in
        *)
          gl_COMPILER_OPTION_IF([-fstack-protector-strong], [
            AM_CFLAGS="$AM_CFLAGS -fstack-protector-strong"
            ],
            [
               gl_COMPILER_OPTION_IF([-fstack-protector], [
                 AM_CFLAGS="$AM_CFLAGS -fstack-protector"
                 ], [], [AC_LANG_PROGRAM()])
            ],
            [AC_LANG_PROGRAM()]
          )
      esac
    ])
])

AC_DEFUN([DC_DOVECOT_MODULEDIR],[
	AC_ARG_WITH(moduledir,
	[  --with-moduledir=DIR    Base directory for dynamically loadable modules],
		[moduledir="$withval"],
		[moduledir="\$(libdir)/dovecot"]
	)
	AC_SUBST(moduledir)
])

AC_DEFUN([DC_PLUGIN_DEPS],[
	_plugin_deps=yes
	AC_MSG_CHECKING([whether OS supports plugin dependencies])
	case "$host_os" in
	  darwin*)
	    dnl OSX loads the plugins twice, which breaks stuff
	    _plugin_deps=no
	    ;;
	esac
	AC_MSG_RESULT([$_plugin_deps])
	AM_CONDITIONAL([DOVECOT_PLUGIN_DEPS], [test "x$_plugin_deps" = "xyes"])
	unset _plugin_deps
])

AC_DEFUN([DC_DOVECOT_TEST_WRAPPER],[
  AC_REQUIRE_AUX_FILE([run-test.sh.in])
  AC_ARG_VAR([VALGRIND], [Path to valgrind])
  AC_PATH_PROG(VALGRIND, valgrind, reject)
  AS_IF([test "$VALGRIND" != reject], [
    RUN_TEST='$(LIBTOOL) execute $(SHELL) $(top_builddir)/build-aux/run-test.sh'
  ], [
    RUN_TEST=''
  ])
  AC_SUBST(RUN_TEST)
])

dnl Substitute every var in the given comma separated list
AC_DEFUN([AX_SUBST_L],[
	m4_foreach([__var__], [$@], [AC_SUBST(__var__)])
])

AC_DEFUN([DC_DOVECOT_HARDENING],[
        AC_ARG_ENABLE(hardening,
        AS_HELP_STRING([--enable-hardening=yes], [Enable various hardenings (default: yes)]),
                enable_hardening=$enableval,
                enable_hardening=yes)

        AC_MSG_CHECKING([Whether to enable hardening])
        AC_MSG_RESULT([$enable_hardening])

	AC_CC_PIE
	AC_CC_F_STACK_PROTECTOR
	AC_CC_D_FORTIFY_SOURCE
	AC_CC_RETPOLINE
	AC_LD_RELRO
	DOVECOT_WANT_UBSAN
])

AC_DEFUN([DC_DOVECOT_FUZZER],[
        AC_ARG_WITH(fuzzer,
        AS_HELP_STRING([--with-fuzzer=clang], [Build with clang fuzzer (default: no)]),
                with_fuzzer=$withval,
                with_fuzzer=no)
	AS_IF([test x$with_fuzzer = xclang], [
		AM_CFLAGS="$AM_CFLAGS -fsanitize=fuzzer-no-link"
		AM_CFLAGS="$AM_CFLAGS -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
		# use $LIB_FUZZING_ENGINE for linking if it exists
		FUZZER_LDFLAGS=${LIB_FUZZING_ENGINE--fsanitize=fuzzer}
		# May need to use CXXLINK for linking, which wants sources to
		# be compiled with -fPIE
		FUZZER_CPPFLAGS='$(AM_CPPFLAGS) -fPIE -DPIE'
	], [test x$with_fuzzer != xno], [
		AC_MSG_ERROR([Unknown fuzzer $with_fuzzer])
	])
	AC_SUBST([FUZZER_CPPFLAGS])
	AC_SUBST([FUZZER_LDFLAGS])
	AM_CONDITIONAL([USE_FUZZER], [test "x$with_fuzzer" != "xno"])

])

AC_DEFUN([DC_DOVECOT],[
	AC_ARG_WITH(dovecot,
	  [  --with-dovecot=DIR      Dovecot base directory],
			[ dovecotdir="$withval" ], [
			  dc_prefix=$prefix
			  test "x$dc_prefix" = xNONE && dc_prefix=$ac_default_prefix
			  dovecotdir="$dc_prefix/lib/dovecot"
			]
	)

	AC_ARG_WITH(dovecot-install-dirs,
		[AS_HELP_STRING([--with-dovecot-install-dirs],
		[Use install directories configured for Dovecot (default)])],
	AS_IF([test x$withval = xno], [
		use_install_dirs=no
	], [
		use_install_dirs=yes
	]),
	use_install_dirs=yes)

	AC_MSG_CHECKING([for "$dovecotdir/dovecot-config"])
	AS_IF([test -f "$dovecotdir/dovecot-config"], [
		AC_MSG_RESULT([$dovecotdir/dovecot-config])
	], [
		AC_MSG_RESULT([not found])
		AC_MSG_NOTICE([])
		AC_MSG_NOTICE([Use --with-dovecot=DIR to provide the path to the dovecot-config file.])
		AC_MSG_ERROR([dovecot-config not found])
	])

	old=`pwd`
	cd $dovecotdir
	abs_dovecotdir=`pwd`
	cd $old
	AC_SUBST(abs_dovecotdir)
	DISTCHECK_CONFIGURE_FLAGS="--with-dovecot=$abs_dovecotdir --without-dovecot-install-dirs"

	dnl Make sure dovecot-config doesn't accidentically override flags
	ORIG_CFLAGS="$CFLAGS"
	ORIG_LDFLAGS="$LDFLAGS"
	ORIG_BINARY_CFLAGS="$BINARY_CFLAGS"
	ORIG_BINARY_LDFLAGS="$BINARY_LDFLAGS"

	eval `$GREP -i '^dovecot_[[a-z_]]*=' "$dovecotdir"/dovecot-config`
	eval `$GREP '^LIBDOVECOT[[A-Z0-9_]]*=' "$dovecotdir"/dovecot-config`

        CFLAGS="$ORIG_CFLAGS"
        LDFLAGS="$ORIG_LDFLAGS"
        BINARY_CFLAGS="$ORIG_BINARY_CFLAGS"
        BINARY_LDFLAGS="$ORIG_BINARY_LDFLAGS"

	dovecot_installed_moduledir="$dovecot_moduledir"

	AS_IF([test "$use_install_dirs" = "no"], [
		dnl the main purpose of these is to fix make distcheck for plugins
		dnl other than that, they don't really make much sense
		dovecot_pkgincludedir='$(pkgincludedir)'
		dovecot_pkglibdir='$(pkglibdir)'
		dovecot_pkglibexecdir='$(libexecdir)/dovecot'
		dovecot_docdir='$(docdir)'
		dovecot_moduledir='$(moduledir)'
		dovecot_statedir='$(statedir)'
	])

	CC_CLANG
	CC_STRICT_BOOL
	DC_DOVECOT_CFLAGS
	DC_DOVECOT_HARDENING

	AX_SUBST_L([DISTCHECK_CONFIGURE_FLAGS], [dovecotdir], [dovecot_moduledir], [dovecot_installed_moduledir], [dovecot_pkgincludedir], [dovecot_pkglibexecdir], [dovecot_pkglibdir], [dovecot_docdir], [dovecot_statedir])
	AX_SUBST_L([DOVECOT_INSTALLED], [DOVECOT_CFLAGS], [DOVECOT_LIBS], [DOVECOT_SSL_LIBS], [DOVECOT_SQL_LIBS], [DOVECOT_LDAP_LIBS], [DOVECOT_COMPRESS_LIBS], [DOVECOT_BINARY_CFLAGS], [DOVECOT_BINARY_LDFLAGS])
	AX_SUBST_L([LIBDOVECOT], [LIBDOVECOT_LOGIN], [LIBDOVECOT_SQL], [LIBDOVECOT_LDAP], [LIBDOVECOT_OPENSSL], [LIBDOVECOT_COMPRESS], [LIBDOVECOT_LDA], [LIBDOVECOT_STORAGE], [LIBDOVECOT_DSYNC], [LIBDOVECOT_LIBLANG], [LIBDOVECOT_GSSAPI])
	AX_SUBST_L([LIBDOVECOT_DEPS], [LIBDOVECOT_LOGIN_DEPS], [LIBDOVECOT_SQL_DEPS], [LIBDOVECOT_LDAP_DEPS], [LIBDOVECOT_OPENSSL_DEPS], [LIBDOVECOT_COMPRESS_DEPS], [LIBDOVECOT_LDA_DEPS], [LIBDOVECOT_STORAGE_DEPS], [LIBDOVECOT_DSYNC_DEPS], [LIBDOVECOT_LIBLANG_DEPS], [LIBDOVECOT_GSSAPI_DEPS])
	AX_SUBST_L([LIBDOVECOT_INCLUDE], [LIBDOVECOT_LDA_INCLUDE], [LIBDOVECOT_AUTH_INCLUDE], [LIBDOVECOT_DOVEADM_INCLUDE], [LIBDOVECOT_SERVICE_INCLUDE], [LIBDOVECOT_STORAGE_INCLUDE], [LIBDOVECOT_LOGIN_INCLUDE], [LIBDOVECOT_SQL_INCLUDE], [LIBDOVECOT_LDAP_INCLUDE])
	AX_SUBST_L([LIBDOVECOT_IMAP_LOGIN_INCLUDE], [LIBDOVECOT_CONFIG_INCLUDE], [LIBDOVECOT_IMAP_INCLUDE], [LIBDOVECOT_POP3_INCLUDE], [LIBDOVECOT_SUBMISSION_INCLUDE], [LIBDOVECOT_LMTP_INCLUDE], [LIBDOVECOT_DSYNC_INCLUDE], [LIBDOVECOT_IMAPC_INCLUDE], [LIBDOVECOT_FTS_INCLUDE])
	AX_SUBST_L([LIBDOVECOT_NOTIFY_INCLUDE], [LIBDOVECOT_PUSH_NOTIFICATION_INCLUDE], [LIBDOVECOT_ACL_INCLUDE], [LIBDOVECOT_LIBLANG_INCLUDE], [LIBDOVECOT_LUA_INCLUDE])
	AX_SUBST_L([DOVECOT_LUA_LIBS], [DOVECOT_LUA_CFLAGS], [LIBDOVECOT_LUA], [LIBDOVECOT_LUA_DEPS])

	AS_IF([test x$DOVECOT_HAVE_MAIL_UTF8 = xyes], [
		AC_DEFINE([DOVECOT_HAVE_MAIL_UTF8],,"Define if Dovecot has mail UTF-8 support")
	])
	AM_CONDITIONAL(DOVECOT_INSTALLED, test "$DOVECOT_INSTALLED" = "yes")

	DC_PLUGIN_DEPS
	DC_DOVECOT_TEST_WRAPPER
])

AC_DEFUN([DC_CC_WRAPPER],[
  AS_IF([test "$want_shared_libs" != "yes"], [
    dnl want_shared_libs=no is for internal use. the liblib.la check is for plugins
    AS_IF([test "$want_shared_libs" = "no" || echo "$LIBDOVECOT" | $GREP "/liblib.la" > /dev/null], [
      AS_IF([test "$with_gnu_ld" = yes], [
	dnl libtool can't handle using whole-archive flags, so we need to do this
	dnl with a CC wrapper.. shouldn't be much of a problem, since most people
	dnl are building with shared libs.
	cat > cc-wrapper.sh <<_DC_EOF
#!/bin/sh

if echo "\$[*]" | $GREP -- -export-dynamic > /dev/null; then
  # the binary uses plugins. make sure we include everything from .a libs
  exec $CC -Wl,--whole-archive \$[*] -Wl,--no-whole-archive
else
  exec $CC \$[*]
fi
_DC_EOF
	chmod +x cc-wrapper.sh
	CC=`pwd`/cc-wrapper.sh
      ])
    ])
  ])
])

# warnings.m4 serial 11
dnl Copyright (C) 2008-2015 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl From Simon Josefsson

# gl_AS_VAR_APPEND(VAR, VALUE)
# ----------------------------
# Provide the functionality of AS_VAR_APPEND if Autoconf does not have it.
m4_ifdef([AS_VAR_APPEND],
[m4_copy([AS_VAR_APPEND], [gl_AS_VAR_APPEND])],
[m4_define([gl_AS_VAR_APPEND],
[AS_VAR_SET([$1], [AS_VAR_GET([$1])$2])])])


# gl_COMPILER_OPTION_IF(OPTION, [IF-SUPPORTED], [IF-NOT-SUPPORTED],
#                       [PROGRAM = AC_LANG_PROGRAM()])
# -----------------------------------------------------------------
# Check if the compiler supports OPTION when compiling PROGRAM.
#
# FIXME: gl_Warn must be used unquoted until we can assume Autoconf
# 2.64 or newer.
AC_DEFUN([gl_COMPILER_OPTION_IF],
[AS_VAR_PUSHDEF([gl_Warn], [gl_cv_warn_[]_AC_LANG_ABBREV[]_$1])dnl
AS_VAR_PUSHDEF([gl_Flags], [_AC_LANG_PREFIX[]FLAGS])dnl
AS_LITERAL_IF([$1],
  [m4_pushdef([gl_Positive], m4_bpatsubst([$1], [^-Wno-], [-W]))],
  [gl_positive="$1"
case $gl_positive in
  -Wno-*) gl_positive=-W`expr "X$gl_positive" : 'X-Wno-\(.*\)'` ;;
esac
m4_pushdef([gl_Positive], [$gl_positive])])dnl
AC_CACHE_CHECK([whether _AC_LANG compiler handles $1], m4_defn([gl_Warn]), [
  gl_save_compiler_FLAGS="$gl_Flags"
  gl_AS_VAR_APPEND(m4_defn([gl_Flags]),
    [" $gl_unknown_warnings_are_errors ]m4_defn([gl_Positive])["])
  AC_LINK_IFELSE([m4_default([$4], [AC_LANG_PROGRAM([])])],
                 [AS_VAR_SET(gl_Warn, [yes])],
                 [AS_VAR_SET(gl_Warn, [no])])
  gl_Flags="$gl_save_compiler_FLAGS"
])
AS_VAR_IF(gl_Warn, [yes], [$2], [$3])
m4_popdef([gl_Positive])dnl
AS_VAR_POPDEF([gl_Flags])dnl
AS_VAR_POPDEF([gl_Warn])dnl
])

# gl_UNKNOWN_WARNINGS_ARE_ERRORS
# ------------------------------
# Clang doesn't complain about unknown warning options unless one also
# specifies -Wunknown-warning-option -Werror.  Detect this.
AC_DEFUN([gl_UNKNOWN_WARNINGS_ARE_ERRORS],
[gl_COMPILER_OPTION_IF([-Werror -Wunknown-warning-option],
   [gl_unknown_warnings_are_errors='-Wunknown-warning-option -Werror'],
   [gl_unknown_warnings_are_errors=])])

# gl_WARN_ADD(OPTION, [VARIABLE = WARN_CFLAGS],
#             [PROGRAM = AC_LANG_PROGRAM()])
# ---------------------------------------------
# Adds parameter to WARN_CFLAGS if the compiler supports it when
# compiling PROGRAM.  For example, gl_WARN_ADD([-Wparentheses]).
#
# If VARIABLE is a variable name, AC_SUBST it.
AC_DEFUN([gl_WARN_ADD],
[AC_REQUIRE([gl_UNKNOWN_WARNINGS_ARE_ERRORS])
gl_COMPILER_OPTION_IF([$1],
  [gl_AS_VAR_APPEND(m4_if([$2], [], [[WARN_CFLAGS]], [[$2]]), [" $1"])],
  [],
  [$3])
m4_ifval([$2],
         [AS_LITERAL_IF([$2], [AC_SUBST([$2])])],
         [AC_SUBST([WARN_CFLAGS])])dnl
])

# Local Variables:
# mode: autoconf
# End:
dnl * clang check
AC_DEFUN([CC_CLANG],[
  AC_MSG_CHECKING([whether $CC is clang 3.3+])
  AS_IF([$CC -dM -E -x c /dev/null | $GREP __clang__ > /dev/null 2>&1], [
      AS_VAR_SET([have_clang], [yes])
      # buffer_t usage triggers this warning
      gl_WARN_ADD([-Wno-default-const-init-field-unsafe])
      AM_CFLAGS="$AM_CFLAGS $WARN_CFLAGS"
  ], [
      AS_VAR_SET([have_clang], [no])
  ])
  AC_MSG_RESULT([$have_clang])
])

AC_DEFUN([CC_STRICT_BOOL], [
  AS_IF([test $have_clang = yes], [
    AC_REQUIRE([gl_UNKNOWN_WARNINGS_ARE_ERRORS])
    gl_COMPILER_OPTION_IF([-Wstrict-bool], [
      AC_DEFINE(HAVE_STRICT_BOOL,, [we have strict bool])
    ])
  ])
])

AC_DEFUN([DOVECOT_WANT_UBSAN], [
  AC_ARG_ENABLE(ubsan,
    AS_HELP_STRING([--enable-ubsan], [Enable undefined behaviour sanitizes (default=no)]),
                   [want_ubsan=yes], [want_ubsan=no])
  AC_MSG_CHECKING([whether we want undefined behaviour sanitizer])
  AC_MSG_RESULT([$want_ubsan])
  AS_IF([test x$want_ubsan = xyes], [
     san_flags=""
     gl_COMPILER_OPTION_IF([-fsanitize=undefined], [
             san_flags="$san_flags -fsanitize=undefined -fno-sanitize=function,vptr"
             AC_DEFINE([HAVE_FSANITIZE_UNDEFINED], [1], [Define if your compiler has -fsanitize=undefined])
     ])
     gl_COMPILER_OPTION_IF([-fno-sanitize=nonnull-attribute], [
             san_flags="$san_flags -fno-sanitize=nonnull-attribute"
             AC_DEFINE([HAVE_FNO_SANITIZE_NONNULL_ATTRIBUTE], [1], [Define if your compiler has -fno-sanitize=nonnull-attribute])
     ])
     gl_COMPILER_OPTION_IF([-fsanitize=implicit-integer-truncation], [
             san_flags="$san_flags -fsanitize=implicit-integer-truncation"
             AC_DEFINE([HAVE_FSANITIZE_IMPLICIT_INTEGER_TRUNCATION], [1], [Define if your compiler has -fsanitize=implicit-integer-truncation])
     ])
     gl_COMPILER_OPTION_IF([-fsanitize=local-bounds], [
             san_flags="$san_flags -fsanitize=local-bounds"
             AC_DEFINE([HAVE_FSANITIZE_LOCAL_BOUNDS], [1], [Define if your compiler has -fsanitize=local-bounds])
     ])
     gl_COMPILER_OPTION_IF([-fsanitize=integer], [
             san_flags="$san_flags -fsanitize=integer"
             AC_DEFINE([HAVE_FSANITIZE_INTEGER], [1], [Define if your compiler has -fsanitize=integer])
     ])
     gl_COMPILER_OPTION_IF([-fsanitize=nullability], [
             san_flags="$san_flags -fsanitize=nullability"
             AC_DEFINE([HAVE_FSANITIZE_NULLABILITY], [1], [Define if your compiler has -fsanitize=nullability])
     ])
     AS_IF([test "$san_flags" != "" ], [
       AM_CFLAGS="$AM_CFLAGS $san_flags -U_FORTIFY_SOURCE -g -ggdb3 -O0 -fno-omit-frame-pointer"
       AC_DEFINE([HAVE_UNDEFINED_SANITIZER], [1], [Define if your compiler supports undefined sanitizers])
     ], [
       AC_MSG_ERROR([No undefined sanitizer support in your compiler])
     ])
     san_flags=""
  ])
])
