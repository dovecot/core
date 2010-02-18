# dovecot.m4 - Check presence of dovecot -*-Autoconf-*-
#
#   Copyright (C) 2010 Dennis Schridde
#
# This file is free software; the authors give
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.

AC_DEFUN([DC_PLUGIN_DEPS],[
	_plugin_deps=yes
	AC_MSG_CHECKING([whether OS supports plugin dependencies])
	AS_CASE([$host_os],
		[darwin*],[
			# OSX loads the plugins twice, which breaks stuff
			_plugin_deps=no
		]
	)
	AC_MSG_RESULT([$_plugin_deps])
	AM_CONDITIONAL([DOVECOT_PLUGIN_DEPS], [test "x$_plugin_deps" = "xyes"])
	AS_UNSET([_plugin_deps])
])

# Substitute every var in the given comma seperated list
AC_DEFUN([AX_SUBST_L],[
	m4_foreach([__var__], [$@], [AC_SUBST(__var__)])
])

AC_DEFUN([DC_DOVECOT],[
	AC_ARG_WITH(dovecot,
		AS_HELP_STRING([--with-dovecot=DIR],[Dovecot base directory [LIBDIR/dovecot]]),
			[ dovecotdir="$withval" ], [ dovecotdir="${libdir}"/dovecot ]
	)

	AC_MSG_CHECKING([for dovecot-config in "$dovecotdir"])
	AS_IF([test -f "$dovecotdir/dovecot-config"],[
		AC_MSG_RESULT([$dovecotdir/dovecot-config])
	],[
		AC_MSG_RESULT([not found])
		AC_MSG_NOTICE([])
		AC_MSG_NOTICE([Use --with-dovecot=DIR to provide the path to the dovecot-config file.])
		AC_MSG_ERROR([dovecot-config not found])
	])

	eval `grep \
		-e ^dovecot_[[a-z]]*= \
		-e ^LIBDOVECOT[[A-Z_]]*= \
		"$dovecotdir"/dovecot-config`
	AX_SUBST_L([dovecot_moduledir], [dovecot_pkgincludedir], [dovecot_pkglibexecdir], [dovecot_pkglibdir], [dovecot_docdir])
	AX_SUBST_L([LIBDOVECOT], [LIBDOVECOT_LOGIN], [LIBDOVECOT_SQL], [LIBDOVECOT_STORAGE])
	AX_SUBST_L([LIBDOVECOT_DEPS], [LIBDOVECOT_LOGIN_DEPS], [LIBDOVECOT_SQL_DEPS], [LIBDOVECOT_STORAGE_DEPS])
	AX_SUBST_L([LIBDOVECOT_INCLUDE], [LIBDOVECOT_LDA_INCLUDE], [LIBDOVECOT_SERVICE_INCLUDE], [LIBDOVECOT_STORAGE_INCLUDE], [LIBDOVECOT_LOGIN_INCLUDE])

	_cppflags=$CPPFLAGS
	CPPFLAGS=$LIBDOVECOT_INCLUDE
	AC_MSG_CHECKING([dovecot version])
	AC_RUN_IFELSE([
		AC_LANG_PROGRAM([[
			/* needed for dovecot to include its own config.h ... */
			#define HAVE_CONFIG_H
			#include "lib.h"
			#include <stdlib.h>
			#include <stdio.h>
		]],[[
			printf("%s\n", DOVECOT_VERSION);
		]])
	],[
		DOVECOT_VERSION=`./conftest$EXEEXT`
	],[
		AC_MSG_FAILURE([unable to determine dovecot version])
	])
	AC_SUBST([DOVECOT_VERSION])
	CPPFLAGS=$_cppflags
	AS_UNSET([_cppflags])

	m4_foreach_w([__flag__],[$1],[
		# Inside m4_foreach __flag__ is a variable!
		# This expands *entirely* for every flag in the argument list!
		AS_CASE([__flag__],
			[
				# assume an unknown flag is a version number
				AC_MSG_CHECKING([whether dovecot is newer than __flag__])
				AS_VERSION_COMPARE([$DOVECOT_VERSION],[__flag__],[
					AC_MSG_RESULT([no])
					AC_MSG_ERROR([at least dovecot-flag is required, your version seems older])
				],[
					AC_MSG_RESULT([yes])
				],[
					AC_MSG_RESULT([yes])
				])
		])
	])

	DC_PLUGIN_DEPS
])
