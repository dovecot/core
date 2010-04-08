pkgsysconfdir = $(sysconfdir)/dovecot

noinst_LTLIBRARIES = libmaster.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DSYSCONFDIR=\""$(pkgsysconfdir)"\" \
	-DBINDIR=\""$(bindir)"\"

libmaster_la_SOURCES = \
	anvil-client.c \
	master-auth.c \
	master-login.c \
	master-login-auth.c \
	master-service.c \
	master-service-settings.c \
	master-service-settings-cache.c \
	syslog-util.c

headers = \
	anvil-client.h \
	master-auth.h \
	master-interface.h \
	master-login.h \
	master-login-auth.h \
	master-service.h \
	master-service-private.h \
	master-service-settings.h \
	master-service-settings-cache.h \
	service-settings.h \
	syslog-util.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
