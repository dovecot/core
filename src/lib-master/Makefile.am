noinst_LTLIBRARIES = libmaster.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DPKG_RUNDIR=\""$(rundir)"\"

libmaster_la_SOURCES = \
	master-service.c \
	master-service-settings.c \
	syslog-util.c

noinst_HEADERS = \
	master-service.h \
	master-service-private.h \
	master-service-settings.h \
	syslog-util.h
