pkglibexecdir = $(libexecdir)/dovecot

sbin_PROGRAMS = dovecot

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DPKG_STATEDIR=\""$(statedir)"\" \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	-DBINDIR=\""$(bindir)"\"

libs = \
	$(LIBCAP) \
	$(LIBDOVECOT)

dovecot_LDADD = $(libs)
dovecot_DEPENDENCIES = $(libs)

dovecot_SOURCES = \
	capabilities-posix.c \
	dup2-array.c \
	main.c \
	master-settings.c \
	service-anvil.c \
	service-auth-server.c \
	service-auth-source.c \
	service-listen.c \
	service-log.c \
	service-monitor.c \
	service-process.c \
	service-process-notify.c \
	service.c

noinst_HEADERS = \
	capabilities.h \
	common.h \
	dup2-array.h \
	master-settings.h \
	service-anvil.h \
	service-auth-server.h \
	service-auth-source.h \
	service-listen.h \
	service-log.h \
	service-monitor.h \
	service-process.h \
	service-process-notify.h \
	service.h
