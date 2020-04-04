pkglibexecdir = $(libexecdir)/dovecot

sbin_PROGRAMS = dovecot
systemd_lib =

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DPKG_STATEDIR=\""$(statedir)"\" \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	-DBINDIR=\""$(bindir)"\" \
	$(BINARY_CFLAGS)

dovecot_LDADD = \
	$(SYSTEMD_LIBS) \
	$(LIBCAP) \
	$(LIBDOVECOT) \
	$(BINARY_LDFLAGS)

dovecot_DEPENDENCIES = $(LIBDOVECOT_DEPS)

dovecot_SOURCES = \
	capabilities-posix.c \
	dup2-array.c \
	main.c \
	master-client.c \
	master-settings.c \
	service-anvil.c \
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
	master-client.h \
	master-settings.h \
	service-anvil.h \
	service-listen.h \
	service-log.h \
	service-monitor.h \
	service-process.h \
	service-process-notify.h \
	service.h
