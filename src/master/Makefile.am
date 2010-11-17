pkglibexecdir = $(libexecdir)/dovecot

sbin_PROGRAMS = dovecot

if HAVE_SYSTEMD
SYSTEMD_SOURCES = sd-daemon.c
endif


AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DPKG_STATEDIR=\""$(statedir)"\" \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	-DBINDIR=\""$(bindir)"\"

dovecot_LDADD = \
	$(LIBCAP) \
	$(LIBDOVECOT)
dovecot_DEPENDENCIES = $(LIBDOVECOT_DEPS)

dovecot_SOURCES = \
	capabilities-posix.c \
	dup2-array.c \
	main.c \
	master-settings.c \
	service-anvil.c \
	service-listen.c \
	service-log.c \
	service-monitor.c \
	service-process.c \
	service-process-notify.c \
	service.c \
	$(SYSTEMD_SOURCES)

noinst_HEADERS = \
	capabilities.h \
	common.h \
	dup2-array.h \
	master-settings.h \
	sd-daemon.h \
	service-anvil.h \
	service-listen.h \
	service-log.h \
	service-monitor.h \
	service-process.h \
	service-process-notify.h \
	service.h

