pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = \
	rawlog \
	script \
	script-login \
	$(TCPWRAP_BIN) \
	gdbhelper \
	maildirlock

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/auth \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	$(BINARY_CFLAGS)

rawlog_LDADD = $(LIBDOVECOT) \
	$(BINARY_LDFLAGS)

rawlog_DEPENDENCIES = $(LIBDOVECOT_DEPS)
rawlog_SOURCES = \
	rawlog.c

script_login_LDADD = \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT) \
	$(BINARY_LDFLAGS)

script_login_DEPENDENCIES = \
	$(LIBDOVECOT_STORAGE_DEPS) \
	$(LIBDOVECOT_DEPS)
script_login_SOURCES = \
	script-login.c

script_LDADD = $(LIBDOVECOT) \
	$(BINARY_LDFLAGS)
script_DEPENDENCIES = $(LIBDOVECOT_DEPS)
script_SOURCES = \
	script.c \
	health-check-settings.c

if TCPWRAPPERS
TCPWRAP_BIN = tcpwrap
tcpwrap_LDADD = $(LIBDOVECOT) $(LIBWRAP_LIBS) \
	$(BINARY_LDFLAGS)

tcpwrap_DEPENDENCIES = $(LIBDOVECOT_DEPS)
tcpwrap_SOURCES = \
	tcpwrap.c \
	tcpwrap-settings.c
endif

gdbhelper_LDADD = $(LIBDOVECOT) \
	$(BINARY_LDFLAGS)

gdbhelper_DEPENDENCIES = $(LIBDOVECOT_DEPS)
gdbhelper_SOURCES = \
	gdbhelper.c

maildirlock_LDADD = $(LIBDOVECOT) \
	$(BINARY_LDFLAGS)

maildirlock_DEPENDENCIES = $(LIBDOVECOT_DEPS)
maildirlock_SOURCES = \
	maildirlock.c

pkglibexec_SCRIPTS = health-check.sh

bin_SCRIPTS = dovecot-sysreport

EXTRA_DIST = $(pkglibexec_SCRIPTS) \
	$(bin_SCRIPTS)