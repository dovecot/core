pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = \
	rawlog \
	script \
	script-login \
	gdbhelper

noinst_PROGRAMS = \
	test-fs

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-fs \
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

test_fs_SOURCES = test-fs.c
test_fs_LDADD = $(LIBDOVECOT) \
	$(BINARY_LDFLAGS)
test_fs_DEPENDENCIES = $(LIBDOVECOT_DEPS)

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

gdbhelper_LDADD = $(LIBDOVECOT) \
	$(BINARY_LDFLAGS)

gdbhelper_DEPENDENCIES = $(LIBDOVECOT_DEPS)
gdbhelper_SOURCES = \
	gdbhelper.c

pkglibexec_SCRIPTS = health-check.sh

bin_SCRIPTS = dovecot-sysreport

EXTRA_DIST = $(pkglibexec_SCRIPTS) \
	$(bin_SCRIPTS)