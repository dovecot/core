pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = \
	rawlog \
	script \
	gdbhelper \
	imap-utf7 \
	listview \
	maildirlock

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/auth \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	-DPKG_RUNDIR=\""$(rundir)"\"

rawlog_LDADD = $(LIBDOVECOT)
rawlog_DEPENDENCIES = $(LIBDOVECOT_DEPS)
rawlog_SOURCES = \
	rawlog.c

script_LDADD = $(LIBDOVECOT)
script_DEPENDENCIES = $(LIBDOVECOT_DEPS)
script_SOURCES = \
	script.c

gdbhelper_LDADD = $(LIBDOVECOT)
gdbhelper_DEPENDENCIES = $(LIBDOVECOT_DEPS)
gdbhelper_SOURCES = \
	gdbhelper.c

imap_utf7_LDADD = $(LIBDOVECOT)
imap_utf7_DEPENDENCIES = $(LIBDOVECOT_DEPS)
imap_utf7_SOURCES = \
	imap-utf7.c

listview_LDADD = $(LIBDOVECOT)
listview_DEPENDENCIES = $(LIBDOVECOT_DEPS)
listview_SOURCES = \
	listview.c

maildirlock_LDADD = $(LIBDOVECOT)
maildirlock_DEPENDENCIES = $(LIBDOVECOT_DEPS)
maildirlock_SOURCES = \
	maildirlock.c
