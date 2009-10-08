pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = \
	rawlog \
	gdbhelper \
	idxview \
	imap-utf7 \
	listview \
	logview \
	mailboxlogview \
	maildirlock \
	threadview

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
	-DPKG_RUNDIR=\""$(rundir)"\"

rawlog_LDADD = $(LIBDOVECOT)
rawlog_DEPENDENCIES = $(LIBDOVECOT)
rawlog_SOURCES = \
	rawlog.c

gdbhelper_LDADD = $(LIBDOVECOT)
gdbhelper_DEPENDENCIES = $(LIBDOVECOT)
gdbhelper_SOURCES = \
	gdbhelper.c

idxview_LDADD = $(LIBDOVECOT_STORAGE) $(LIBDOVECOT)
idxview_DEPENDENCIES = $(LIBDOVECOT_STORAGE) $(LIBDOVECOT)
idxview_SOURCES = \
	idxview.c

imap_utf7_LDADD = $(LIBDOVECOT)
imap_utf7_DEPENDENCIES = $(LIBDOVECOT)
imap_utf7_SOURCES = \
	imap-utf7.c

listview_LDADD = $(LIBDOVECOT)
listview_DEPENDENCIES = $(LIBDOVECOT)
listview_SOURCES = \
	listview.c

logview_LDADD = $(LIBDOVECOT)
logview_DEPENDENCIES = $(LIBDOVECOT)
logview_SOURCES = \
	logview.c

mailboxlogview_LDADD = $(LIBDOVECOT)
mailboxlogview_DEPENDENCIES = $(LIBDOVECOT)
mailboxlogview_SOURCES = \
	mailboxlogview.c

maildirlock_LDADD = $(LIBDOVECOT)
maildirlock_DEPENDENCIES = $(LIBDOVECOT)
maildirlock_SOURCES = \
	maildirlock.c

threadview_LDADD = $(LIBDOVECOT)
threadview_DEPENDENCIES = $(LIBDOVECOT)
threadview_SOURCES = \
	threadview.c
