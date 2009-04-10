pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = \
	rawlog \
	gdbhelper \
	idxview \
	imap_utf7 \
	listview \
	logview \
	maildirlock \
	threadview

sbin_PROGRAMS = dovecotpw doveadm

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/auth

rawlog_LDADD = \
	../lib-dovecot/libdovecot.la
rawlog_SOURCES = \
	rawlog.c

gdbhelper_LDADD = \
	../lib-dovecot/libdovecot.la
gdbhelper_SOURCES = \
	gdbhelper.c

idxview_LDADD = \
	../lib-dovecot/libdovecot.la \
	../lib-storage/libdovecot-storage.la
idxview_SOURCES = \
	idxview.c

imap_utf7_LDADD = \
	../lib-dovecot/libdovecot.la
imap_utf7_SOURCES = \
	imap-utf7.c

listview_LDADD = \
	../lib-dovecot/libdovecot.la
listview_SOURCES = \
	listview.c

logview_LDADD = \
	../lib-dovecot/libdovecot.la
logview_SOURCES = \
	logview.c

maildirlock_LDADD = \
	../lib-dovecot/libdovecot.la
maildirlock_SOURCES = \
	maildirlock.c

threadview_LDADD = \
	../lib-dovecot/libdovecot.la
threadview_SOURCES = \
	threadview.c

dovecotpw_LDADD = \
	../auth/libpassword.a \
	../lib-ntlm/libntlm.a \
	../lib-otp/libotp.a \
	../lib-dovecot/libdovecot.la \
	$(AUTH_LIBS)

dovecotpw_SOURCES = \
	dovecotpw.c

doveadm_LDADD = \
	../lib-dovecot/libdovecot.la \
	../lib-storage/libdovecot-storage.la
doveadm_SOURCES = \
	doveadm.c

