pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = rawlog gdbhelper idxview listview logview
sbin_PROGRAMS = dovecotpw

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/auth

rawlog_LDADD = \
	../lib/liblib.a

rawlog_SOURCES = \
	rawlog.c

gdbhelper_LDADD = \
	../lib/liblib.a

gdbhelper_SOURCES = \
	gdbhelper.c

idxview_LDADD = \
	../lib/liblib.a

idxview_SOURCES = \
	idxview.c

listview_LDADD = \
	../lib/liblib.a

listview_SOURCES = \
	listview.c

logview_LDADD = \
	../lib/liblib.a

logview_SOURCES = \
	logview.c

dovecotpw_LDADD = \
	../auth/libpassword.a \
	../lib-ntlm/libntlm.a \
	../lib-otp/libotp.a \
	../lib/liblib.a \
	$(AUTH_LIBS) \
	$(RAND_LIBS) \
	$(MODULE_LIBS)

dovecotpw_SOURCES = \
	dovecotpw.c
