pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = rawlog
sbin_PROGRAMS = dovecotpw

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/auth

rawlog_LDADD = \
	../lib/liblib.a

rawlog_SOURCES = \
	rawlog.c

dovecotpw_LDADD = \
	../auth/libpassword.a \
	../lib-ntlm/libntlm.a \
	../lib/liblib.a \
	$(AUTH_LIBS) \
	$(RAND_LIBS) \
	$(MODULE_LIBS)

dovecotpw_SOURCES = \
	dovecotpw.c
