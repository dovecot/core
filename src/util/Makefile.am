pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = rawlog
sbin_PROGRAMS = dovecotpw

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/auth

rawlog_LDADD = \
	../lib/liblib.a

rawlog_SOURCES = \
	rawlog.c

dovecotpw_LDADD = \
	../lib/liblib.a \
	../auth/password-scheme.o \
	../auth/password-scheme-cram-md5.o \
	../auth/password-scheme-md5crypt.o \
	../auth/mycrypt.o \
	$(AUTH_LIBS)

dovecotpw_SOURCES = \
	dovecotpw.c
