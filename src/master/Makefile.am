sbin_PROGRAMS = imap-master

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DPKG_RUNDIR=\""$(localstatedir)/run/$(PACKAGE)"\" \
	-DPKG_LIBDIR=\""$(pkglibdir)"\"

imap_master_LDADD = \
	../lib/liblib.a \
	$(SSL_LIBS)

imap_master_SOURCES = \
	auth-process.c \
	imap-process.c \
	login-process.c \
	main.c \
	settings.c \
	ssl-init.c

noinst_HEADERS = \
	auth-process.h \
	common.h \
	login-process.h \
	master-interface.h \
	settings.h \
	ssl-init.h
