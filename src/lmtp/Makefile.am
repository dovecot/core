pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = lmtp

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-lda \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/raw

lmtp_LDFLAGS = -export-dynamic

libs = \
	../lib-lda/liblda.a \
	$(LIBDOVECOT_STORAGE)

lmtp_LDADD = $(libs) $(LIBDOVECOT) $(MODULE_LIBS)
lmtp_DEPENDENCIES = $(libs) $(LIBDOVECOT_DEPS)

lmtp_SOURCES = \
	main.c \
	client.c \
	commands.c \
	lmtp-proxy.c \
	lmtp-settings.c

noinst_HEADERS = \
	main.h \
	client.h \
	commands.h \
	lmtp-proxy.h \
	lmtp-settings.h
