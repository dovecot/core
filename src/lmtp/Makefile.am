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

if !BUILD_SHARED_LIBS
unused_objects = \
	../lib/mountpoint.o \
	../lib-mail/message-header-encode.o \
	../lib-imap/imap-util.o \
	../lib-storage/mail-search-parser-imap.o \
	../lib-lda/smtp-client.o \
	../lib-lda/mail-send.o
endif

libs = \
	$(unused_objects) \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT_LDA)

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
