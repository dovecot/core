pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = dovecot-lda

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-lda \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/raw

dovecot_lda_LDFLAGS = -export-dynamic

if !BUILD_SHARED_LIBS
unused_objects = \
	../lib/mountpoint.o \
	../lib-mail/message-header-encode.o \
	../lib-imap/imap-util.o \
	../lib-storage/mail-search-parser-imap.o
endif

libs = \
	$(unused_objects) \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT_LDA)

dovecot_lda_LDADD = $(libs) $(LIBDOVECOT) $(MODULE_LIBS)
dovecot_lda_DEPENDENCIES = $(libs) $(LIBDOVECOT_DEPS)

dovecot_lda_SOURCES = \
	main.c

install-exec-local:
	rm -f $(DESTDIR)$(pkglibexecdir)/deliver
	$(LN_S) dovecot-lda $(DESTDIR)$(pkglibexecdir)/deliver
