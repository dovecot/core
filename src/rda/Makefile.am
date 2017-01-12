pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = dovecot-rda

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-lda \
	-I$(top_srcdir)/src/lib-smtp \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/raw \
	$(BINARY_CFLAGS)

dovecot_rda_LDFLAGS = -export-dynamic

dovecot_rda_LDADD = \
	$(LIBDOVECOT_LDA) \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT) \
	$(BINARY_LDFLAGS)

dovecot_rda_DEPENDENCIES = \
	$(LIBDOVECOT_LDA) \
	$(LIBDOVECOT_STORAGE_DEPS) \
	$(LIBDOVECOT_DEPS)

dovecot_rda_SOURCES = \
	main.c

install-exec-local:
	rm -f $(DESTDIR)$(pkglibexecdir)/deliver
	$(LN_S) dovecot-rda $(DESTDIR)$(pkglibexecdir)/deliver
