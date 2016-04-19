pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = dns-client

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-settings \
	$(BINARY_CFLAGS)

dns_client_LDADD = $(LIBDOVECOT) \
	$(BINARY_LDFLAGS)

dns_client_DEPENDENCIES = $(LIBDOVECOT_DEPS)
dns_client_SOURCES = \
	dns-client.c \
	dns-client-settings.c
