pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = ssl-params

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-DPKG_STATEDIR=\""$(statedir)"\"

ssl_params_LDADD = $(LIBDOVECOT) ../lib-ssl-iostream/libssl_iostream.la
ssl_params_DEPENDENCIES = $(LIBDOVECOT_DEPS) ../lib-ssl-iostream/libssl_iostream.la
ssl_params_SOURCES = \
	main.c \
	ssl-params.c \
	ssl-params-settings.c

noinst_HEADERS = \
	ssl-params.h \
	ssl-params-settings.h
