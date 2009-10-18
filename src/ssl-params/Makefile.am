pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = ssl-params

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-settings \
	-DPKG_STATEDIR=\""$(statedir)"\"

ssl_params_LDADD = $(LIBDOVECOT) $(SSL_LIBS)
ssl_params_DEPENDENCIES = $(LIBDOVECOT_DEPS)
ssl_params_SOURCES = \
	main.c \
	ssl-params.c \
	ssl-params-openssl.c \
	ssl-params-settings.c

noinst_HEADERS = \
	ssl-params.h \
	ssl-params-settings.h
