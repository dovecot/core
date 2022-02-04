pkgsysconfdir = $(sysconfdir)/dovecot
pkglibexecdir = $(libexecdir)/dovecot
exampledir = $(docdir)/example-config

bin_PROGRAMS = doveconf
pkglibexec_PROGRAMS = config

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-pop3 \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DPKG_STATEDIR=\""$(statedir)"\" \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	-DEXAMPLE_CONFIG_DIR=\""$(exampledir)"\" \
	-DMODULEDIR=\""$(moduledir)"\" \
	-DSSLDIR=\""$(ssldir)\"" \
	-DSYSCONFDIR=\""$(pkgsysconfdir)"\" \
	$(BINARY_CFLAGS)

noinst_LTLIBRARIES = libconfig.la

config_LDADD = \
	$(noinst_LTLIBRARIES) \
	$(LIBDOVECOT) \
	$(RAND_LIBS) \
	$(BINARY_LDFLAGS) \
	-lm

config_DEPENDENCIES = $(LIBDOVECOT_DEPS) $(noinst_LTLIBRARIES)

doveconf_LDADD = \
	$(noinst_LTLIBRARIES) \
	$(LIBDOVECOT) \
	$(RAND_LIBS) \
	$(BINARY_LDFLAGS) \
	-lm

doveconf_DEPENDENCIES = $(LIBDOVECOT_DEPS) $(noinst_LTLIBRARIES)

common = \
	config-connection.c \
	config-filter.c \
	config-parser.c \
	config-request.c \
	old-set-parser.c \
	sysinfo-get.c

libconfig_la_SOURCES = $(common)

config_SOURCES = \
	all-settings.c \
	main.c

doveconf_SOURCES = \
	all-settings.c \
	doveconf.c

noinst_HEADERS = \
	all-settings.h \
	config-connection.h \
	old-set-parser.h \
	sysinfo-get.h

pkginclude_HEADERS = \
	config-filter.h \
	config-parser.h \
	config-parser-private.h \
	config-request.h

all-settings.c: $(SETTING_FILES) $(top_srcdir)/src/config/settings-get.pl
	$(AM_V_GEN)$(top_srcdir)/src/config/settings-get.pl $(SETTING_FILES) > all-settings.c || rm -f all-settings.c

EXTRA_DIST = \
	config-settings.c \
	settings-get.pl

test_programs = \
	test-config-parser

noinst_PROGRAMS = $(test_programs)

test_libs = \
	$(noinst_LTLIBRARIES) \
	$(LIBDOVECOT)

test_config_parser_CFLAGS = $(AM_CPPFLAGS)
test_config_parser_SOURCES = test-config-parser.c
test_config_parser_LDADD = $(test_libs)
test_config_parser_DEPENDENCIES = $(LIBDOVECOT_DEPS) $(noinst_LTLIBRARIES)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
