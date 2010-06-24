pkglibexecdir = $(libexecdir)/dovecot
exampledir = $(docdir)/example-config

bin_PROGRAMS = doveconf
pkglibexec_PROGRAMS = config

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	-DEXAMPLE_CONFIG_DIR=\""$(exampledir)"\" \
	-DMODULEDIR=\""$(moduledir)"\" \
	-DSSLDIR=\""$(ssldir)\""

config_LDADD = \
	$(LIBDOVECOT) \
	$(MODULE_LIBS) \
	$(RAND_LIBS)
config_DEPENDENCIES = $(LIBDOVECOT_DEPS)

doveconf_LDADD = \
	$(LIBDOVECOT) \
	$(MODULE_LIBS) \
	$(RAND_LIBS)
doveconf_DEPENDENCIES = $(LIBDOVECOT_DEPS)

common = \
	all-settings.c \
	config-connection.c \
	config-filter.c \
	config-parser.c \
	config-request.c \
	old-set-parser.c \
	sysinfo-get.c

config_SOURCES = \
	main.c \
	$(common)

doveconf_SOURCES = \
	doveconf.c \
	$(common)

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
	$(top_srcdir)/src/config/settings-get.pl $(SETTING_FILES) > all-settings.c || rm -f all-settings.c

EXTRA_DIST = \
	config-settings.c \
	settings-get.pl
