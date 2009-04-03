bin_PROGRAMS = doveconf

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	-DMODULEDIR=\""$(moduledir)"\" \
	-DSSLDIR=\""$(ssldir)\""

doveconf_LDADD = \
	../lib-settings/libsettings.a \
	../lib/liblib.a \
	$(RAND_LIBS)

doveconf_SOURCES = \
	all-settings.c \
	config-connection.c \
	config-parser.c \
	main.c

noinst_HEADERS = \
	all-settings.h \
	common.h \
	config-connection.h \
	config-parser.h

all-settings.c: $(SETTING_FILES) $(top_srcdir)/src/config/settings-get.pl
	$(top_srcdir)/src/config/settings-get.pl $(SETTING_FILES) > all-settings.c || rm -f all-settings.c

EXTRA_DIST = \
	settings-get.pl
