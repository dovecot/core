noinst_LTLIBRARIES = libdict_extra.la

dict_drivers = @dict_drivers@

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-fs \
	-I$(top_srcdir)/src/lib-ldap \
	-I$(top_srcdir)/src/lib-settings

libdict_extra_la_SOURCES = \
	dict-fs.c \
	dict-register.c

NOPLUGIN_LDFLAGS =

if HAVE_LDAP
LIBDICT_LDAP = libdict_ldap.la
endif
libdict_ldap_la_LDFLAGS = -module -avoid-version $(LIBDOVECOT_LDAP)

module_dictdir = $(moduledir)/dict
module_dict_LTLIBRARIES = \
	$(LIBDICT_LDAP)

libdict_ldap_la_SOURCES = \
	dict-ldap.c \
	dict-ldap-settings.c

noinst_HEADERS = \
	dict-ldap-settings.h
