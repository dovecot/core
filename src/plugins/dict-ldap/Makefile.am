AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-ldap \
	-I$(top_srcdir)/src/lib-settings

LIBDICT_LDAP = libdict_ldap.la
libdict_ldap_la_DEPENDENCIES = $(LIBDOVECOT_LDAP) $(LIBDOVECOT_DEPS)
libdict_ldap_la_LDFLAGS = -module -avoid-version
libdict_ldap_la_LIBADD = $(LIBDOVECOT_LDAP) $(LIBDOVECOT)

module_dictdir = $(moduledir)/dict
module_dict_LTLIBRARIES = \
	$(LIBDICT_LDAP)

libdict_ldap_la_SOURCES = \
	dict-ldap.c \
	dict-ldap-settings.c

noinst_HEADERS = \
	dict-ldap-settings.h
