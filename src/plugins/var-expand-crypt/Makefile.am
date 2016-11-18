AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-dcrypt

NOPLUGIN_LDFLAGS =
lib20_var_expand_crypt_la_LDFLAGS = -module -avoid-version

auth_moduledir = $(moduledir)/auth

module_LTLIBRARIES = \
	lib20_var_expand_crypt.la

auth_module_LTLIBRARIES = \
	lib20_auth_var_expand_crypt.la

lib20_auth_var_expand_crypt_la_SOURCES = \
	var-expand-crypt-plugin.c

lib20_var_expand_crypt_la_SOURCES = \
	var-expand-crypt-plugin.c
