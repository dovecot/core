noinst_LTLIBRARIES = libpassword.la libauth.la
auth_moduledir = $(moduledir)/auth

# automake seems to force making this unconditional..
NOPLUGIN_LDFLAGS =

if GSSAPI_PLUGIN
GSSAPI_LIB = libmech_gssapi.la
endif

if LDAP_PLUGIN
LDAP_LIB = libauthdb_ldap.la
endif

auth_module_LTLIBRARIES = \
	$(GSSAPI_LIB) \
	$(LDAP_LIB) \
	$(LUA_LIB) \
	libauthdb_imap.la

pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = auth checkpassword-reply

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-http \
	-I$(top_srcdir)/src/lib-sql \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-old-stats \
	-I$(top_srcdir)/src/lib-ntlm \
	-I$(top_srcdir)/src/lib-otp \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-oauth2 \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-lua \
	-I$(top_srcdir)/src/lib-dcrypt \
	-DAUTH_MODULE_DIR=\""$(auth_moduledir)"\" \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)/dovecot"\" \
	$(LUA_CFLAGS) \
	$(AUTH_CFLAGS)

auth_LDFLAGS = -export-dynamic

libpassword_la_SOURCES = \
	crypt-blowfish.c \
	mycrypt.c \
	password-scheme.c \
	password-scheme-crypt.c \
	password-scheme-md5crypt.c \
	password-scheme-scram.c \
	password-scheme-otp.c \
	password-scheme-rpa.c \
	password-scheme-pbkdf2.c \
	password-scheme-sodium.c
libpassword_la_CFLAGS = $(AM_CPPFLAGS) $(LIBSODIUM_CFLAGS)

if HAVE_LUA
if AUTH_LUA_PLUGIN
LUA_LIB = libauthdb_lua.la
else !AUTH_LUA_PLUGIN
LIBDOVECOT_LUA = ../lib-lua/libdovecot-lua.la
endif !AUTH_LUA_PLUGIN
endif

auth_libs = \
	libauth.la \
	libstats_auth.la \
	libpassword.la \
	../lib-ntlm/libntlm.la \
	../lib-otp/libotp.la \
	$(LIBDOVECOT_LUA) \
	$(LIBDOVECOT_SQL)

auth_CPPFLAGS = $(AM_CPPFLAGS) $(BINARY_CFLAGS)
auth_LDADD = $(auth_libs) $(LIBDOVECOT) $(AUTH_LIBS) $(BINARY_LDFLAGS)
auth_DEPENDENCIES = $(auth_libs) $(LIBDOVECOT_DEPS)
auth_SOURCES = main.c

ldap_sources = db-ldap.c passdb-ldap.c userdb-ldap.c
lua_sources = db-lua.c passdb-lua.c userdb-lua.c

libauth_la_DEPENDENCIES = $(LIBDOVECOT_DEPS)
libauth_la_SOURCES = \
	auth.c \
	auth-cache.c \
	auth-client-connection.c \
	auth-master-connection.c \
	auth-policy.c \
	mech-otp-skey-common.c \
	mech-plain-common.c \
	auth-penalty.c \
	auth-request.c \
	auth-request-handler.c \
	auth-request-stats.c \
	auth-request-var-expand.c \
	auth-settings.c \
	auth-fields.c \
	auth-token.c \
	auth-worker-client.c \
	auth-worker-server.c \
	db-checkpassword.c \
	db-dict.c \
	db-dict-cache-key.c \
	db-oauth2.c \
	db-sql.c \
	db-passwd-file.c \
	mech.c \
	mech-anonymous.c \
	mech-plain.c \
	mech-login.c \
	mech-cram-md5.c \
	mech-digest-md5.c \
	mech-external.c \
	mech-gssapi.c \
	mech-ntlm.c \
	mech-otp.c \
	mech-scram.c \
	mech-skey.c \
	mech-rpa.c \
	mech-apop.c \
	mech-winbind.c \
	mech-dovecot-token.c \
	mech-oauth2.c \
	passdb.c \
	passdb-blocking.c \
	passdb-bsdauth.c \
	passdb-cache.c \
	passdb-checkpassword.c \
	passdb-dict.c \
	passdb-oauth2.c \
	passdb-passwd.c \
	passdb-passwd-file.c \
	passdb-pam.c \
	passdb-shadow.c \
	passdb-sia.c \
	passdb-vpopmail.c \
	passdb-sql.c \
	passdb-static.c \
	passdb-template.c \
	userdb.c \
	userdb-blocking.c \
	userdb-checkpassword.c \
	userdb-dict.c \
	userdb-passwd.c \
	userdb-passwd-file.c \
	userdb-prefetch.c \
	userdb-static.c \
	userdb-vpopmail.c \
	userdb-sql.c \
	userdb-template.c \
	$(ldap_sources) \
	$(lua_sources)

headers = \
	auth.h \
	auth-cache.h \
	auth-client-connection.h \
	auth-common.h \
	auth-master-connection.h \
	mech-otp-skey-common.h \
	mech-plain-common.h \
	mech-scram.h \
	auth-penalty.h \
	auth-policy.h \
	auth-request.h \
	auth-request-handler.h \
	auth-request-handler-private.h \
	auth-request-stats.h \
	auth-request-var-expand.h \
	auth-settings.h \
	auth-stats.h \
	auth-fields.h \
	auth-token.h \
	auth-worker-client.h \
	auth-worker-server.h \
	db-dict.h \
	db-ldap.h \
	db-sql.h \
	db-passwd-file.h \
	db-checkpassword.h \
	db-oauth2.h \
	mech.h \
	mycrypt.h \
	passdb.h \
	passdb-blocking.h \
	passdb-cache.h \
	passdb-template.h \
	password-scheme.h \
	userdb.h \
	userdb-blocking.h \
	userdb-template.h \
	userdb-vpopmail.h

if GSSAPI_PLUGIN
libmech_gssapi_la_LDFLAGS = -module -avoid-version
libmech_gssapi_la_LIBADD = $(KRB5_LIBS)
libmech_gssapi_la_CPPFLAGS = $(AM_CPPFLAGS) $(KRB5_CFLAGS) -DPLUGIN_BUILD
libmech_gssapi_la_SOURCES = mech-gssapi.c
endif

if LDAP_PLUGIN
libauthdb_ldap_la_LDFLAGS = -module -avoid-version
libauthdb_ldap_la_LIBADD = $(LDAP_LIBS)
libauthdb_ldap_la_CPPFLAGS = $(AM_CPPFLAGS) -DPLUGIN_BUILD
libauthdb_ldap_la_SOURCES = $(ldap_sources)
endif

if AUTH_LUA_PLUGIN
libauthdb_lua_la_LDFLAGS = -module -avoid-version
libauthdb_lua_la_LIBADD = ../lib-lua/libdovecot-lua.la $(LUA_LIBS)
libauthdb_lua_la_CPPFLAGS = $(AM_CPPFLAGS) -DPLUGIN_BUILD
libauthdb_lua_la_SOURCES = $(lua_sources)
endif

libauthdb_imap_la_LDFLAGS = -module -avoid-version
libauthdb_imap_la_LIBADD = \
	../lib-imap-client/libimap_client.la \
	$(LIBDOVECOT)
libauthdb_imap_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-imap-client
libauthdb_imap_la_SOURCES = passdb-imap.c

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

checkpassword_reply_CPPFLAGS = $(AM_CPPFLAGS) $(BINARY_CFLAGS)
checkpassword_reply_LDADD = $(LIBDOVECOT) $(BINARY_LDFLAGS)
checkpassword_reply_DEPENDENCIES = $(LIBDOVECOT_DEPS)

checkpassword_reply_sources = \
	checkpassword-reply.c

stats_moduledir = $(moduledir)/old-stats
stats_module_LTLIBRARIES = libstats_auth.la

libstats_auth_la_LDFLAGS = -module -avoid-version
libstats_auth_la_LIBADD = $(LIBDOVECOT)
libstats_auth_la_DEPENDENCIES = $(LIBDOVECOT_DEPS)
libstats_auth_la_SOURCES = auth-stats.c

test_programs = \
	test-libpassword \
	test-auth-cache \
	test-auth

noinst_PROGRAMS = $(test_programs)

noinst_HEADERS = test-auth.h crypt-blowfish.h db-lua.h

test_libs = \
	../lib-dovecot/libdovecot.la

test_libpassword_SOURCES = test-libpassword.c
test_libpassword_LDADD = \
	libpassword.la \
	../lib-ntlm/libntlm.la \
        ../lib-otp/libotp.la \
	$(CRYPT_LIBS) \
	$(LIBDOVECOT_SQL) \
	$(LIBSODIUM_LIBS) \
	$(test_libs) \
	$(BINARY_LDFLAGS)

test_libpassword_DEPENDENCIES = libpassword.la
test_libpassword_CPPFLAGS = $(AM_CPPFLAGS) $(BINARY_CFLAGS)

test_auth_cache_SOURCES = auth-cache.c test-auth-cache.c
test_auth_cache_LDADD = $(test_libs)
test_auth_cache_DEPENDENCIES = $(pkglibexec_PROGRAMS) $(test_libs)
# this is needed to force auth-cache.c recompilation
test_auth_cache_CPPFLAGS = $(AM_CPPFLAGS)

test_auth_SOURCES = \
	test-auth-request-var-expand.c \
	test-username-filter.c \
	test-db-dict.c \
	test-lua.c \
	test-mock.c \
	test-main.c

test_auth_LDADD = $(test_libs) $(auth_libs) $(AUTH_LIBS)
test_auth_DEPENDENCIES = $(pkglibexec_PROGRAMS) $(test_libs)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
