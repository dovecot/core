pkglibexecdir = $(libexecdir)/dovecot

# Refer to comment in imap-urlauth.c for info on what these binaries are for.
pkglibexec_PROGRAMS = imap-urlauth-login imap-urlauth imap-urlauth-worker

# imap-urlauth-login

imap_urlauth_login_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/login-common

imap_urlauth_login_LDADD = \
	$(LIBDOVECOT_LOGIN) \
	$(LIBDOVECOT) \
	$(SSL_LIBS)
imap_urlauth_login_DEPENDENCIES = \
	$(LIBDOVECOT_LOGIN_DEPS) \
	$(LIBDOVECOT_DEPS)

imap_urlauth_login_SOURCES = \
	imap-urlauth-login.c \
	imap-urlauth-login-settings.c

# imap-urlauth

imap_urlauth_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-dict \
	-DPKG_RUNDIR=\""$(rundir)"\"

imap_urlauth_LDFLAGS = -export-dynamic

imap_urlauth_LDADD = $(LIBDOVECOT)
imap_urlauth_DEPENDENCIES = $(LIBDOVECOT_DEPS)

imap_urlauth_SOURCES = \
	imap-urlauth.c \
	imap-urlauth-client.c \
	imap-urlauth-settings.c

# imap-urlauth-worker

imap_urlauth_worker_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/imap \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-imap-storage \
	-I$(top_srcdir)/src/lib-imap-urlauth \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/login-common

imap_urlauth_worker_LDFLAGS = -export-dynamic

urlauth_libs = \
	$(top_builddir)/src/lib-imap-urlauth/libimap-urlauth.la

imap_urlauth_worker_LDADD = $(urlauth_libs) $(LIBDOVECOT_STORAGE) $(LIBDOVECOT)
imap_urlauth_worker_DEPENDENCIES = $(urlauth_libs) $(LIBDOVECOT_STORAGE_DEPS) $(LIBDOVECOT_DEPS)

imap_urlauth_worker_SOURCES = \
	imap-urlauth-worker.c \
	imap-urlauth-worker-settings.c

noinst_HEADERS = \
	imap-urlauth-client.h \
	imap-urlauth-common.h \
	imap-urlauth-settings.h \
	imap-urlauth-login-settings.h \
	imap-urlauth-worker-settings.h

