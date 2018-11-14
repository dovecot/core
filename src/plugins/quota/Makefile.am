doveadm_moduledir = $(moduledir)/doveadm

pkglibexecdir = $(libexecdir)/dovecot
pkglibexec_PROGRAMS = quota-status

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-smtp \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-imap-client \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/imapc \
	-I$(top_srcdir)/src/lib-storage/index/maildir \
	-I$(top_srcdir)/src/lib-program-client \
	-I$(top_srcdir)/src/doveadm \
	$(LIBTIRPC_CFLAGS)

NOPLUGIN_LDFLAGS =
lib10_doveadm_quota_plugin_la_LDFLAGS = -module -avoid-version
lib10_quota_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib10_quota_plugin.la

quota_dist_sources = \
	quota.c \
	quota-count.c \
	quota-fs.c \
	quota-dict.c \
	quota-dirsize.c \
	quota-imapc.c \
	quota-maildir.c \
        quota-plugin.c \
	quota-storage.c \
	quota-util.c

quota_common_objects = \
	quota.lo \
	quota-count.lo \
	quota-fs.lo \
	quota-dict.lo \
	quota-dirsize.lo \
	quota-imapc.lo \
	quota-maildir.lo \
        quota-plugin.lo \
	quota-storage.lo \
	quota-util.lo \
	$(RQUOTA_XDR_LO)

lib10_quota_plugin_la_SOURCES = $(quota_dist_sources)
nodist_lib10_quota_plugin_la_SOURCES = $(RQUOTA_XDR)
lib10_quota_plugin_la_LIBADD = $(QUOTA_LIBS)

doveadm_module_LTLIBRARIES = \
	lib10_doveadm_quota_plugin.la

lib10_doveadm_quota_plugin_la_SOURCES = \
	doveadm-quota.c

quota_status_SOURCES = \
	quota-status.c \
	quota-status-settings.c

quota_status_CPPFLAGS = $(AM_CPPFLAGS) $(BINARY_CFLAGS)
quota_status_LDADD = \
	$(quota_common_objects) \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT) \
	$(QUOTA_LIBS) \
	$(BINARY_LDFLAGS)
quota_status_DEPENDENCIES = \
	$(quota_common_objects) \
	$(LIBDOVECOT_STORAGE_DEPS) \
	$(LIBDOVECOT_DEPS)

if HAVE_RQUOTA
RQUOTA_XDR = rquota_xdr.c
RQUOTA_XDR_LO = rquota_xdr.lo
#RQUOTA_X = /usr/include/rpcsvc/rquota.x
RQUOTA_X = $(srcdir)/rquota.x
rquota_xdr.c: Makefile rquota.h
	if [ "$(top_srcdir)" != "$(top_builddir)" ]; then \
	  cp $(RQUOTA_X) $(top_builddir)/src/plugins/quota/; \
	fi; \
	(echo '#include "lib.h"'; \
	 echo '#undef FALSE'; \
	 echo '#undef TRUE'; \
	 echo '#include <rpc/rpc.h>'; \
	 $(RPCGEN) -c $(top_builddir)/src/plugins/quota/rquota.x | \
	  sed -e 's/IXDR_PUT/(void)IXDR_PUT/g' \
	    -e 's,!xdr_,0 == xdr_,' \
	    -e 's,/usr/include/rpcsvc/rquota.h,rquota.h,' \
	    -e 's/int32_t \*buf/int32_t *buf ATTR_UNUSED/' \
	    -e 's/^static char rcsid.*//' ) > rquota_xdr.c

rquota.h: Makefile $(RQUOTA_X)
	$(RPCGEN) -h $(RQUOTA_X) > rquota.h

quota-fs.lo: rquota.h

endif

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = \
	quota.h \
	quota-fs.h \
	quota-plugin.h \
	quota-private.h
noinst_HEADERS = \
	quota-status-settings.h

EXTRA_DIST = rquota.x

clean-generic:
	if [ "$(top_srcdir)" != "$(top_builddir)" ]; then \
	  rm -f $(top_builddir)/src/plugins/quota/rquota.x; \
	fi; \
	rm -f rquota_xdr.c rquota.h

test_programs = \
	test-quota-util
noinst_PROGRAMS = $(test_programs)

test_libs = \
	../../lib-test/libtest.la \
	../../lib/liblib.la
test_deps = $(noinst_LTLIBRARIES) $(test_libs)

test_quota_util_SOURCES = test-quota-util.c
test_quota_util_LDADD = quota-util.lo $(test_libs)
test_quota_util_DEPENDENCIES = quota-util.lo $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
