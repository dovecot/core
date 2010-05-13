doveadm_moduledir = $(moduledir)/doveadm

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/maildir \
	-I$(top_srcdir)/src/doveadm

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
	quota-maildir.c \
        quota-plugin.c \
	quota-storage.c

lib10_quota_plugin_la_SOURCES = $(quota_dist_sources)
nodist_lib10_quota_plugin_la_SOURCES = $(RQUOTA_XDR)

doveadm_module_LTLIBRARIES = \
	lib10_doveadm_quota_plugin.la

lib10_doveadm_quota_plugin_la_SOURCES = \
	doveadm-quota.c

if HAVE_RQUOTA
RQUOTA_XDR = rquota_xdr.c
#RQUOTA_X = /usr/include/rpcsvc/rquota.x
RQUOTA_X = $(srcdir)/rquota.x
rquota_xdr.c: Makefile $(RQUOTA_X)
	if [ "$(top_srcdir)" != "$(top_builddir)" ]; then \
	  cp $(RQUOTA_X) $(top_builddir)/src/plugins/quota/; \
	fi; \
	(echo '#include "lib.h"'; \
	 echo '#include <rpc/rpc.h>'; \
	 $(RPCGEN) -c $(top_builddir)/src/plugins/quota/rquota.x | \
	  sed -e 's/IXDR_PUT/(void)IXDR_PUT/g' \
	    -e 's,/usr/include/rpcsvc/rquota.h,rquota.h,' \
	    -e 's/int32_t \*buf/int32_t *buf ATTR_UNUSED/' \
	    -e 's/^static char rcsid.*//' ) > rquota_xdr.c

rquota.h: Makefile $(RQUOTA_X)
	$(RPCGEN) -h $(RQUOTA_X) > rquota.h

quota-fs.lo: rquota.h

endif

noinst_HEADERS = \
	quota.h \
	quota-fs.h \
	quota-plugin.h \
	quota-private.h

EXTRA_DIST = rquota.x

clean-generic:
	if [ "$(top_srcdir)" != "$(top_builddir)" ]; then \
	  rm -f $(top_builddir)/src/plugins/quota/rquota.x; \
	fi; \
	rm -f rquota_xdr.c rquota.h
