AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/maildir

lib10_quota_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib10_quota_plugin.la

if HAVE_RQUOTA
lib10_quota_plugin_la_LIBADD = \
	-lrpcsvc
endif

lib10_quota_plugin_la_SOURCES = \
	quota.c \
	quota-count.c \
	quota-fs.c \
	quota-dict.c \
	quota-dirsize.c \
	quota-maildir.c \
        quota-plugin.c \
	quota-storage.c

if HAVE_RQUOTA
$(srcdir)/quota-fs.c: rquota_xdr.c

rquota_xdr.c: Makefile
	$(RPCGEN) -c /usr/include/rpcsvc/rquota.x | \
	  sed -e 's/IXDR_PUT/(void)IXDR_PUT/g' \
	    -e 's/int32_t \*buf/int32_t *buf __attr_unused__/' > rquota_xdr.c
endif

noinst_HEADERS = \
	quota.h \
	quota-fs.h \
	quota-plugin.h \
	quota-private.h

install-exec-local:
	for d in imap pop3 lda; do \
	  $(mkdir_p) $(DESTDIR)$(moduledir)/$$d; \
	  rm -f $(DESTDIR)$(moduledir)/$$d/lib10_quota_plugin.so; \
	  $(LN_S) ../lib10_quota_plugin.so $(DESTDIR)$(moduledir)/$$d; \
	done

distclean-generic:
	rm -f Makefile rquota_xdr.c
