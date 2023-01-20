SUBDIRS = list index

noinst_LTLIBRARIES = libstorage.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-auth-client \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-sasl \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-fs \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-charset \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-smtp \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DMODULEDIR=\""$(moduledir)"\"

libstorage_la_SOURCES = \
	fail-mail-storage.c \
	fail-mailbox.c \
	fail-mail.c \
	mail.c \
	mail-autoexpunge.c \
	mail-copy.c \
	mail-duplicate.c \
	mail-error.c \
	mail-namespace.c \
	mail-search.c \
	mail-search-args-cmdline.c \
	mail-search-args-imap.c \
	mail-search-args-simplify.c \
	mail-search-build.c \
	mail-search-mime.c \
	mail-search-mime-build.c \
	mail-search-mime-register.c \
	mail-search-parser.c \
	mail-search-parser-imap.c \
	mail-search-parser-cmdline.c \
	mail-search-register.c \
	mail-search-register-human.c \
	mail-search-register-imap.c \
	mail-storage.c \
	mail-storage-hooks.c \
	mail-storage-register.c \
	mail-storage-service.c \
	mail-storage-settings.c \
	mail-thread.c \
	mail-user.c \
	mailbox-attribute.c \
	mailbox-attribute-internal.c \
	mailbox-get.c \
	mailbox-guid-cache.c \
	mailbox-header.c \
	mailbox-keywords.c \
	mailbox-list.c \
	mailbox-list-notify.c \
	mailbox-list-register.c \
	mailbox-match-plugin.c \
	mailbox-recent-flags.c \
	mailbox-search-result.c \
	mailbox-tree.c \
	mailbox-uidvalidity.c \
	mailbox-watch.c \
	test-mail-storage-common.c

headers = \
	fail-mail-storage.h \
	mail-autoexpunge.h \
	mail-copy.h \
	mail-duplicate.h \
	mail-error.h \
	mail-namespace.h \
	mail-search.h \
	mail-search-build.h \
	mail-search-mime.h \
	mail-search-mime-build.h \
	mail-search-mime-register.h \
	mail-search-register.h \
	mail-thread.h \
	mail-storage.h \
	mail-search-parser.h \
	mail-search-parser-private.h \
	mail-storage-private.h \
	mail-storage-hooks.h \
	mail-storage-service.h \
	mail-storage-settings.h \
	mail-user.h \
	mailbox-attribute.h \
	mailbox-attribute-internal.h \
	mailbox-attribute-private.h \
	mailbox-guid-cache.h \
	mailbox-list.h \
	mailbox-list-iter.h \
	mailbox-list-private.h \
	mailbox-list-notify.h \
	mailbox-match-plugin.h \
	mailbox-recent-flags.h \
	mailbox-search-result-private.h \
	mailbox-tree.h \
	mailbox-uidvalidity.h \
	mailbox-watch.h \
	test-mail-storage-common.h

shlibs = \
	index/shared/libstorage_shared.la \
	index/dbox-multi/libstorage_dbox_multi.la \
	index/dbox-single/libstorage_dbox_single.la \
	index/dbox-common/libstorage_dbox_common.la \
	index/maildir/libstorage_maildir.la \
	index/mbox/libstorage_mbox.la \
	index/imapc/libstorage_imapc.la \
	../lib-imap-client/libimap_client.la \
	index/pop3c/libstorage_pop3c.la \
	index/raw/libstorage_raw.la \
	list/libstorage_list.la \
	index/libstorage_index.la \
	../lib-index/libindex.la \
	../lib-imap-storage/libimap-storage.la

libstorage_la_LIBADD = $(shlibs)
libstorage_la_DEPENDENCIES = $(shlibs)

pkglib_LTLIBRARIES = libdovecot-storage.la
libdovecot_storage_la_SOURCES =
libdovecot_storage_la_LIBADD = \
	libstorage.la \
	../lib-dovecot/libdovecot.la \
	$(LINKED_STORAGE_LDADD)
libdovecot_storage_la_DEPENDENCIES = \
	libstorage.la \
	../lib-dovecot/libdovecot.la \
	$(LIBDOVECOT_DEPS)
libdovecot_storage_la_LDFLAGS = -export-dynamic

if HAVE_LUA
pkglib_LTLIBRARIES += libdovecot-storage-lua.la
libdovecot_storage_lua_la_SOURCES = \
	mail-lua.c \
	mail-user-lua.c \
	mail-storage-lua.c \
	mailbox-lua.c \
	mailbox-attribute-lua.c
libdovecot_storage_lua_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(LUA_CFLAGS) \
	-I$(top_srcdir)/src/lib-lua
libdovecot_storage_lua_la_LIBADD = \
	libdovecot-storage.la \
	../lib-lua/libdovecot-lua.la
libdovecot_storage_lua_la_DEPENDENCIES = \
	libdovecot-storage.la \
	../lib-lua/libdovecot-lua.la
libdovecot_storage_lua_la_LDFLAGS = -export-dynamic

headers += \
	mail-storage-lua.h \
	mail-storage-lua-private.h
endif

test_programs = \
	test-mail-search-args-imap \
	test-mail-search-args-simplify \
	test-mail \
	test-mail-storage \
	test-mailbox-get \
	test-mailbox-list

noinst_PROGRAMS = $(test_programs)

test_libs = \
	$(top_builddir)/src/lib-test/libtest.la \
	$(top_builddir)/src/lib/liblib.la

test_mail_search_args_imap_SOURCES = test-mail-search-args-imap.c
test_mail_search_args_imap_LDADD = libstorage.la $(LIBDOVECOT)
test_mail_search_args_imap_DEPENDENCIES = libstorage.la $(LIBDOVECOT_DEPS)

test_mail_search_args_simplify_SOURCES = test-mail-search-args-simplify.c
test_mail_search_args_simplify_LDADD = libstorage.la $(LIBDOVECOT)
test_mail_search_args_simplify_DEPENDENCIES = libstorage.la $(LIBDOVECOT_DEPS)

test_mailbox_get_SOURCES = test-mailbox-get.c
test_mailbox_get_LDADD = mailbox-get.lo $(test_libs)
test_mailbox_get_DEPENDENCIES = $(noinst_LTLIBRARIES) $(test_libs)

test_mail_SOURCES = test-mail.c
test_mail_LDADD = libstorage.la $(LIBDOVECOT)
test_mail_DEPENDENCIES = libstorage.la $(LIBDOVECOT_DEPS)

test_mail_storage_SOURCES = test-mail-storage.c
test_mail_storage_LDADD = libstorage.la $(LIBDOVECOT)
test_mail_storage_DEPENDENCIES = libstorage.la $(LIBDOVECOT_DEPS)

test_mailbox_list_SOURCES = test-mailbox-list.c
test_mailbox_list_LDADD = libstorage.la $(LIBDOVECOT)
test_mailbox_list_DEPENDENCIES = libstorage.la $(LIBDOVECOT_DEPS)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
noinst_HEADERS = $(test_headers)
