pkglib_LTLIBRARIES = libdovecot-storage.la
libdovecot_storage_la_SOURCES =
libdovecot_storage_la_LIBADD = \
	../lib-storage/libstorage.la \
	../lib-imap-storage/libimap-storage.la \
	$(LIBDOVECOT) \
	$(LINKED_STORAGE_LDADD)
libdovecot_storage_la_DEPENDENCIES = \
	../lib-storage/libstorage.la \
	../lib-imap-storage/libimap-storage.la \
	$(LIBDOVECOT_DEPS)
libdovecot_storage_la_LDFLAGS = -export-dynamic
