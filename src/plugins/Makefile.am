if BUILD_ZLIB_PLUGIN
ZLIB = zlib
endif

if BUILD_LUCENE
FTS_LUCENE = fts-lucene
endif

SUBDIRS = \
	acl convert expire fts fts-squat lazy-expunge mail-log mbox-snarf \
	quota imap-quota trash virtual \
	$(ZLIB) $(FTS_LUCENE)
