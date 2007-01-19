if BUILD_ZLIB
ZLIB = zlib
endif

if BUILD_LUCENE
FTS_LUCENE = fts-lucene
endif

SUBDIRS = \
	acl convert expire fts fts-squat lazy-expunge mail-log \
	quota imap-quota trash \
	$(ZLIB) $(FTS_LUCENE)
