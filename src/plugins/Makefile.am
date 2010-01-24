if BUILD_ZLIB_PLUGIN
ZLIB = zlib
endif

if BUILD_LUCENE
FTS_LUCENE = fts-lucene
endif

if BUILD_SOLR
FTS_SOLR = fts-solr
endif

SUBDIRS = \
	acl \
	imap-acl \
	autocreate \
	expire \
	fts \
	fts-squat \
	lazy-expunge \
	listescape \
	mbox-snarf \
	notify \
	mail-log \
	quota \
	imap-quota \
	trash \
	virtual \
	$(ZLIB) \
	$(FTS_LUCENE) \
	$(FTS_SOLR)
