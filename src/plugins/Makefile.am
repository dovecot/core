if BUILD_ZLIB_PLUGIN
ZLIB = zlib imap-zlib
endif

if BUILD_LUCENE
FTS_LUCENE = fts-lucene
endif

if BUILD_SOLR
FTS_SOLR = fts-solr
endif

if HAVE_LDAP
DICT_LDAP = dict-ldap
endif

SUBDIRS = \
	acl \
	imap-acl \
	autocreate \
	expire \
	fts \
	fts-squat \
	last-login \
	lazy-expunge \
	listescape \
	notify \
	push-notification \
	mail-filter \
	mail-log \
	mailbox-alias \
	quota \
	quota-clone \
	imap-quota \
	pop3-migration \
	replication \
	snarf \
	stats \
	imap-stats \
	mail-crypt \
	trash \
	virtual \
	welcome \
	$(ZLIB) \
	$(FTS_LUCENE) \
	$(FTS_SOLR) \
	$(DICT_LDAP) \
	fs-compress
