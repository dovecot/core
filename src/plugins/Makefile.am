if BUILD_ZLIB_PLUGIN
ZLIB = zlib imap-zlib
endif

if BUILD_LUCENE
FTS_LUCENE = fts-lucene
endif

if BUILD_SOLR
FTS_SOLR = fts-solr
endif

if HAVE_APPARMOR
APPARMOR = apparmor
endif

if HAVE_LUA
MAIL_LUA = mail-lua
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
	notify-status \
	push-notification \
	mail-filter \
	mail-log \
	$(MAIL_LUA) \
	mailbox-alias \
	quota \
	quota-clone \
	imap-quota \
	pop3-migration \
	replication \
	snarf \
	old-stats \
	imap-old-stats \
	mail-crypt \
	trash \
	virtual \
	welcome \
	$(ZLIB) \
	$(FTS_LUCENE) \
	$(FTS_SOLR) \
	$(DICT_LDAP) \
	$(APPARMOR) \
	fs-compress \
	var-expand-crypt \
	charset-alias
