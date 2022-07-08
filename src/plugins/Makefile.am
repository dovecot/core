if BUILD_SOLR
FTS_SOLR = fts-solr
endif

if BUILD_FLATCURVE
FTS_FLATCURVE = fts-flatcurve
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
	fts \
	last-login \
	lazy-expunge \
	listescape \
	notify \
	notify-status \
	push-notification \
	mail-log \
	$(MAIL_LUA) \
	quota \
	quota-clone \
	imap-quota \
	pop3-migration \
	replication \
	mail-compress \
	mail-crypt \
	trash \
	virtual \
	welcome \
	$(FTS_SOLR) \
	$(FTS_FLATCURVE) \
	$(DICT_LDAP) \
	$(APPARMOR) \
	fs-compress \
	var-expand-crypt \
	charset-alias
