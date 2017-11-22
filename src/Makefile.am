if HAVE_LDAP
LIB_LDAP=lib-ldap
endif
if HAVE_LUA
LIB_LUA=lib-lua
endif

LIBDOVECOT_SUBDIRS = \
	lib-test \
	lib \
	lib-settings \
	lib-auth \
	lib-master \
	lib-charset \
	lib-ssl-iostream \
	lib-dcrypt \
	lib-dns \
	lib-dict \
	lib-sasl \
	lib-old-stats \
	lib-http \
	lib-fs \
	lib-mail \
	lib-program-client \
	lib-smtp \
	lib-imap \
	lib-imap-storage \
	lib-oauth2

SUBDIRS = \
	$(LIBDOVECOT_SUBDIRS) \
	lib-dict-extra \
	lib-dovecot \
	$(LIB_LDAP) \
	$(LIB_LUA) \
	lib-fts \
	lib-imap-client \
	lib-imap-urlauth \
	lib-compression \
	lib-index \
	lib-storage \
	lib-sql \
	lib-ntlm \
	lib-otp \
	lib-lda \
	lib-dict-backend \
	anvil \
	auth \
	dict \
	dns \
	indexer \
	ipc \
	master \
	login-common \
	imap-hibernate \
	imap-login \
	imap \
	imap-urlauth \
	pop3-login \
	pop3 \
	submission-login \
	submission \
	lda \
	lmtp \
	log \
	config \
	director \
	replication \
	util \
	doveadm \
	stats \
	old-stats \
	plugins
