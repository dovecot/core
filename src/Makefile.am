if HAVE_LDAP
LIB_LDAP=lib-ldap
endif

if HAVE_DCRYPT
LIB_DCRYPT=lib-dcrypt
endif

LIBDOVECOT_SUBDIRS = \
	lib-test \
	lib \
	lib-settings \
	lib-auth \
	lib-master \
	lib-charset \
	lib-ssl-iostream \
	$(LIB_DCRYPT) \
	lib-dns \
	lib-dict \
	lib-sasl \
	lib-stats \
	lib-http \
	lib-fs \
	lib-mail \
	lib-imap \
	lib-imap-storage

SUBDIRS = \
	$(LIBDOVECOT_SUBDIRS) \
	lib-dict-extra \
	lib-dovecot \
	$(LIB_LDAP) \
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
	lda \
	lmtp \
	log \
	config \
	director \
	replication \
	util \
	doveadm \
	ssl-params \
	stats \
	plugins
