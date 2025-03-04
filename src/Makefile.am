if HAVE_LDAP
LIB_LDAP=lib-ldap
endif
if HAVE_LUA
LIB_LUA=lib-lua
endif
if BUILD_IMAP_HIBERNATE
IMAP_HIBERNATE=imap-hibernate
endif

LIBDOVECOT_SUBDIRS = \
	lib-test \
	lib \
	lib-var-expand \
	lib-dns \
	lib-settings \
	lib-otp \
	lib-auth \
	lib-auth-client \
	lib-dns-client \
	lib-ssl-iostream \
	lib-master \
	lib-login \
	lib-charset \
	lib-json \
	lib-dcrypt \
	lib-dict \
	lib-sasl \
	lib-http \
	lib-fs \
	lib-mail \
	lib-program-client \
	lib-smtp \
	lib-pop3 \
	lib-imap \
	lib-imap-storage \
	lib-oauth2 \
	lib-doveadm \
	lib-var-expand-crypt

SUBDIRS = \
	$(LIBDOVECOT_SUBDIRS) \
	lib-dict-extra \
	lib-dovecot \
	$(LIB_LDAP) \
	$(LIB_LUA) \
	lib-language \
	lib-imap-client \
	lib-imap-urlauth \
	lib-compression \
	lib-index \
	lib-storage \
	lib-sql \
	lib-lda \
	lib-dict-backend \
	anvil \
	auth \
	dict \
	dns \
	indexer \
	master \
	login-common \
	$(IMAP_HIBERNATE) \
	imap-login \
	imap \
	imap-urlauth \
	imap-urlauth-login \
	pop3-login \
	pop3 \
	submission-login \
	submission \
	lda \
	lmtp \
	log \
	config \
	util \
	doveadm \
	stats \
	plugins
