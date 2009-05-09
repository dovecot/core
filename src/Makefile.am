LIBDOVECOT_SUBDIRS = \
	lib \
	lib-auth \
	lib-charset \
	lib-mail \
	lib-imap \
	lib-master \
	lib-dict \
	lib-settings

SUBDIRS = \
	lib-test \
	$(LIBDOVECOT_SUBDIRS) \
	lib-dovecot \
	lib-index \
	lib-storage \
	lib-sql \
	lib-ntlm \
	lib-otp \
	lib-lda \
	anvil \
	auth \
	dict \
	master \
	login-common \
	imap-login \
	imap \
	pop3-login \
	pop3 \
	lda \
	lmtp \
	log \
	config \
	util \
	plugins

test:
	for dir in $(SUBDIRS); do \
	  cd $$dir && if ! $(MAKE) test; then exit 1; fi; cd ..; \
	done
