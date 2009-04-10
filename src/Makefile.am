if BUILD_POP3D
POP3D = pop3-login pop3
endif

if BUILD_DELIVER
DELIVER = deliver
endif

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
	$(LIBDOVECOT_SUBDIRS) \
	lib-dovecot \
	lib-index \
	lib-storage \
	lib-sql \
	lib-ntlm \
	lib-otp \
	auth \
	dict \
	master \
	login-common \
	imap-login \
	imap \
	$(POP3D) \
	$(DELIVER) \
	config \
	tests \
	util \
	plugins
