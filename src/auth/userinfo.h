#ifndef __USERINFO_H
#define __USERINFO_H

#include "auth-interface.h"

typedef struct {
	void (*init)(const char *args);
	void (*deinit)(void);

	/* Returns TRUE if user/pass matches, and fills reply with user
	   information. reply should have been initialized (zeroed) before
	   calling this function. */
	int (*verify_plain)(const char *user, const char *password,
			   AuthCookieReplyData *reply);

	/* Digest-MD5 specific password lookup. The digest is filled with
	   the MD5 password which consists of a MD5 sum of
	   "user:realm:password". If utf8 is TRUE, the user and realm are
	   in UTF-8, otherwise ISO-8859-1. Returns TRUE if user was found. */
	int (*lookup_digest_md5)(const char *user, const char *realm,
				 unsigned char digest[16],
				 AuthCookieReplyData *reply);
} UserInfoModule;

extern UserInfoModule *userinfo;

extern UserInfoModule userinfo_passwd;
extern UserInfoModule userinfo_shadow;
extern UserInfoModule userinfo_pam;
extern UserInfoModule userinfo_passwd_file;

void userinfo_init(void);
void userinfo_deinit(void);

#endif
