#ifndef __USERINFO_PASSWD_H
#define __USERINFO_PASSWD_H

#include <pwd.h>

#define IS_VALID_PASSWD(pass) \
	((pass)[0] != '\0' && (pass)[0] != '*' && (pass)[0] != '!')

void passwd_fill_cookie_reply(struct passwd *pw, AuthCookieReplyData *reply);

#endif
