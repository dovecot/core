#ifndef __USERINFO_PASSWD_H
#define __USERINFO_PASSWD_H

/* can't remember what these were for. needed in some systems I think :) */
#ifndef _XOPEN_SOURCE_EXTENDED
#  define _XOPEN_SOURCE_EXTENDED
#endif
#define _XPG4_2

/* Do this first so we're not (hopefully) affected by the temporary
   _XOPEN_SOURCE define. Required to compile with new NetBSDs (around 1.6K) */
#include <sys/types.h>

/* _XOPEN_SOURCE is required for crypt(). However with Solaris 8 it breaks
   a few other header files so keep it defined only for unistd.h */
#define _XOPEN_SOURCE 4 /* needed for crypt() */
#include <unistd.h>
#undef _XOPEN_SOURCE

#include "common.h"
#include "userinfo.h"

#include <pwd.h>

#define IS_VALID_PASSWD(pass) \
	((pass)[0] != '\0' && (pass)[0] != '*' && (pass)[0] != '!')

void passwd_fill_cookie_reply(struct passwd *pw, AuthCookieReplyData *reply);

#endif
