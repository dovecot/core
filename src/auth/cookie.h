#ifndef __COOKIE_H
#define __COOKIE_H

#include "auth-interface.h"

typedef struct _CookieData CookieData;

struct _CookieData {
	unsigned char cookie[AUTH_COOKIE_SIZE];

	/* continue authentication */
	void (*auth_continue)(CookieData *cookie,
			      AuthContinuedRequestData *request,
			      const unsigned char *data,
			      AuthCallback callback, void *user_data);

	/* fills reply from cookie, returns TRUE if successful */
	int (*auth_fill_reply)(CookieData *cookie, AuthCookieReplyData *reply);

	/* Free all data related to cookie */
	void (*free)(CookieData *cookie);

	void *user_data;
};

typedef void (*CookieFreeFunc)(void *data);

/* data->cookie is filled */
void cookie_add(CookieData *data);
/* Looks up the cookie */
CookieData *cookie_lookup(unsigned char cookie[AUTH_COOKIE_SIZE]);
/* Removes and frees the cookie */
void cookie_remove(unsigned char cookie[AUTH_COOKIE_SIZE]);
/* Looks up the cookie and removes it, you have to free the returned data. */
CookieData *cookie_lookup_and_remove(unsigned char cookie[AUTH_COOKIE_SIZE]);

void cookies_init(void);
void cookies_deinit(void);

#endif
