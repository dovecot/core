/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "auth.h"
#include "cookie.h"
#include "userinfo.h"

static void auth_plain_continue(CookieData *cookie,
				AuthContinuedRequestData *request,
				const unsigned char *data,
				AuthCallback callback, void *user_data)
{
	AuthCookieReplyData *cookie_reply = cookie->user_data;
	AuthReplyData reply;
	const char *user, *pass;
	unsigned int i, count;

	/* initialize reply */
	memset(&reply, 0, sizeof(reply));
	reply.id = request->id;
	reply.result = AUTH_RESULT_FAILURE;
	memcpy(reply.cookie, cookie->cookie, AUTH_COOKIE_SIZE);

	/* data should contain user\0...\0pass */
	user = (const char *) data;
	pass = NULL;
	count = 0;
	for (i = 0; i < request->data_size; i++) {
		if (data[i] == '\0') {
			if (++count == 2) {
				pass = i+1 == request->data_size ? "" :
					t_strndup((const char *) data + i + 1,
						  request->data_size - i - 1);
				break;
			}
		}
	}

	if (pass != NULL) {
		if (userinfo->verify_plain(user, pass, cookie_reply)) {
			cookie_reply->success = TRUE;
			reply.result = AUTH_RESULT_SUCCESS;
		}
	}

        callback(&reply, NULL, user_data);

	if (!cookie_reply->success) {
		/* failed, we don't need the cookie anymore */
		cookie_remove(cookie->cookie);
	}
}

static int auth_plain_fill_reply(CookieData *cookie, AuthCookieReplyData *reply)
{
	AuthCookieReplyData *cookie_reply;

	cookie_reply = cookie->user_data;
	if (!cookie_reply->success)
		return FALSE;

	memcpy(reply, cookie_reply, sizeof(AuthCookieReplyData));
	return TRUE;
}

static void auth_plain_free(CookieData *cookie)
{
	i_free(cookie->user_data);
	i_free(cookie);
}

static void auth_plain_init(AuthInitRequestData *request,
			    AuthCallback callback, void *user_data)
{
	CookieData *cookie;
	AuthReplyData reply;

	cookie = i_new(CookieData, 1);
	cookie->auth_fill_reply = auth_plain_fill_reply;
	cookie->auth_continue = auth_plain_continue;
	cookie->free = auth_plain_free;
	cookie->user_data = i_new(AuthCookieReplyData, 1);

	cookie_add(cookie);

	/* initialize reply */
	memset(&reply, 0, sizeof(reply));
	reply.id = request->id;
	reply.result = AUTH_RESULT_CONTINUE;
	memcpy(reply.cookie, cookie->cookie, AUTH_COOKIE_SIZE);

	callback(&reply, NULL, user_data);
}

AuthModule auth_plain = {
	AUTH_METHOD_PLAIN,
	auth_plain_init
};
