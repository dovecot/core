/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "safe-memset.h"
#include "auth.h"
#include "cookie.h"
#include "userinfo.h"

static void auth_plain_continue(struct cookie_data *cookie,
				struct auth_continued_request_data *request,
				const unsigned char *data,
				AuthCallback callback, void *context)
{
	struct auth_cookie_reply_data *cookie_reply = cookie->context;
	struct auth_reply_data reply;
	const char *user;
	char *pass;
	size_t i, count, len;

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
		if (data[i] == '\0' && ++count == 2) {
			i++;
			if (i == request->data_size)
				pass = "";
			else {
				len = request->data_size - i;
				pass = t_malloc(len+1);
                                memcpy(pass, (const char *) data + i, len);
                                pass[len] = '\0';
			}
			break;
		}
	}

	if (pass != NULL) {
		if (userinfo->verify_plain(user, pass, cookie_reply)) {
			cookie_reply->success = TRUE;
			reply.result = AUTH_RESULT_SUCCESS;

			if (strocpy(reply.virtual_user,
				    cookie_reply->virtual_user,
				    sizeof(reply.virtual_user)) < 0)
				i_panic("virtual_user overflow");
		}

		if (*pass != '\0') {
			/* make sure it's cleared */
			safe_memset(pass, 0, strlen(pass));
		}
	}

        callback(&reply, NULL, context);

	if (!cookie_reply->success) {
		/* failed, we don't need the cookie anymore */
		cookie_remove(cookie->cookie);
	}
}

static int auth_plain_fill_reply(struct cookie_data *cookie,
				 struct auth_cookie_reply_data *reply)
{
	struct auth_cookie_reply_data *cookie_reply;

	cookie_reply = cookie->context;
	if (!cookie_reply->success)
		return FALSE;

	memcpy(reply, cookie_reply, sizeof(struct auth_cookie_reply_data));
	return TRUE;
}

static void auth_plain_free(struct cookie_data *cookie)
{
	i_free(cookie->context);
	i_free(cookie);
}

static void auth_plain_init(unsigned int login_pid,
			    struct auth_init_request_data *request,
			    AuthCallback callback, void *context)
{
	struct cookie_data *cookie;
	struct auth_reply_data reply;

	cookie = i_new(struct cookie_data, 1);
	cookie->login_pid = login_pid;
	cookie->auth_fill_reply = auth_plain_fill_reply;
	cookie->auth_continue = auth_plain_continue;
	cookie->free = auth_plain_free;
	cookie->context = i_new(struct auth_cookie_reply_data, 1);

	cookie_add(cookie);

	/* initialize reply */
	memset(&reply, 0, sizeof(reply));
	reply.id = request->id;
	reply.result = AUTH_RESULT_CONTINUE;
	memcpy(reply.cookie, cookie->cookie, AUTH_COOKIE_SIZE);

	callback(&reply, NULL, context);
}

struct auth_module auth_plain = {
	AUTH_MECH_PLAIN,
	auth_plain_init
};
