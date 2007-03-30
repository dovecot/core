/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "file-lock.h"
#include "randgen.h"
#include "lib-signals.h"
#include "dict-client.h"
#include "mail-search.h"
#include "mail-storage.h"
#include "auth-client.h"
#include "expire-env.h"

#include <stdlib.h>

/* ugly, but automake doesn't like having it built as both static and
   dynamic object.. */
#include "expire-env.c"

#define DEFAULT_AUTH_SOCKET_PATH PKG_RUNDIR"/auth-master"

struct expire_context {
	struct auth_connection *auth_conn;

	char *user;
	struct mail_storage *storage;
};

static int user_init(struct expire_context *ctx, const char *user)
{
	enum mail_storage_flags flags;
	enum file_lock_method lock_method;
	const char *mail_env;
	int ret;

	if ((ret = auth_client_put_user_env(ctx->auth_conn, user)) <= 0) {
		if (ret < 0)
			return ret;

		/* user no longer exists */
		return 0;
	}

	mail_env = getenv("MAIL");
	mail_storage_parse_env(&flags, &lock_method);
	ctx->storage = mail_storage_create(NULL, mail_env, user,
					   flags, lock_method);
	if (ctx->storage == NULL) {
		i_error("Failed to create storage for '%s' with mail '%s'",
			user, mail_env == NULL ? "(null)" : mail_env);
		return -1;
	}
	return 1;
}

static void user_deinit(struct expire_context *ctx)
{
	mail_storage_destroy(&ctx->storage);
	i_free_and_null(ctx->user);
}

static int
mailbox_delete_old_mails(struct expire_context *ctx, const char *user,
			 const char *mailbox, time_t expire_secs,
			 time_t *oldest_r)
{
	struct mailbox *box;
	struct mail_search_context *search_ctx;
	struct mailbox_transaction_context *t;
	struct mail_search_arg search_arg;
	struct mail *mail;
	time_t now, save_time;
	int ret = 0;

	*oldest_r = 0;

	if (ctx->user != NULL && strcmp(user, ctx->user) != 0)
		user_deinit(ctx);
	if (ctx->user == NULL) {
		if ((ret = user_init(ctx, user)) <= 0)
			return ret;
		ctx->user = i_strdup(user);
	}

	memset(&search_arg, 0, sizeof(search_arg));
	search_arg.type = SEARCH_ALL;
	search_arg.next = NULL;

	box = mailbox_open(ctx->storage, mailbox, NULL, 0);
	t = mailbox_transaction_begin(box, 0);
	search_ctx = mailbox_search_init(t, NULL, &search_arg, NULL);
	mail = mail_alloc(t, 0, NULL);

	now = time(NULL);
	while (mailbox_search_next(search_ctx, mail) > 0) {
		save_time = mail_get_save_date(mail);
		if (save_time == (time_t)-1) {
			/* maybe just got expunged. anyway try again later. */
			ret = -1;
			break;
		}

		if (save_time + expire_secs <= now) {
			if (mail_expunge(mail) < 0) {
				ret = -1;
				break;
			}
		} else {
			/* first non-expunged one. */
			*oldest_r = save_time;
			break;
		}
	}
	mail_free(&mail);

	if (mailbox_search_deinit(&search_ctx) < 0)
		ret = -1;
	if (mailbox_transaction_commit(&t, MAILBOX_SYNC_FLAG_FULL_READ |
				       MAILBOX_SYNC_FLAG_FULL_WRITE) < 0)
		ret = -1;
	mailbox_close(&box);
	return ret < 0 ? -1 : 0;
}

static void expire_run(void)
{
	struct expire_context ctx;
	struct dict *dict = NULL;
	struct dict_transaction_context *trans;
	struct dict_iterate_context *iter;
	struct expire_env *env;
	const struct expire_box *expire_box;
	time_t oldest;
	const char *auth_socket, *p, *key, *value;
	const char *username, *mailbox;

	dict_driver_register(&dict_driver_client);
	mail_storage_init();
	mail_storage_register_all();
	mailbox_list_register_all();

	if (getenv("EXPIRE") == NULL)
		i_fatal("expire setting not set");
	if (getenv("EXPIRE_DICT") == NULL)
		i_fatal("expire_dict setting not set");

	auth_socket = getenv("AUTH_SOCKET_PATH");
	if (auth_socket == NULL)
		auth_socket = DEFAULT_AUTH_SOCKET_PATH;

	memset(&ctx, 0, sizeof(ctx));
	ctx.auth_conn = auth_connection_init(auth_socket);
	env = expire_env_init(getenv("EXPIRE"));
	dict = dict_init(getenv("EXPIRE_DICT"), DICT_DATA_TYPE_UINT32, "");
	trans = dict_transaction_begin(dict);
	iter = dict_iterate_init(dict, DICT_PATH_SHARED,
				 DICT_ITERATE_FLAG_SORT_BY_VALUE);

	/* We'll get the oldest values (timestamps) first */
	while (dict_iterate(iter, &key, &value) > 0) {
		/* key = DICT_PATH_SHARED<user>/<mailbox> */
		username = key + strlen(DICT_PATH_SHARED);

		p = strchr(username, '/');
		if (p == NULL) {
			i_error("Expire dictionary contains invalid key: %s",
				key);
			continue;
		}

		t_push();
		username = t_strdup_until(username, p);
		mailbox = p + 1;

		expire_box = expire_box_find(env, mailbox);
		if (expire_box == NULL) {
			/* we're no longer expunging old messages from here */
			dict_unset(trans, key);
		} else if (time(NULL) < (time_t)strtoul(value, NULL, 10)) {
			/* this and the rest of the timestamps are in future,
			   so stop processing */
			t_pop();
			break;
		} else {
			if (mailbox_delete_old_mails(&ctx, username, mailbox,
						     expire_box->expire_secs,
						     &oldest) == 0) {
				/* successful update */
				if (oldest == 0) {
					/* no more messages or we're no longer
					   expunging messages from here */
					dict_unset(trans, key);
				} else {
					const char *new_value;

					oldest += expire_box->expire_secs;
					new_value = dec2str(oldest);
					if (strcmp(value, new_value) != 0)
						dict_set(trans, key, new_value);
				}
			}
		}
		t_pop();
	}
	dict_iterate_deinit(iter);
	dict_transaction_commit(trans);
	dict_deinit(&dict);

	if (ctx.user != NULL)
		user_deinit(&ctx);
	auth_connection_deinit(ctx.auth_conn);

	mail_storage_deinit();
	dict_driver_unregister(&dict_driver_client);
}

int main(void)
{
	struct ioloop *ioloop;

	lib_init();
	lib_signals_init();
	random_init();

	ioloop = io_loop_create();
	expire_run();
	io_loop_destroy(&ioloop);

	lib_signals_deinit();
	lib_deinit();
	return 0;
}
