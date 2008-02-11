/* Copyright (c) 2006-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "file-lock.h"
#include "randgen.h"
#include "lib-signals.h"
#include "dict-client.h"
#include "mail-search.h"
#include "mail-storage.h"
#include "mail-namespace.h"
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
	pool_t namespace_pool;
	struct mail_namespace *ns;
};

static int user_init(struct expire_context *ctx, const char *user)
{
	int ret;

	if ((ret = auth_client_put_user_env(ctx->auth_conn, user)) <= 0) {
		if (ret < 0)
			return ret;

		/* user no longer exists */
		return 0;
	}

	if (mail_namespaces_init(ctx->namespace_pool, user, &ctx->ns) < 0)
		return -1;
	return 1;
}

static void user_deinit(struct expire_context *ctx)
{
	mail_namespaces_deinit(&ctx->ns);
	i_free_and_null(ctx->user);
	p_clear(ctx->namespace_pool);
}

static int
mailbox_delete_old_mails(struct expire_context *ctx, const char *user,
			 const char *mailbox, time_t expire_secs,
			 time_t *oldest_r)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	struct mail_search_context *search_ctx;
	struct mailbox_transaction_context *t;
	struct mail_search_arg search_arg;
	struct mail *mail;
	time_t now, save_time;
	int ret;

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

	ns = mail_namespace_find(ctx->ns, &mailbox);
	if (ns == NULL)
		return -1;

	box = mailbox_open(ns->storage, mailbox, NULL, 0);
	t = mailbox_transaction_begin(box, 0);
	search_ctx = mailbox_search_init(t, NULL, &search_arg, NULL);
	mail = mail_alloc(t, 0, NULL);

	now = time(NULL);
	while ((ret = mailbox_search_next(search_ctx, mail)) > 0) {
		if (mail_get_save_date(mail, &save_time) < 0) {
			/* maybe just got expunged. anyway try again later. */
			ret = -1;
			break;
		}

		if (save_time + expire_secs <= now)
			mail_expunge(mail);
		else {
			/* first non-expunged one. */
			*oldest_r = save_time;
			break;
		}
	}
	mail_free(&mail);

	if (mailbox_search_deinit(&search_ctx) < 0)
		ret = -1;
	if (mailbox_transaction_commit(&t) < 0)
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
	const char *userp, *mailbox;
	int ret;

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
	ctx.namespace_pool = pool_alloconly_create("namespaces", 1024);
	env = expire_env_init(getenv("EXPIRE"));
	dict = dict_init(getenv("EXPIRE_DICT"), DICT_DATA_TYPE_UINT32, "");
	trans = dict_transaction_begin(dict);
	iter = dict_iterate_init(dict, DICT_PATH_SHARED,
				 DICT_ITERATE_FLAG_SORT_BY_VALUE);

	/* We'll get the oldest values (timestamps) first */
	while (dict_iterate(iter, &key, &value) > 0) {
		/* key = DICT_PATH_SHARED<user>/<mailbox> */
		userp = key + strlen(DICT_PATH_SHARED);

		p = strchr(userp, '/');
		if (p == NULL) {
			i_error("Expire dictionary contains invalid key: %s",
				key);
			continue;
		}

		mailbox = p + 1;
		expire_box = expire_box_find(env, mailbox);
		if (expire_box == NULL) {
			/* we're no longer expunging old messages from here */
			dict_unset(trans, key);
		} else if (time(NULL) < (time_t)strtoul(value, NULL, 10)) {
			/* this and the rest of the timestamps are in future,
			   so stop processing */
			break;
		} else {
			T_BEGIN {
				const char *username;

				username = t_strdup_until(userp, p);
				ret = mailbox_delete_old_mails(&ctx, username,
						mailbox,
						expire_box->expire_secs,
						&oldest);
			} T_END;
			if (ret < 0) {
				/* failed to update */
			} else if (oldest == 0) {
				/* no more messages or we're no longer
				   expunging messages from here */
				dict_unset(trans, key);
			} else {
				char new_value[MAX_INT_STRLEN];

				oldest += expire_box->expire_secs;
				i_snprintf(new_value, sizeof(new_value), "%lu",
					   (unsigned long)oldest);
				if (strcmp(value, new_value) != 0)
					dict_set(trans, key, new_value);
			}
		}
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
