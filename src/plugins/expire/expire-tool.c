/* Copyright (c) 2006-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "env-util.h"
#include "file-lock.h"
#include "randgen.h"
#include "lib-signals.h"
#include "dict.h"
#include "mail-index.h"
#include "mail-search-build.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "auth-client.h"
#include "auth-master.h"
#include "expire-env.h"

#include <stdlib.h>

/* ugly, but automake doesn't like having it built as both static and
   dynamic object.. */
#include "expire-env.c"

#define DEFAULT_AUTH_SOCKET_PATH PKG_RUNDIR"/auth-master"

struct expire_context {
	struct auth_master_connection *auth_conn;

	char *user;
	struct mail_user *mail_user;
	bool testrun;
};

static int user_init(struct expire_context *ctx, const char *user)
{
	int ret;

	env_clean();
	if ((ret = auth_client_put_user_env(ctx->auth_conn, user)) <= 0) {
		if (ret < 0)
			return ret;

		/* user no longer exists */
		return 0;
	}

	ctx->mail_user = mail_user_init(user);
	mail_user_set_home(ctx->mail_user, getenv("HOME"));
	if (mail_namespaces_init(ctx->mail_user) < 0)
		return -1;
	return 1;
}

static void user_deinit(struct expire_context *ctx)
{
	mail_user_unref(&ctx->mail_user);
	i_free_and_null(ctx->user);
}

static int
mailbox_delete_old_mails(struct expire_context *ctx, const char *user,
			 const char *mailbox,
			 unsigned int expunge_secs, unsigned int altmove_secs,
			 time_t *oldest_r)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	struct mail_search_context *search_ctx;
	struct mailbox_transaction_context *t;
	struct mail_search_args *search_args;
	struct mail *mail;
	const char *ns_mailbox, *errstr;
	time_t now, save_time;
	enum mail_error error;
	enum mail_flags flags;
	int ret;

	*oldest_r = 0;

	if (ctx->user != NULL && strcmp(user, ctx->user) != 0)
		user_deinit(ctx);
	if (ctx->user == NULL) {
		if ((ret = user_init(ctx, user)) <= 0) {
			if (ctx->testrun)
				i_info("User lookup failed: %s", user);
			return ret;
		}
		ctx->user = i_strdup(user);
	}

	ns_mailbox = mailbox;
	ns = mail_namespace_find(ctx->mail_user->namespaces, &ns_mailbox);
	if (ns == NULL) {
		/* entire namespace no longer exists, remove the entry */
		if (ctx->testrun)
			i_info("Namespace lookup failed: %s", mailbox);
		return 0;
	}

	box = mailbox_open(ns->storage, ns_mailbox, NULL, 0);
	if (box == NULL) {
		errstr = mail_storage_get_last_error(ns->storage, &error);
		if (error != MAIL_ERROR_NOTFOUND) {
			i_error("%s: Opening mailbox %s failed: %s",
				user, mailbox, errstr);
			return -1;
		}
		
		/* mailbox no longer exists, remove the entry */
		return 0;
	}

	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);

	t = mailbox_transaction_begin(box, 0);
	search_ctx = mailbox_search_init(t, search_args, NULL);
	mail_search_args_unref(&search_args);

	mail = mail_alloc(t, 0, NULL);

	now = time(NULL);
	while ((ret = mailbox_search_next(search_ctx, mail)) > 0) {
		if (mail_get_save_date(mail, &save_time) < 0) {
			/* maybe just got expunged. anyway try again later. */
			if (ctx->testrun) {
				i_info("%s/%s: seq=%u uid=%u: "
				       "Save date lookup failed",
				       user, mailbox, mail->seq, mail->uid);
			}
			ret = -1;
			break;
		}

		if (save_time + (time_t)expunge_secs <= now &&
		    expunge_secs != 0) {
			if (!ctx->testrun)
				mail_expunge(mail);
			else {
				i_info("%s/%s: seq=%u uid=%u: Expunge",
				       user, mailbox, mail->seq, mail->uid);
			}
		} else if (save_time + (time_t)altmove_secs <= now &&
			   altmove_secs != 0) {
			/* works only with dbox */
			flags = mail_get_flags(mail);
			if ((flags & MAIL_INDEX_MAIL_FLAG_BACKEND) != 0) {
				/* alread moved */
			} else if (!ctx->testrun) {
				mail_update_flags(mail, MODIFY_ADD,
						  MAIL_INDEX_MAIL_FLAG_BACKEND);
			} else {
				i_info("%s/%s: seq=%u uid=%u: Move to alt dir",
				       user, mailbox, mail->seq, mail->uid);
			}
		} else {
			/* first non-expired one. */
			*oldest_r = save_time;
			break;
		}
	}
	mail_free(&mail);

	if (mailbox_search_deinit(&search_ctx) < 0)
		ret = -1;
	if (!ctx->testrun) {
		if (mailbox_transaction_commit(&t) < 0)
			ret = -1;
	} else {
		mailbox_transaction_rollback(&t);
	}

	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FAST, 0, NULL) < 0)
		ret = -1;

	mailbox_close(&box);
	return ret < 0 ? -1 : 0;
}

static void expire_run(bool testrun)
{
	struct expire_context ctx;
	struct dict *dict = NULL;
	struct dict_transaction_context *trans;
	struct dict_iterate_context *iter;
	struct expire_env *env;
	time_t oldest;
	unsigned int expunge_secs, altmove_secs;
	const char *auth_socket, *p, *key, *value;
	const char *userp, *mailbox;
	int ret;

	dict_drivers_register_builtin();
	mail_users_init(getenv("AUTH_SOCKET_PATH"), getenv("DEBUG") != NULL);
	mail_storage_init();
	mail_storage_register_all();
	mailbox_list_register_all();

	if (getenv("EXPIRE") == NULL && getenv("EXPIRE_ALTMOVE") == NULL)
		i_fatal("expire and expire_altmove settings not set");
	if (getenv("EXPIRE_DICT") == NULL)
		i_fatal("expire_dict setting not set");

	auth_socket = getenv("AUTH_SOCKET_PATH");
	if (auth_socket == NULL)
		auth_socket = DEFAULT_AUTH_SOCKET_PATH;

	memset(&ctx, 0, sizeof(ctx));
	ctx.testrun = testrun;
	ctx.auth_conn = auth_master_init(auth_socket, getenv("DEBUG") != NULL);
	env = expire_env_init(getenv("EXPIRE"), getenv("EXPIRE_ALTMOVE"));
	dict = dict_init(getenv("EXPIRE_DICT"), DICT_DATA_TYPE_UINT32, "");
	if (dict == NULL)
		i_fatal("dict_init() failed");

	trans = dict_transaction_begin(dict);
	iter = dict_iterate_init(dict, DICT_EXPIRE_PREFIX,
				 DICT_ITERATE_FLAG_RECURSE |
				 DICT_ITERATE_FLAG_SORT_BY_VALUE);

	/* We'll get the oldest values (timestamps) first */
	while (dict_iterate(iter, &key, &value) > 0) {
		/* key = DICT_EXPIRE_PREFIX<user>/<mailbox> */
		userp = key + strlen(DICT_EXPIRE_PREFIX);

		p = strchr(userp, '/');
		if (p == NULL) {
			i_error("Expire dictionary contains invalid key: %s",
				key);
			continue;
		}

		mailbox = p + 1;
		if (!expire_box_find(env, mailbox,
				     &expunge_secs, &altmove_secs)) {
			/* we're no longer expunging old messages from here */
			if (!testrun)
				dict_unset(trans, key);
			else {
				i_info("%s: mailbox '%s' removed from config",
				       userp, mailbox);
			}
			continue;
		}
		if (time(NULL) < (time_t)strtoul(value, NULL, 10)) {
			/* this and the rest of the timestamps are in future,
			   so stop processing */
			if (testrun) {
				i_info("%s: stop, expire time in future: %s",
				       userp, value);
			}
			break;
		}

		T_BEGIN {
			const char *username;

			username = t_strdup_until(userp, p);
			ret = mailbox_delete_old_mails(&ctx, username,
						       mailbox, expunge_secs,
						       altmove_secs, &oldest);
		} T_END;

		if (ret < 0) {
			/* failed to update */
		} else if (oldest == 0) {
			/* no more messages or mailbox deleted */
			if (!testrun)
				dict_unset(trans, key);
			else
				i_info("%s: no messages left", userp);
		} else {
			char new_value[MAX_INT_STRLEN];

			oldest += altmove_secs != 0 ?
				altmove_secs : expunge_secs;
			i_snprintf(new_value, sizeof(new_value), "%lu",
				   (unsigned long)oldest);
			if (strcmp(value, new_value) == 0) {
				/* no change */
			} else if (!testrun)
				dict_set(trans, key, new_value);
			else {
				i_info("%s: timestamp %s -> %s",
				       userp, value, new_value);
			}
		}
	}
	dict_iterate_deinit(&iter);
	if (!testrun)
		dict_transaction_commit(&trans);
	else
		dict_transaction_rollback(&trans);
	dict_deinit(&dict);

	if (ctx.user != NULL)
		user_deinit(&ctx);
	auth_master_deinit(&ctx.auth_conn);

	mail_storage_deinit();
	mail_users_deinit();
	dict_drivers_unregister_builtin();
}

int main(int argc ATTR_UNUSED, const char *argv[])
{
	struct ioloop *ioloop;
	bool test = FALSE;

	lib_init();
	lib_signals_init();
	random_init();

	while (argv[1] != NULL) {
		if (strcmp(argv[1], "--test") == 0)
			test = TRUE;
		else
			i_fatal("Unknown parameter: %s", argv[1]);
		argv++;
	}

	ioloop = io_loop_create();
	expire_run(test);
	io_loop_destroy(&ioloop);

	lib_signals_deinit();
	lib_deinit();
	return 0;
}
