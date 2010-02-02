/* Copyright (c) 2006-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "env-util.h"
#include "dict.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "mail-index.h"
#include "mail-search-build.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "mail-namespace.h"
#include "auth-client.h"
#include "auth-master.h"
#include "expire-env.h"

#include <stdlib.h>
#include <time.h>

struct expire_context {
	struct mail_storage_service_ctx *storage_service;
	struct mail_storage_service_user *service_user;
	struct mail_user *mail_user;
	struct expire_env *env;
	bool testrun;
};

static int expire_init_user(struct expire_context *ctx, const char *user)
{
	struct mail_storage_service_input input;
	const char *errstr;
	int ret;

	i_set_failure_prefix(t_strdup_printf("expire-tool(%s): ", user));

	memset(&input, 0, sizeof(input));
	input.service = "expire-tool";
	input.username = user;

	ret = mail_storage_service_lookup_next(ctx->storage_service, &input,
					       &ctx->service_user,
					       &ctx->mail_user, &errstr);
	if (ret <= 0) {
		if (ret < 0 || ctx->testrun)
			i_error("%s", errstr);
		return ret;
	}

	if (mail_user_set_plugin_getenv(ctx->mail_user->set, "expire") == NULL)
		i_fatal("expire settings not set");

	ctx->env = expire_env_init(ctx->mail_user->namespaces);
	return 1;
}

static void expire_deinit_user(struct expire_context *ctx)
{
	mail_user_unref(&ctx->mail_user);
	mail_storage_service_user_free(&ctx->service_user);
	expire_env_deinit(&ctx->env);
}

static int
mailbox_delete_old_mails(struct expire_context *ctx, const char *user,
			 const char *mailbox, time_t *next_expire_r)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	struct mail_search_context *search_ctx;
	struct mailbox_transaction_context *t;
	struct mail_search_args *search_args;
	struct mail *mail;
	const char *ns_mailbox, *errstr;
	unsigned int expunge_secs, altmove_secs;
	time_t now, save_time;
	enum mail_error error;
	enum mail_flags flags;
	int ret;

	*next_expire_r = 0;

	if (ctx->mail_user != NULL &&
	    strcmp(user, ctx->mail_user->username) != 0)
		expire_deinit_user(ctx);
	if (ctx->mail_user == NULL) {
		if ((ret = expire_init_user(ctx, user)) <= 0)
			return ret;
	}

	if (!expire_rule_find(ctx->env, mailbox, &expunge_secs, &altmove_secs)) {
		/* we're no longer expunging old messages from here */
		if (ctx->testrun) {
			i_info("%s: mailbox '%s' removed from config",
			       user, mailbox);
		}
		return 0;
	}

	ns_mailbox = mailbox;
	ns = mail_namespace_find(ctx->mail_user->namespaces, &ns_mailbox);
	if (ns == NULL) {
		/* entire namespace no longer exists, remove the entry */
		if (ctx->testrun)
			i_info("Namespace lookup failed: %s", mailbox);
		return 0;
	}

	box = mailbox_alloc(ns->list, ns_mailbox, NULL, 0);
	if (mailbox_open(box) < 0) {
		errstr = mail_storage_get_last_error(mailbox_get_storage(box),
						     &error);
		mailbox_close(&box);
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

	now = time(NULL); ret = 0;
	while (mailbox_search_next(search_ctx, mail)) {
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
			*next_expire_r = save_time +
				(altmove_secs != 0 ?
				 altmove_secs : expunge_secs);
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

	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FAST) < 0)
		ret = -1;

	mailbox_close(&box);
	return ret;
}

static void expire_run(struct master_service *service, bool testrun)
{
	struct expire_context ctx;
	struct dict *dict = NULL;
	const struct mail_user_settings *user_set;
	struct mail_storage_service_input input;
	void **sets;
	struct dict_transaction_context *trans;
	struct dict_iterate_context *iter;
	time_t next_expire, expire_time;
	const char *p, *key, *value, *expire_dict;
	const char *userp = NULL, *mailbox;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.storage_service = mail_storage_service_init(service, NULL,
				MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP);

	memset(&input, 0, sizeof(input));
	input.module = input.service = "expire-tool";
	mail_storage_service_init_settings(ctx.storage_service, &input);

	sets = master_service_settings_get_others(service);
	user_set = sets[0];

	expire_dict = mail_user_set_plugin_getenv(user_set, "expire_dict");
	if (expire_dict == NULL)
		i_fatal("expire_dict setting not set");

	ctx.testrun = testrun;
	dict = dict_init(expire_dict, DICT_DATA_TYPE_UINT32, "",
			 user_set->base_dir);
	if (dict == NULL)
		i_fatal("dict_init() failed");

	trans = dict_transaction_begin(dict);
	iter = dict_iterate_init(dict, DICT_EXPIRE_PREFIX,
				 DICT_ITERATE_FLAG_RECURSE |
				 DICT_ITERATE_FLAG_SORT_BY_VALUE);

	/* We'll get the oldest values (timestamps) first */
	while ((ret = dict_iterate(iter, &key, &value)) > 0) {
		/* key = DICT_EXPIRE_PREFIX<user>/<mailbox> */
		userp = key + strlen(DICT_EXPIRE_PREFIX);

		p = strchr(userp, '/');
		if (p == NULL) {
			i_error("Expire dictionary contains invalid key: %s",
				key);
			continue;
		}

		mailbox = p + 1;
		expire_time = strtoul(value, NULL, 10);
		if (time(NULL) < expire_time) {
			/* this and the rest of the timestamps are in future,
			   so stop processing */
			if (testrun) {
				i_info("%s: stop, expire time in future: %s",
				       userp, ctime(&expire_time));
			}
			break;
		}

		T_BEGIN {
			const char *username;

			username = t_strdup_until(userp, p);
			ret = mailbox_delete_old_mails(&ctx, username,
						       mailbox, &next_expire);
		} T_END;

		if (ret < 0) {
			/* failed to update */
			ret = 0;
		} else if (next_expire == 0) {
			/* no more messages or mailbox deleted */
			if (!testrun)
				dict_unset(trans, key);
			else
				i_info("%s: no messages left", userp);
		} else {
			char new_value[MAX_INT_STRLEN];

			i_snprintf(new_value, sizeof(new_value), "%lu",
				   (unsigned long)next_expire);
			if (strcmp(value, new_value) == 0) {
				/* no change */
			} else if (!testrun)
				dict_set(trans, key, new_value);
			else T_BEGIN {
				i_info("%s: timestamp %s (%s) -> %s (%s)",
				       userp, value,
				       t_strcut(ctime(&expire_time), '\n'),
				       new_value,
				       t_strcut(ctime(&next_expire), '\n'));
			} T_END;
		}
	}
	if (ret < 0)
		i_error("Dictionary iteration failed");
	if (testrun && userp == NULL)
		i_info("No entries in dictionary");

	dict_iterate_deinit(&iter);
	if (!testrun)
		dict_transaction_commit(&trans);
	else
		dict_transaction_rollback(&trans);
	dict_deinit(&dict);

	if (ctx.mail_user != NULL)
		expire_deinit_user(&ctx);
	mail_storage_service_deinit(&ctx.storage_service);
}

int main(int argc, char *argv[])
{
	bool test = FALSE;
	int c;

	master_service = master_service_init("expire-tool",
					     MASTER_SERVICE_FLAG_STANDALONE,
					     &argc, &argv, "t");

	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 't':
			test = TRUE;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}
	if (optind != argc)
		i_fatal("Unknown parameter: %s", argv[optind]);

	expire_run(master_service, test);

	master_service_deinit(&master_service);
	return 0;
}
