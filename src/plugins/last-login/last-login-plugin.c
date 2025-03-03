/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "settings.h"
#include "settings-parser.h"
#include "dict.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "mail-storage-hooks.h"
#include "last-login-plugin.h"

#define LAST_LOGIN_USER_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, last_login_user_module)

struct last_login_user {
	union mail_user_module_context module_ctx;
	struct dict *dict;
	struct timeout *to;
};

struct last_login_settings {
	pool_t pool;

	const char *last_login_key;
	const char *last_login_precision;
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct last_login_settings)
static const struct setting_define last_login_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "last_login" },
	DEF(STR, last_login_key),
	DEF(ENUM, last_login_precision),

	SETTING_DEFINE_LIST_END
};
static const struct last_login_settings last_login_default_settings = {
	.last_login_key = "last-login/%{user}",
	.last_login_precision = "s:ms:us:ns",
};

const struct setting_parser_info last_login_setting_parser_info = {
	.name = "last_login",
	.plugin_dependency = "lib10_last_login_plugin",

	.defines = last_login_setting_defines,
	.defaults = &last_login_default_settings,

	.struct_size = sizeof(struct last_login_settings),
	.pool_offset1 = 1 + offsetof(struct last_login_settings, pool),
};

const char *last_login_plugin_version = DOVECOT_ABI_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(last_login_user_module,
				  &mail_user_module_register);

static void last_login_dict_deinit(struct mail_user *user)
{
	struct last_login_user *luser = LAST_LOGIN_USER_CONTEXT(user);

	if (luser->dict != NULL) {
		dict_wait(luser->dict);
		dict_deinit(&luser->dict);
	}
	/* remove timeout after dict_wait(), which may trigger
	   last_login_dict_commit() */
	timeout_remove(&luser->to);
}

static void last_login_user_deinit(struct mail_user *user)
{
	struct last_login_user *luser = LAST_LOGIN_USER_CONTEXT(user);

	last_login_dict_deinit(user);
	luser->module_ctx.super.deinit(user);
}

static void
last_login_dict_commit(const struct dict_commit_result *result,
		       struct mail_user *user)
{
	struct last_login_user *luser = LAST_LOGIN_USER_CONTEXT(user);

	switch(result->ret) {
	case DICT_COMMIT_RET_OK:
	case DICT_COMMIT_RET_NOTFOUND:
		break;
	case DICT_COMMIT_RET_FAILED:
		e_error(user->event,
			"last_login_dict: Failed to write value: %s",
			result->error);
		break;
	case DICT_COMMIT_RET_WRITE_UNCERTAIN:
		e_error(user->event,
			"last_login_dict: Write was unconfirmed (timeout or disconnect): %s",
			result->error);
		break;
	}

	/* don't deinit the dict immediately here, lib-dict will just crash */
	luser->to = timeout_add(0, last_login_dict_deinit, user);
}

static void last_login_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct last_login_user *luser;
	const struct last_login_settings *set;
	struct dict *dict;
	struct dict_transaction_context *trans;
	const char *key_name, *error;
	int ret;

	if (user->autocreated) {
		/* we want to handle only logged in users,
		   not lda's raw user or accessed shared users */
		return;
	}
	if (user->session_restored) {
		/* This is IMAP unhibernation, not a real login. */
		return;
	}

	struct event *event = event_create(user->event);
	settings_event_add_filter_name(event, "last_login");
	event_set_append_log_prefix(event, "last_login_dict: ");
	if (settings_get(event, &last_login_setting_parser_info, 0,
			 &set, &error) < 0) {
		e_error(event, "%s", error);
		event_unref(&event);
		return;
	}

	if ((ret = dict_init_auto(event, &dict, &error)) <= 0) {
		if (ret < 0)
			e_error(event, "%s", error);
		settings_free(set);
		event_unref(&event);
		return;
	}

	luser = p_new(user->pool, struct last_login_user, 1);
	luser->module_ctx.super = *v;
	user->vlast = &luser->module_ctx.super;
	v->deinit = last_login_user_deinit;

	luser->dict = dict;
	MODULE_CONTEXT_SET(user, last_login_user_module, luser);

	key_name = t_strconcat(DICT_PATH_SHARED, set->last_login_key, NULL);

	struct dict_op_settings dset = *mail_user_get_dict_op_settings(user);
	dset.no_slowness_warning = TRUE;
	trans = dict_transaction_begin(dict, &dset);
	if (strcmp(set->last_login_precision, "s") == 0)
		dict_set(trans, key_name, dec2str(ioloop_time));
	else if (strcmp(set->last_login_precision, "ms") == 0) {
		dict_set(trans, key_name, t_strdup_printf(
			"%ld%03u", (long)ioloop_timeval.tv_sec,
			(unsigned int)(ioloop_timeval.tv_usec/1000)));
	} else if (strcmp(set->last_login_precision, "us") == 0) {
		dict_set(trans, key_name, t_strdup_printf(
			"%ld%06u", (long)ioloop_timeval.tv_sec,
			(unsigned int)ioloop_timeval.tv_usec));
	} else if (strcmp(set->last_login_precision, "ns") == 0) {
		dict_set(trans, key_name, t_strdup_printf(
			"%ld%06u000", (long)ioloop_timeval.tv_sec,
			(unsigned int)ioloop_timeval.tv_usec));
	} else {
		i_unreached();
	}
	dict_transaction_commit_async(&trans, last_login_dict_commit, user);
	settings_free(set);
	event_unref(&event);
}

static struct mail_storage_hooks last_login_mail_storage_hooks = {
	.mail_user_created = last_login_mail_user_created
};

void last_login_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &last_login_mail_storage_hooks);
}

void last_login_plugin_deinit(void)
{
	mail_storage_hooks_remove(&last_login_mail_storage_hooks);
}
