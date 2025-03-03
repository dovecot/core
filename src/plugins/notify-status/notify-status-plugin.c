/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "json-generator.h"
#include "str.h"
#include "var-expand.h"
#include "mail-user.h"
#include "mail-storage.h"
#include "mail-storage-private.h"
#include "mail-namespace.h"
#include "mail-storage-hooks.h"
#include "dict.h"
#include "notify-plugin.h"
#include "settings.h"
#include "settings-parser.h"

#define NOTIFY_STATUS_SETTING_VALUE_TEMPLATE_DEFAULT "{\"messages\":%{messages},\"unseen\":%{unseen}}"
#define NOTIFY_STATUS_KEY "priv/status/%s"

#define NOTIFY_STATUS_USER_CONTEXT(obj) \
	(struct notify_status_user*)MODULE_CONTEXT(obj, notify_status_user_module)

static MODULE_CONTEXT_DEFINE_INIT(notify_status_user_module,
				  &mail_user_module_register);

void notify_status_plugin_init(struct module *module);
void notify_status_plugin_deinit(void);

const char *notify_status_plugin_version = DOVECOT_ABI_VERSION;
const char *notify_status_plugin_dependencies[] = { "notify", NULL };

struct notify_status_plugin_settings {
	pool_t pool;

	bool mailbox_notify_status;
	const char *notify_status_value;
};

#undef DEF
#define DEF(type, name) \
       SETTING_DEFINE_STRUCT_##type(#name, name, struct notify_status_plugin_settings)
static const struct setting_define notify_status_plugin_setting_defines[] = {
       DEF(BOOL, mailbox_notify_status),
       DEF(STR_NOVARS, notify_status_value),
       { .type = SET_FILTER_NAME, .key = "notify_status",
	 .required_setting = "dict", },

       SETTING_DEFINE_LIST_END
};

static const struct notify_status_plugin_settings notify_status_plugin_default_settings = {
	.notify_status_value = NOTIFY_STATUS_SETTING_VALUE_TEMPLATE_DEFAULT,
	.mailbox_notify_status = FALSE,
};

const struct setting_parser_info notify_status_plugin_setting_parser_info = {
       .name = "notify_status",
       .plugin_dependency = "lib20_notify_status_plugin",

       .defines = notify_status_plugin_setting_defines,
       .defaults = &notify_status_plugin_default_settings,

       .struct_size = sizeof(struct notify_status_plugin_settings),
       .pool_offset1 = 1 + offsetof(struct notify_status_plugin_settings, pool),
};

struct notify_status_mail_txn {
	struct mailbox *box;
	bool changed:1;
};

struct notify_status_user {
	union mail_user_module_context module_ctx;

	struct dict *dict;
	const struct notify_status_plugin_settings *set;
	struct notify_context *context;
};

static bool notify_status_mailbox_enabled(struct mailbox *box)
{
	struct mail_user *user = mail_storage_get_user(mailbox_get_storage(box));
	struct notify_status_user *nuser = NOTIFY_STATUS_USER_CONTEXT(user);
	const char *error;
	const struct notify_status_plugin_settings *set;
	bool notify_status_mailbox;

	/* not enabled */
	if (nuser == NULL)
		return FALSE;

	/* Get mailbox specific notify_status_mailbox setting */
	if (settings_get(box->event, &notify_status_plugin_setting_parser_info,
			 0, &set, &error) < 0) {
		e_error(box->event, "%s", error);
		return nuser->set->mailbox_notify_status;
	}

	notify_status_mailbox = set->mailbox_notify_status;
	settings_free(set);
	return notify_status_mailbox;
}

static void notify_update_callback(const struct dict_commit_result *result,
				   struct event *event)
{
	if (result->ret == DICT_COMMIT_RET_OK ||
	    result->ret == DICT_COMMIT_RET_NOTFOUND) {
		event_unref(&event);
		return;
	}

	e_error(event, "notify-status: dict_transaction_commit failed: %s",
		result->error == NULL ? "" : result->error);

	event_unref(&event);
}

#define MAILBOX_STATUS_NOTIFY (STATUS_MESSAGES|STATUS_UNSEEN|\
			       STATUS_RECENT|STATUS_UIDNEXT|\
			       STATUS_UIDVALIDITY|\
			       STATUS_HIGHESTMODSEQ|STATUS_FIRST_RECENT_UID|\
			       STATUS_HIGHESTPVTMODSEQ)
static void notify_update_mailbox_status(struct mailbox *box)
{
	struct mail_user *user = mail_storage_get_user(mailbox_get_storage(box));
	struct notify_status_user *nuser = NOTIFY_STATUS_USER_CONTEXT(user);
	i_assert(nuser != NULL);
	struct dict_transaction_context *t;
	struct mailbox_status status;

	e_debug(box->event, "notify-status: Updating mailbox status");

	box = mailbox_alloc(mailbox_get_namespace(box)->list,
			   mailbox_get_vname(box), MAILBOX_FLAG_READONLY);

	if (mailbox_open(box) < 0) {
		e_error(box->event, "notify-status: mailbox_open() failed: %s",
			mailbox_get_last_error(box, NULL));
	} else if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		e_error(box->event, "notify-status: mailbox_sync() failed: %s",
			mailbox_get_last_error(box, NULL));
	} else if (mailbox_get_status(box, MAILBOX_STATUS_NOTIFY, &status) < 0) {
		e_error(box->event, "notify-status: mailbox_get_status() failed: %s",
			mailbox_get_last_error(box, NULL));
	} else {
		string_t *username = t_str_new(strlen(user->username));
		string_t *mboxname = t_str_new(64);

		json_append_escaped(username, user->username);
		json_append_escaped(mboxname, mailbox_get_vname(box));

		const struct var_expand_table values[] = {
			{ .key = "username", .value = str_c(username) },
			{ .key = "mailbox", .value = str_c(mboxname) },
			{ .key = "messages", .value = dec2str(status.messages) },
			{ .key = "unseen", .value = dec2str(status.unseen) },
			{ .key = "recent", .value = dec2str(status.recent) },
			{ .key = "uidvalidity", .value = dec2str(status.uidvalidity) },
			{ .key = "uidnext", .value = dec2str(status.uidnext) },
			{ .key = "first_recent_uid", .value = dec2str(status.first_recent_uid) },
			{ .key = "highest_modseq", .value = dec2str(status.highest_modseq) },
			{ .key = "highest_pvt_modseq", .value = dec2str(status.highest_pvt_modseq) },
			VAR_EXPAND_TABLE_END
		};
		const struct var_expand_params params = {
			.table = values,
			.event = box->event,
		};
		const char *error;
		const char *key =
			t_strdup_printf(NOTIFY_STATUS_KEY, mailbox_get_vname(box));
		string_t *dest = t_str_new(64);
		if (var_expand(dest, nuser->set->notify_status_value,
				   &params, &error) < 0) {
			e_error(box->event, "notify-status: var_expand(%s) failed: %s",
				nuser->set->notify_status_value, error);
		} else {
			const struct dict_op_settings *set = mail_user_get_dict_op_settings(user);
			t = dict_transaction_begin(nuser->dict, set);
			dict_set(t, key, str_c(dest));
			dict_transaction_commit_async(&t, notify_update_callback,
						      event_create(box->event));
		}
	}

	mailbox_free(&box);
}

static void notify_remove_mailbox_status(struct mailbox *box)
{
	struct mail_user *user = mail_storage_get_user(mailbox_get_storage(box));
	struct notify_status_user *nuser = NOTIFY_STATUS_USER_CONTEXT(user);
	i_assert(nuser != NULL);
	struct dict_transaction_context *t;

	e_debug(box->event, "notify-status: Removing mailbox status");

	const char *key =
		t_strdup_printf(NOTIFY_STATUS_KEY, mailbox_get_vname(box));

	const struct dict_op_settings *set = mail_user_get_dict_op_settings(user);
	t = dict_transaction_begin(nuser->dict, set);
	dict_unset(t, key);
	dict_transaction_commit_async(&t, notify_update_callback,
				      event_create(box->event));
}

static void *notify_status_mail_transaction_begin(struct mailbox_transaction_context *t)
{
	struct notify_status_mail_txn *txn = i_new(struct notify_status_mail_txn, 1);
	txn->box = mailbox_transaction_get_mailbox(t);
	return txn;
}

static void
notify_status_mail_transaction_commit(void *t,
				      struct mail_transaction_commit_changes *changes ATTR_UNUSED)
{
	struct notify_status_mail_txn *txn = (struct notify_status_mail_txn *)t;
	if (txn->changed && notify_status_mailbox_enabled(txn->box))
		notify_update_mailbox_status(txn->box);
	i_free(txn);
}

static void notify_status_mail_transaction_rollback(void *t)
{
	i_free(t);
}

static void notify_status_mailbox_create(struct mailbox *box)
{
	if (notify_status_mailbox_enabled(box))
		notify_update_mailbox_status(box);
}

static void notify_status_mailbox_delete_commit(void *txn ATTR_UNUSED,
						struct mailbox *box)
{
	if (notify_status_mailbox_enabled(box))
		notify_remove_mailbox_status(box);
}

static void notify_status_mailbox_rename(struct mailbox *src, struct mailbox *dest)
{
	if (notify_status_mailbox_enabled(src))
		notify_remove_mailbox_status(src);
	if (notify_status_mailbox_enabled(dest))
		notify_update_mailbox_status(dest);
}

static void notify_status_mail_save(void *t, struct mail *mail ATTR_UNUSED)
{
	struct notify_status_mail_txn *txn = (struct notify_status_mail_txn *)t;
	txn->changed = TRUE;
}

static void notify_status_mail_copy(void *t, struct mail *src ATTR_UNUSED,
				    struct mail *dst ATTR_UNUSED)
{
	struct notify_status_mail_txn *txn = (struct notify_status_mail_txn *)t;
	txn->changed = TRUE;
}

static void notify_status_mail_expunge(void *t, struct mail *mail ATTR_UNUSED)
{
	struct notify_status_mail_txn *txn = (struct notify_status_mail_txn *)t;
	txn->changed = TRUE;
}
static void notify_status_mail_update_flags(void *t, struct mail *mail,
					    enum mail_flags old_flags)
{
	struct notify_status_mail_txn *txn = (struct notify_status_mail_txn *)t;
	if ((old_flags & MAIL_SEEN) != (mail_get_flags(mail) & MAIL_SEEN))
		txn->changed = TRUE;
}

static const struct notify_vfuncs notify_vfuncs =
{
	.mail_transaction_begin = notify_status_mail_transaction_begin,
	.mail_save = notify_status_mail_save,
	.mail_copy = notify_status_mail_copy,
	.mail_expunge = notify_status_mail_expunge,
	.mail_update_flags = notify_status_mail_update_flags,
	.mail_transaction_commit = notify_status_mail_transaction_commit,
	.mail_transaction_rollback = notify_status_mail_transaction_rollback,
	.mailbox_create = notify_status_mailbox_create,
	.mailbox_delete_commit = notify_status_mailbox_delete_commit,
	.mailbox_rename = notify_status_mailbox_rename,
};

static void notify_status_mail_user_deinit(struct mail_user *user)
{
	struct notify_status_user *nuser = NOTIFY_STATUS_USER_CONTEXT(user);
	i_assert(nuser != NULL);

	dict_wait(nuser->dict);
	dict_deinit(&nuser->dict);
	settings_free(nuser->set);
	notify_unregister(&nuser->context);
	nuser->module_ctx.super.deinit(user);
}

static void notify_status_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct notify_status_plugin_settings *set;
	struct notify_status_user *nuser;
	struct dict *dict;
	const char *error;

	if (user->autocreated)
		return;

	if (settings_get(user->event, &notify_status_plugin_setting_parser_info,
			 0, &set, &error) < 0) {
		e_error(user->event, "%s", error);
		return;
	}

	struct event *event = event_create(user->event);
	settings_event_add_filter_name(event, "notify_status");

	int ret = dict_init_auto(event, &dict, &error);
	event_unref(&event);
	if (ret < 0)
		e_error(user->event, "notify-status: dict_init_auto() failed: %s", error);
	if (ret <= 0) {
		settings_free(set);
		return;
	}

	nuser = p_new(user->pool, struct notify_status_user, 1);
	nuser->module_ctx.super = *v;
	nuser->dict = dict;
	nuser->set = set;
	user->vlast = &nuser->module_ctx.super;
	v->deinit = notify_status_mail_user_deinit;

	MODULE_CONTEXT_SET(user, notify_status_user_module, nuser);
}

static void
notify_status_mail_namespaces_created(struct mail_namespace *namespaces)
{
	struct mail_user *user = namespaces->user;
	struct notify_status_user *nuser = NOTIFY_STATUS_USER_CONTEXT(user);
	if (nuser == NULL)
		return;
	nuser->context = notify_register(&notify_vfuncs);
}

static const struct mail_storage_hooks notify_storage_hooks =
{
	.mail_user_created = notify_status_mail_user_created,
	.mail_namespaces_created = notify_status_mail_namespaces_created,
};

void notify_status_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &notify_storage_hooks);
}

void notify_status_plugin_deinit(void)
{
	mail_storage_hooks_remove(&notify_storage_hooks);
}
