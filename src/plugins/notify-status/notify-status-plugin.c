/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "json-parser.h"
#include "str.h"
#include "var-expand.h"
#include "mail-user.h"
#include "mail-storage.h"
#include "mail-storage-private.h"
#include "mail-namespace.h"
#include "mail-storage-hooks.h"
#include "imap-match.h"
#include "dict.h"
#include "notify-plugin.h"

#define NOTIFY_STATUS_SETTING_DICT_URI "notify_status_dict"
#define NOTIFY_STATUS_SETTING_MAILBOX_PREFIX "notify_status_mailbox"
#define NOTIFY_STATUS_SETTING_VALUE_TEMPLATE "notify_status_value"
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

ARRAY_DEFINE_TYPE(imap_match_glob, struct imap_match_glob*);

struct notify_status_mail_txn {
	struct mailbox *box;
	bool changed:1;
};

struct notify_status_user {
	union mail_user_module_context module_ctx;

	ARRAY_TYPE(imap_match_glob) patterns;
	struct dict *dict;
	const char *value_template;
	struct notify_context *context;
};

static int notify_status_dict_init(struct mail_user *user, const char *uri,
				   struct dict **dict_r, const char **error_r)
{
	struct dict_settings set = {
		.username = user->username,
		.base_dir = user->set->base_dir,
	};
	(void)mail_user_get_home(user, &set.home_dir);
	if (dict_init(uri, &set, dict_r, error_r) < 0) {
		*error_r = t_strdup_printf("dict_init(%s) failed: %s",
					   uri, *error_r);
		return -1;
	}
	return 0;
}

static void notify_status_mailbox_patterns_init(struct mail_user *user,
						ARRAY_TYPE(imap_match_glob) *patterns)
{
	const char *value;
	unsigned int i;

	p_array_init(patterns, user->pool, 2);

	for(i=1;;i++) {
		struct imap_match_glob **glob;
		const char *key = NOTIFY_STATUS_SETTING_MAILBOX_PREFIX;
		if (i > 1)
			key = t_strdup_printf("%s%u", key, i);
		value = mail_user_plugin_getenv(user, key);
		if (value == NULL)
			return;
		char sep = mail_namespace_get_sep(user->namespaces);
		glob = array_append_space(patterns);
		*glob = imap_match_init(user->pool, value, TRUE, sep);
	}
}

static bool notify_status_mailbox_enabled(struct mailbox *box)
{
	struct mail_user *user = mail_storage_get_user(mailbox_get_storage(box));
	struct notify_status_user *nuser = NOTIFY_STATUS_USER_CONTEXT(user);
	struct imap_match_glob **glob;
	/* not enabled */
	if (nuser == NULL)
		return FALSE;

	/* if no patterns defined, anything goes */
	if (array_count(&nuser->patterns) == 0)
		return TRUE;

	array_foreach_modifiable(&nuser->patterns, glob) {
		if ((imap_match(*glob, mailbox_get_vname(box)) & IMAP_MATCH_YES) != 0)
			return TRUE;
	}
	return FALSE;
}

static void notify_update_callback(const struct dict_commit_result *result,
				   void *context ATTR_UNUSED)
{
	if (result->ret == DICT_COMMIT_RET_OK ||
	    result->ret == DICT_COMMIT_RET_NOTFOUND)
		return;

	i_error("notify-status: dict_transaction_commit failed: %s",
		result->error == NULL ? "" : result->error);
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
		i_error("notify-status: mailbox_open(%s) failed: %s",
			  mailbox_get_vname(box),
			  mailbox_get_last_error(box, NULL));
	} else if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		i_error("notify-status: mailbox_sync(%s) failed: %s",
			  mailbox_get_vname(box),
			  mailbox_get_last_error(box, NULL));
	} else if (mailbox_get_status(box, MAILBOX_STATUS_NOTIFY,
				      &status) < 0) {
		i_error("notify-status: mailbox_get_status(%s) failed: %s",
			  mailbox_get_vname(box),
			  mailbox_get_last_error(box, NULL));
	} else {
		string_t *username = t_str_new(strlen(user->username));
		string_t *mboxname = t_str_new(64);

		json_append_escaped(username, user->username);
		json_append_escaped(mboxname, mailbox_get_vname(box));

		const struct var_expand_table values[] = {
			{ '\0', str_c(username), "username" },
			{ '\0', str_c(mboxname), "mailbox" },
			{ '\0', dec2str(status.messages), "messages" },
			{ '\0', dec2str(status.unseen), "unseen" },
			{ '\0', dec2str(status.recent), "recent" },
			{ '\0', dec2str(status.uidvalidity), "uidvalidity" },
			{ '\0', dec2str(status.uidnext), "uidnext" },
			{ '\0', dec2str(status.first_recent_uid), "first_recent_uid" },
			{ '\0', dec2str(status.highest_modseq), "highest_modseq" },
			{ '\0', dec2str(status.highest_pvt_modseq), "highest_pvt_modseq" },
			{ '\0', NULL, NULL }
		};
		const char *error;
		const char *key =
			t_strdup_printf(NOTIFY_STATUS_KEY, mailbox_get_vname(box));
		string_t *dest = t_str_new(64);
		if (var_expand(dest, nuser->value_template, values, &error)<0) {
			i_error("notify-status: var_expand(%s) failed: %s",
				nuser->value_template, error);
		} else {
			t = dict_transaction_begin(nuser->dict);
			dict_set(t, key, str_c(dest));
			dict_transaction_commit_async(&t, notify_update_callback, NULL) ;
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

	t = dict_transaction_begin(nuser->dict);
	dict_unset(t, key);
	dict_transaction_commit_async(&t, notify_update_callback, NULL) ;
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
	notify_unregister(nuser->context);
	nuser->module_ctx.super.deinit(user);
}

static void notify_status_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct notify_status_user *nuser;
	struct dict *dict;
	const char *error;
	const char *template = mail_user_plugin_getenv(user, NOTIFY_STATUS_SETTING_VALUE_TEMPLATE);
	const char *uri = mail_user_plugin_getenv(user, NOTIFY_STATUS_SETTING_DICT_URI);

	if (user->autocreated)
		return;

	if (uri == NULL || *uri == '\0') {
		e_debug(user->event, "notify-status: Disabled - Missing plugin/"
			NOTIFY_STATUS_SETTING_DICT_URI" setting");
		return;
	}

	if (template == NULL || *template == '\0')
		template = NOTIFY_STATUS_SETTING_VALUE_TEMPLATE_DEFAULT;

	if (notify_status_dict_init(user, uri, &dict, &error) < 0) {
		i_error("notify-status: %s", error);
		return;
	}

	nuser = p_new(user->pool, struct notify_status_user, 1);
	nuser->module_ctx.super = *v;
	nuser->dict = dict;
	user->vlast = &nuser->module_ctx.super;
	v->deinit = notify_status_mail_user_deinit;
	/* either static value or lifetime is user object's lifetime */
	nuser->value_template = template;

	MODULE_CONTEXT_SET(user, notify_status_user_module, nuser);
}

static void
notify_status_mail_namespaces_created(struct mail_namespace *namespaces)
{
	struct mail_user *user = namespaces->user;
	struct notify_status_user *nuser = NOTIFY_STATUS_USER_CONTEXT(user);
	if (nuser == NULL)
		return;
        notify_status_mailbox_patterns_init(user, &nuser->patterns);
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
