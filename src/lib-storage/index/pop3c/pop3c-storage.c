/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "settings.h"
#include "mail-copy.h"
#include "mail-user.h"
#include "mailbox-list-private.h"
#include "index-mail.h"
#include "pop3c-client.h"
#include "pop3c-sync.h"
#include "pop3c-storage.h"

#define DNS_CLIENT_SOCKET_NAME "dns-client"

extern struct mail_storage pop3c_storage;
extern struct mailbox pop3c_mailbox;

static struct event_category event_category_pop3c = {
	.name = "pop3c",
	.parent = &event_category_storage,
};

static struct mail_storage *pop3c_storage_alloc(void)
{
	struct pop3c_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("pop3c storage", 512+256);
	storage = p_new(pool, struct pop3c_storage, 1);
	storage->storage = pop3c_storage;
	storage->storage.pool = pool;
	return &storage->storage;
}

static bool
pop3c_storage_match(struct mail_storage *_storage, struct mailbox_list *list)
{
	struct pop3c_storage *storage = POP3C_STORAGE(_storage);
	const struct pop3c_settings *pop3c_set;
	const char *error;
	bool match;

	if (storage->disabled ||
	    HAS_ANY_BITS(list->ns->flags, NAMESPACE_FLAG_UNUSABLE)) {
		/* Never share a disabled client, or share a working client
		   with a namespace that must not access the remote. */
		return FALSE;
	}
	if (settings_get(list->event, &pop3c_setting_parser_info, 0,
			 &pop3c_set, &error) < 0) {
		/* The error is reported when the new storage is created. */
		return FALSE;
	}
	match = settings_equal(&pop3c_setting_parser_info,
			       storage->set, pop3c_set, NULL);
	settings_free(pop3c_set);
	if (!match)
		return FALSE;
	if (pop3c_client_settings_match(storage->list_event, list->event,
					&error) <= 0) {
		/* Any error is reported when the new storage is created. */
		return FALSE;
	}
	return TRUE;
}

static int
pop3c_storage_create(struct mail_storage *_storage,
		     struct mail_namespace *ns,
		     const char **error_r)
{
	struct pop3c_storage *storage = POP3C_STORAGE(_storage);
	struct event *list_event;

	list_event = event_create(ns->list->event);
	event_add_category(list_event, &event_category_pop3c);

	if (settings_get(list_event, &pop3c_setting_parser_info, 0,
			 &storage->set, error_r) < 0) {
		event_unref(&list_event);
		return -1;
	}

	storage->list_event = list_event;
	if ((ns->flags & NAMESPACE_FLAG_UNUSABLE) != 0) {
		/* Shared namespace user doesn't actually exist. Don't try to
		   access the user via pop3c, but also don't make this a
		   visible error. If any code path tries to connect to pop3c,
		   it's a bug. */
		storage->disabled = TRUE;
	}
	return 0;
}

static void pop3c_storage_destroy(struct mail_storage *_storage)
{
	struct pop3c_storage *storage = POP3C_STORAGE(_storage);

	settings_free(storage->set);
	event_unref(&storage->list_event);
	index_storage_destroy(_storage);
}

static int
pop3c_client_create(struct mail_storage *_storage,
		    struct pop3c_client **client_r, const char **error_r)
{
	struct pop3c_storage *storage = POP3C_STORAGE(_storage);
	struct mail_user *user = _storage->user;
	struct pop3c_parameters params = {};
	string_t *str;

	str = t_str_new(128);
	mail_user_set_get_temp_prefix(str, user->set);
	params.temp_path_prefix = str_c(str);
	if (storage->disabled)
		params.flags |= POP3C_PARAMETER_CLIENT_DISABLED;

	return pop3c_client_init(&params, storage->list_event,
				 client_r, error_r);
}

static struct mailbox *
pop3c_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		    const char *vname, enum mailbox_flags flags)
{
	struct pop3c_mailbox *mbox;
	pool_t pool;

	pool = pool_alloconly_create("pop3c mailbox", 1024*3);
	mbox = p_new(pool, struct pop3c_mailbox, 1);
	mbox->box = pop3c_mailbox;
	mbox->box.pool = pool;
	mbox->box.storage = storage;
	mbox->box.list = list;
	mbox->box.list->props |= MAILBOX_LIST_PROP_AUTOCREATE_DIRS;
	mbox->box.mail_vfuncs = &pop3c_mail_vfuncs;
	mbox->storage = POP3C_STORAGE(storage);

	index_storage_mailbox_alloc(&mbox->box, vname, flags, MAIL_INDEX_PREFIX);
	return &mbox->box;
}

static int
pop3c_mailbox_exists(struct mailbox *box, bool auto_boxes,
		     enum mailbox_existence *existence_r)
{
	if ((auto_boxes && mailbox_is_autocreated(box)) || box->inbox_any)
		*existence_r = MAILBOX_EXISTENCE_SELECT;
	else
		*existence_r = MAILBOX_EXISTENCE_NONE;
	return 0;
}

static void pop3c_login_callback(enum pop3c_command_state state,
				 const char *reply, void *context)
{
	struct pop3c_mailbox *mbox = context;
	const char *suffix;

	switch (state) {
	case POP3C_COMMAND_STATE_OK:
		mbox->logged_in = TRUE;
		break;
	case POP3C_COMMAND_STATE_ERR:
		if (str_begins(reply, "[IN-USE] ", &suffix)) {
			mail_storage_set_error(mbox->box.storage,
					       MAIL_ERROR_INUSE, suffix);
		} else {
			/* authentication failure probably */
			mail_storage_set_error(mbox->box.storage,
					       MAIL_ERROR_PARAMS, reply);
		}
		break;
	case POP3C_COMMAND_STATE_DISCONNECTED:
		mailbox_set_critical(&mbox->box,
			"pop3c: Disconnected from remote server");
		break;
	}
}

static int pop3c_mailbox_open(struct mailbox *box)
{
	struct pop3c_mailbox *mbox = POP3C_MAILBOX(box);
	const char *error;

	if (strcmp(box->name, "INBOX") != 0) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
				       T_MAIL_ERR_MAILBOX_NOT_FOUND(box->vname));
		return -1;
	}

	if (index_storage_mailbox_open(box, FALSE) < 0)
		return -1;
	if (pop3c_client_create(box->storage, &mbox->client, &error) < 0) {
		mailbox_set_critical(box,
			"Failed to initialize POP3 client: %s", error);
		mailbox_close(box);
		return -1;
	}
	pop3c_client_login(mbox->client, pop3c_login_callback, mbox);
	pop3c_client_wait_one(mbox->client);
	return mbox->logged_in ? 0 : -1;
}

static void pop3c_mailbox_close(struct mailbox *box)
{
	struct pop3c_mailbox *mbox = POP3C_MAILBOX(box);

	pool_unref(&mbox->uidl_pool);
	i_free_and_null(mbox->msg_uids);
	i_free_and_null(mbox->msg_sizes);
	pop3c_client_deinit(&mbox->client);
	index_storage_mailbox_close(box);
}

static int
pop3c_mailbox_create(struct mailbox *box,
		     const struct mailbox_update *update ATTR_UNUSED,
		     bool directory ATTR_UNUSED)
{
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			       "POP3 mailbox creation isn't supported");
	return -1;
}

static int
pop3c_mailbox_update(struct mailbox *box,
		     const struct mailbox_update *update ATTR_UNUSED)
{
	if (!guid_128_is_empty(update->mailbox_guid) ||
	    update->uid_validity != 0 || update->min_next_uid != 0 ||
	    update->min_first_recent_uid != 0) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
				       "POP3 mailbox update isn't supported");
	}
	return index_storage_mailbox_update(box, update);
}

static int pop3c_mailbox_get_status(struct mailbox *box,
				    enum mailbox_status_items items,
				    struct mailbox_status *status_r)
{
	struct pop3c_mailbox *mbox = POP3C_MAILBOX(box);

	if (index_storage_get_status(box, items, status_r) < 0)
		return -1;

	if ((pop3c_client_get_capabilities(mbox->client) &
	     POP3C_CAPABILITY_UIDL) == 0)
		status_r->have_guids = FALSE;
	return 0;
}

static int pop3c_mailbox_get_metadata(struct mailbox *box,
				      enum mailbox_metadata_items items,
				      struct mailbox_metadata *metadata_r)
{
	if ((items & MAILBOX_METADATA_GUID) != 0) {
		/* a bit ugly way to do this, but better than nothing for now.
		   FIXME: if indexes are enabled, keep this there. */
		mail_generate_guid_128_hash(box->name, metadata_r->guid);
		items &= ENUM_NEGATE(MAILBOX_METADATA_GUID);
	}
	if (items != 0) {
		if (index_mailbox_get_metadata(box, items, metadata_r) < 0)
			return -1;
	}
	return 0;
}

static void pop3c_notify_changes(struct mailbox *box ATTR_UNUSED)
{
}

static struct mail_save_context *
pop3c_save_alloc(struct mailbox_transaction_context *t)
{
	struct mail_save_context *ctx;

	ctx = i_new(struct mail_save_context, 1);
	ctx->transaction = t;
	return ctx;
}

static int
pop3c_save_begin(struct mail_save_context *ctx,
		 struct istream *input ATTR_UNUSED)
{
	mail_storage_set_error(ctx->transaction->box->storage,
		MAIL_ERROR_NOTPOSSIBLE, "POP3 doesn't support saving mails");
	return -1;
}

static int pop3c_save_continue(struct mail_save_context *ctx ATTR_UNUSED)
{
	return -1;
}

static int pop3c_save_finish(struct mail_save_context *ctx)
{
	index_save_context_free(ctx);
	return -1;
}

static void
pop3c_save_cancel(struct mail_save_context *ctx)
{
	index_save_context_free(ctx);
}

static bool pop3c_storage_is_inconsistent(struct mailbox *box)
{
	struct pop3c_mailbox *mbox = POP3C_MAILBOX(box);

	return index_storage_is_inconsistent(box) ||
		!pop3c_client_is_connected(mbox->client);
}

struct mail_storage pop3c_storage = {
	.name = POP3C_STORAGE_NAME,
	.class_flags = MAIL_STORAGE_CLASS_FLAG_NO_ROOT |
		MAIL_STORAGE_CLASS_FLAG_HAVE_MAIL_GUIDS,
	.event_category = &event_category_pop3c,
	.set_info = &pop3c_setting_parser_info,

	.v = {
		.alloc = pop3c_storage_alloc,
		.create = pop3c_storage_create,
		.destroy = pop3c_storage_destroy,
		.mailbox_alloc = pop3c_mailbox_alloc,
		.storage_match = pop3c_storage_match,
	}
};

struct mailbox pop3c_mailbox = {
	.v = {
		index_storage_is_readonly,
		index_storage_mailbox_enable,
		pop3c_mailbox_exists,
		pop3c_mailbox_open,
		pop3c_mailbox_close,
		index_storage_mailbox_free,
		pop3c_mailbox_create,
		pop3c_mailbox_update,
		index_storage_mailbox_delete,
		index_storage_mailbox_rename,
		pop3c_mailbox_get_status,
		pop3c_mailbox_get_metadata,
		index_storage_set_subscribed,
		index_storage_attribute_set,
		index_storage_attribute_get,
		index_storage_attribute_iter_init,
		index_storage_attribute_iter_next,
		index_storage_attribute_iter_deinit,
		index_storage_list_index_has_changed,
		index_storage_list_index_update_sync,
		pop3c_storage_sync_init,
		index_mailbox_sync_next,
		index_mailbox_sync_deinit,
		NULL,
		pop3c_notify_changes,
		index_transaction_begin,
		index_transaction_commit,
		index_transaction_rollback,
		NULL,
		pop3c_mail_alloc,
		index_storage_search_init,
		index_storage_search_deinit,
		index_storage_search_next_nonblock,
		index_storage_search_next_update_seq,
		index_storage_search_next_match_mail,
		pop3c_save_alloc,
		pop3c_save_begin,
		pop3c_save_continue,
		pop3c_save_finish,
		pop3c_save_cancel,
		mail_storage_copy,
		NULL,
		NULL,
		NULL,
		pop3c_storage_is_inconsistent
	}
};
