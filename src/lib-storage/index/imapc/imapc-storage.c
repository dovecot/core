/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "imap-resp-code.h"
#include "mail-copy.h"
#include "index-mail.h"
#include "imapc-client.h"
#include "imapc-list.h"
#include "imapc-sync.h"
#include "imapc-storage.h"

#define DNS_CLIENT_SOCKET_NAME "dns-client"

struct imapc_open_context {
	struct imapc_mailbox *mbox;
	int ret;
};

struct imapc_status_context {
	struct imapc_mailbox *mbox;
	struct mailbox_status *status;
	int ret;
};

struct imapc_resp_code_map {
	const char *code;
	enum mail_error error;
};

extern struct mail_storage imapc_storage;
extern struct mailbox imapc_mailbox;

static struct imapc_resp_code_map imapc_resp_code_map[] = {
	{ IMAP_RESP_CODE_UNAVAILABLE, MAIL_ERROR_TEMP },
	{ IMAP_RESP_CODE_AUTHFAILED, MAIL_ERROR_PERM },
	{ IMAP_RESP_CODE_AUTHZFAILED, MAIL_ERROR_PERM },
	{ IMAP_RESP_CODE_EXPIRED, MAIL_ERROR_PERM },
	{ IMAP_RESP_CODE_PRIVACYREQUIRED, MAIL_ERROR_PERM },
	{ IMAP_RESP_CODE_CONTACTADMIN, MAIL_ERROR_PERM },
	{ IMAP_RESP_CODE_NOPERM, MAIL_ERROR_PERM },
	{ IMAP_RESP_CODE_INUSE, MAIL_ERROR_INUSE },
	{ IMAP_RESP_CODE_EXPUNGEISSUED, MAIL_ERROR_EXPUNGED },
	{ IMAP_RESP_CODE_CORRUPTION, MAIL_ERROR_TEMP },
	{ IMAP_RESP_CODE_SERVERBUG, MAIL_ERROR_TEMP },
	/* { IMAP_RESP_CODE_CLIENTBUG, 0 }, */
	{ IMAP_RESP_CODE_CANNOT, MAIL_ERROR_NOTPOSSIBLE },
	{ IMAP_RESP_CODE_LIMIT, MAIL_ERROR_NOTPOSSIBLE },
	{ IMAP_RESP_CODE_OVERQUOTA, MAIL_ERROR_NOSPACE },
	{ IMAP_RESP_CODE_ALREADYEXISTS, MAIL_ERROR_EXISTS },
	{ IMAP_RESP_CODE_NONEXISTENT, MAIL_ERROR_NOTFOUND }
};

static bool
imap_resp_text_code_parse(const char *str, enum mail_error *error_r)
{
	unsigned int i;

	if (str == NULL)
		return FALSE;

	for (i = 0; i < N_ELEMENTS(imapc_resp_code_map); i++) {
		if (strcmp(imapc_resp_code_map[i].code, str) == 0) {
			*error_r = imapc_resp_code_map[i].error;
			return TRUE;
		}
	}
	return FALSE;
}

static struct mail_storage *imapc_storage_alloc(void)
{
	struct imapc_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("imapc storage", 512+256);
	storage = p_new(pool, struct imapc_storage, 1);
	storage->storage = imapc_storage;
	storage->storage.pool = pool;
	return &storage->storage;
}

static void
imapc_copy_error_from_reply(struct imapc_storage *storage,
			    enum mail_error default_error,
			    const struct imapc_command_reply *reply)
{
	enum mail_error error;

	if (imap_resp_text_code_parse(reply->resp_text_key, &error)) {
		mail_storage_set_error(&storage->storage, error,
				       reply->text_without_resp);
	} else {
		mail_storage_set_error(&storage->storage, default_error,
				       reply->text_without_resp);
	}
}

void imapc_simple_callback(const struct imapc_command_reply *reply,
			   void *context)
{
	struct imapc_simple_context *ctx = context;

	if (reply->state == IMAPC_COMMAND_STATE_OK)
		ctx->ret = 0;
	else if (reply->state == IMAPC_COMMAND_STATE_NO) {
		imapc_copy_error_from_reply(ctx->storage, MAIL_ERROR_PARAMS, reply);
		ctx->ret = -1;
	} else {
		mail_storage_set_critical(&ctx->storage->storage,
			"imapc: Command failed: %s", reply->text_full);
		ctx->ret = -1;
	}
	imapc_client_stop(ctx->storage->client);
}

void imapc_async_stop_callback(const struct imapc_command_reply *reply,
			       void *context)
{
	struct imapc_storage *storage = context;

	if (reply->state == IMAPC_COMMAND_STATE_OK)
		;
	else if (reply->state == IMAPC_COMMAND_STATE_NO) {
		imapc_copy_error_from_reply(storage, MAIL_ERROR_PARAMS, reply);
	} else {
		mail_storage_set_critical(&storage->storage,
			"imapc: Command failed: %s", reply->text_full);
	}
	imapc_client_stop(storage->client);
}

static void imapc_storage_untagged_cb(const struct imapc_untagged_reply *reply,
				      void *context)
{
	struct imapc_storage *storage = context;
	struct imapc_mailbox *mbox = reply->untagged_box_context;
	const struct imapc_storage_event_callback *cb;
	const struct imapc_mailbox_event_callback *mcb;

	array_foreach(&storage->untagged_callbacks, cb) {
		if (strcasecmp(reply->name, cb->name) == 0)
			cb->callback(reply, storage);
	}

	if (mbox == NULL)
		return;

	array_foreach(&mbox->untagged_callbacks, mcb) {
		if (strcasecmp(reply->name, mcb->name) == 0)
			mcb->callback(reply, mbox);
	}

	if (reply->resp_text_key != NULL) {
		array_foreach(&mbox->resp_text_callbacks, mcb) {
			if (strcasecmp(reply->resp_text_key, mcb->name) == 0)
				mcb->callback(reply, mbox);
		}
	}
}

static int
imapc_storage_create(struct mail_storage *_storage,
		     struct mail_namespace *ns,
		     const char **error_r)
{
	struct imapc_storage *storage = (struct imapc_storage *)_storage;
	struct imapc_client_settings set;

	memset(&set, 0, sizeof(set));
	set.host = ns->list->set.root_dir;
	set.port = 143;
	set.username = _storage->user->username;
	set.password = mail_user_plugin_getenv(_storage->user, "pass");
	if (set.password == NULL) {
		*error_r = "missing pass";
		return -1;
	}
	set.dns_client_socket_path =
		t_strconcat(_storage->user->set->base_dir, "/",
			    DNS_CLIENT_SOCKET_NAME, NULL);
	storage->list = (struct imapc_mailbox_list *)ns->list;
	storage->list->storage = storage;
	storage->client = imapc_client_init(&set);

	p_array_init(&storage->untagged_callbacks, _storage->pool, 16);
	imapc_client_register_untagged(storage->client,
				       imapc_storage_untagged_cb, storage);
	imapc_list_register_callbacks(storage->list);
	return 0;
}

static void imapc_storage_destroy(struct mail_storage *_storage)
{
	struct imapc_storage *storage = (struct imapc_storage *)_storage;

	imapc_client_deinit(&storage->client);
}

void imapc_storage_register_untagged(struct imapc_storage *storage,
				     const char *name,
				     imapc_storage_callback_t *callback)
{
	struct imapc_storage_event_callback *cb;

	cb = array_append_space(&storage->untagged_callbacks);
	cb->name = p_strdup(storage->storage.pool, name);
	cb->callback = callback;
}

static void
imapc_storage_get_list_settings(const struct mail_namespace *ns ATTR_UNUSED,
				struct mailbox_list_settings *set)
{
	set->layout = MAILBOX_LIST_NAME_IMAPC;
}

static struct mailbox *
imapc_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		    const char *vname, enum mailbox_flags flags)
{
	struct imapc_mailbox *mbox;
	struct index_mailbox_context *ibox;
	pool_t pool;

	flags |= MAILBOX_FLAG_NO_INDEX_FILES;

	pool = pool_alloconly_create("imapc mailbox", 1024*3);
	mbox = p_new(pool, struct imapc_mailbox, 1);
	mbox->box = imapc_mailbox;
	mbox->box.pool = pool;
	mbox->box.storage = storage;
	mbox->box.list = list;
	mbox->box.mail_vfuncs = &imapc_mail_vfuncs;

	index_storage_mailbox_alloc(&mbox->box, vname, flags, NULL);

	ibox = INDEX_STORAGE_CONTEXT(&mbox->box);
	ibox->save_commit_pre = imapc_transaction_save_commit_pre;
	ibox->save_commit_post = imapc_transaction_save_commit_post;
	ibox->save_rollback = imapc_transaction_save_rollback;

	mbox->storage = (struct imapc_storage *)storage;

	p_array_init(&mbox->untagged_callbacks, pool, 16);
	p_array_init(&mbox->resp_text_callbacks, pool, 16);
	imapc_mailbox_register_callbacks(mbox);
	return &mbox->box;
}

static void
imapc_mailbox_open_callback(const struct imapc_command_reply *reply,
			    void *context)
{
	struct imapc_open_context *ctx = context;

	if (reply->state == IMAPC_COMMAND_STATE_OK)
		ctx->ret = 0;
	else if (reply->state == IMAPC_COMMAND_STATE_NO) {
		imapc_copy_error_from_reply(ctx->mbox->storage,
					    MAIL_ERROR_NOTFOUND, reply);
		ctx->ret = -1;
	} else {
		mail_storage_set_critical(ctx->mbox->box.storage,
			"imapc: Opening mailbox '%s' failed: %s",
			ctx->mbox->box.name, reply->text_full);
		ctx->ret = -1;
	}
	if (!ctx->mbox->new_msgs)
		imapc_client_stop(ctx->mbox->storage->client);
}

static int imapc_mailbox_open(struct mailbox *box)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;
	struct imapc_open_context ctx;

	if (index_storage_mailbox_open(box, FALSE) < 0)
		return -1;

	mbox->delayed_sync_trans =
		mail_index_transaction_begin(box->view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mbox->delayed_sync_view =
		mail_index_transaction_open_updated_view(mbox->delayed_sync_trans);

	ctx.mbox = mbox;
	ctx.ret = -1;
	mbox->client_box =
		imapc_client_mailbox_open(mbox->storage->client, box->name,
					  imapc_mailbox_open_callback,
					  &ctx, mbox);
	imapc_client_run(mbox->storage->client);
	if (ctx.ret < 0) {
		mailbox_close(box);
		return -1;
	}
	return 0;
}

static void imapc_mailbox_close(struct mailbox *box)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;

	mail_index_view_close(&mbox->delayed_sync_view);
	if (mail_index_transaction_commit(&mbox->delayed_sync_trans) < 0)
		mail_storage_set_index_error(&mbox->box);
	return index_storage_mailbox_close(box);
}

static int
imapc_mailbox_create(struct mailbox *box,
		     const struct mailbox_update *update ATTR_UNUSED,
		     bool directory)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;
	struct imapc_simple_context ctx;
	const char *name = box->name;

	if (directory) {
		name = t_strdup_printf("%s%c", name,
				mailbox_list_get_hierarchy_sep(box->list));
	}
	ctx.storage = mbox->storage;
	imapc_client_cmdf(mbox->storage->client, imapc_simple_callback, &ctx,
			  "CREATE %s", name);
	imapc_client_run(mbox->storage->client);
	return ctx.ret;
}

static int imapc_mailbox_update(struct mailbox *box,
				const struct mailbox_update *update ATTR_UNUSED)
{
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			       "Not supported");
	return -1;
}

static void imapc_mailbox_get_selected_status(struct imapc_mailbox *mbox,
					      enum mailbox_status_items items,
					      struct mailbox_status *status_r)
{
	index_storage_get_status(&mbox->box, items, status_r);
}

static void
imapc_mailbox_status_callback(const struct imapc_command_reply *reply,
			      void *context)
{
	struct imapc_status_context *ctx = context;

	if (reply->state == IMAPC_COMMAND_STATE_OK)
		ctx->ret = 0;
	else if (reply->state == IMAPC_COMMAND_STATE_NO) {
		imapc_copy_error_from_reply(ctx->mbox->storage,
					    MAIL_ERROR_NOTFOUND, reply);
	} else {
		mail_storage_set_critical(ctx->mbox->box.storage,
			"imapc: STATUS for mailbox '%s' failed: %s",
			ctx->mbox->box.name, reply->text_full);
		ctx->ret = -1;
	}
	imapc_client_stop(ctx->mbox->storage->client);
}

static int imapc_mailbox_get_status(struct mailbox *box,
				    enum mailbox_status_items items,
				    struct mailbox_status *status_r)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;
	struct imapc_status_context ctx;
	string_t *str;

	memset(status_r, 0, sizeof(*status_r));

	if (box->opened) {
		imapc_mailbox_get_selected_status(mbox, items, status_r);
		return 0;
	}

	/* mailbox isn't opened yet */
	if ((items & (STATUS_FIRST_UNSEEN_SEQ | STATUS_KEYWORDS)) != 0) {
		/* getting these requires opening the mailbox */
		if (mailbox_open(box) < 0)
			return -1;
		imapc_mailbox_get_selected_status(mbox, items, status_r);
		return 0;
	}

	str = t_str_new(256);
	if ((items & STATUS_MESSAGES) != 0)
		str_append(str, " MESSAGES");
	if ((items & STATUS_RECENT) != 0)
		str_append(str, " RECENT");
	if ((items & STATUS_UIDNEXT) != 0)
		str_append(str, " UIDNEXT");
	if ((items & STATUS_UIDVALIDITY) != 0)
		str_append(str, " UIDVALIDITY");
	if ((items & STATUS_UNSEEN) != 0)
		str_append(str, " UNSEEN");
	if ((items & STATUS_HIGHESTMODSEQ) != 0)
		str_append(str, " HIGHESTMODSEQ");

	if (str_len(str) == 0) {
		/* nothing requested */
		return 0;
	}

	ctx.mbox = mbox;
	ctx.status = status_r;
	imapc_client_cmdf(mbox->storage->client,
			  imapc_mailbox_status_callback, &ctx,
			  "STATUS %s (%1s)", box->name, str_c(str));
	imapc_client_run(mbox->storage->client);
	return ctx.ret;
}

static int imapc_mailbox_get_metadata(struct mailbox *box,
				      enum mailbox_metadata_items items,
				      struct mailbox_metadata *metadata_r)
{
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			       "Not supported");
	return -1;
}

static void imapc_notify_changes(struct mailbox *box)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;

}

struct mail_storage imapc_storage = {
	.name = IMAPC_STORAGE_NAME,
	.class_flags = 0,

	.v = {
		NULL,
		imapc_storage_alloc,
		imapc_storage_create,
		imapc_storage_destroy,
		NULL,
		imapc_storage_get_list_settings,
		NULL,
		imapc_mailbox_alloc,
		NULL
	}
};

struct mailbox imapc_mailbox = {
	.v = {
		index_storage_is_readonly,
		index_storage_allow_new_keywords,
		index_storage_mailbox_enable,
		index_storage_mailbox_exists,
		imapc_mailbox_open,
		imapc_mailbox_close,
		index_storage_mailbox_free,
		imapc_mailbox_create,
		imapc_mailbox_update,
		index_storage_mailbox_delete,
		index_storage_mailbox_rename,
		imapc_mailbox_get_status,
		imapc_mailbox_get_metadata,
		NULL,
		NULL,
		imapc_mailbox_sync_init,
		index_mailbox_sync_next,
		imapc_mailbox_sync_deinit,
		NULL,
		imapc_notify_changes,
		index_transaction_begin,
		index_transaction_commit,
		index_transaction_rollback,
		NULL,
		index_mail_alloc,
		imapc_search_init,
		index_storage_search_deinit,
		imapc_search_next_nonblock,
		index_storage_search_next_update_seq,
		imapc_save_alloc,
		imapc_save_begin,
		imapc_save_continue,
		imapc_save_finish,
		imapc_save_cancel,
		mail_storage_copy,
		index_storage_is_inconsistent
	}
};
