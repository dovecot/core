/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "imap-arg.h"
#include "imap-resp-code.h"
#include "imapc-mail.h"
#include "imapc-client-private.h"
#include "imapc-connection.h"
#include "imapc-list.h"
#include "imapc-sync.h"
#include "imapc-settings.h"
#include "imapc-storage.h"

#define DNS_CLIENT_SOCKET_NAME "dns-client"

struct imapc_open_context {
	struct imapc_mailbox *mbox;
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

static void imapc_untagged_status(const struct imapc_untagged_reply *reply,
				  struct imapc_storage *storage);

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

	pool = pool_alloconly_create("imapc storage", 2048);
	storage = p_new(pool, struct imapc_storage, 1);
	storage->storage = imapc_storage;
	storage->storage.pool = pool;
	return &storage->storage;
}

void imapc_copy_error_from_reply(struct imapc_storage *storage,
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

void imapc_simple_context_init(struct imapc_simple_context *sctx,
			       struct imapc_storage *storage)
{
	memset(sctx, 0, sizeof(*sctx));
	sctx->storage = storage;
	sctx->ret = -2;
}

void imapc_simple_run(struct imapc_simple_context *sctx)
{
	while (sctx->ret == -2)
		imapc_storage_run(sctx->storage);
}

void imapc_storage_run(struct imapc_storage *storage)
{
	struct imapc_client_mailbox *client_box;
	struct imapc_client_connection *const *connp;
	struct imapc_mailbox *mbox;

	imapc_client_run_pre(storage->client);

	array_foreach(&storage->client->conns, connp) {
		client_box = imapc_connection_get_mailbox((*connp)->conn);
		if (client_box == NULL)
			continue;

		mbox = client_box->untagged_box_context;
		if (mbox->to_idle_delay != NULL)
			mbox->to_idle_delay = io_loop_move_timeout(&mbox->to_idle_delay);
	}

	imapc_client_run_post(storage->client);
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

static void imapc_noop_callback(const struct imapc_command_reply *reply,
				void *context)

{
	struct imapc_storage *storage = context;

	if (reply->state == IMAPC_COMMAND_STATE_OK)
		;
	else if (reply->state == IMAPC_COMMAND_STATE_NO)
		imapc_copy_error_from_reply(storage, MAIL_ERROR_PARAMS, reply);
	else if (reply->state == IMAPC_COMMAND_STATE_DISCONNECTED)
		mail_storage_set_internal_error(&storage->storage);
	else {
		mail_storage_set_critical(&storage->storage,
			"imapc: NOOP failed: %s", reply->text_full);
	}
}

void imapc_noop_stop_callback(const struct imapc_command_reply *reply,
			       void *context)
{
	struct imapc_storage *storage = context;

	imapc_noop_callback(reply, context);
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
imapc_storage_get_hierarchy_sep(struct imapc_storage *storage,
				const char **error_r)
{
	struct imapc_simple_context sctx;

	imapc_simple_context_init(&sctx, storage);
	imapc_client_cmdf(storage->client, imapc_simple_callback, &sctx,
			  "LIST \"\" \"\"");
	imapc_simple_run(&sctx);

	if (sctx.ret < 0) {
		*error_r = t_strdup_printf("LIST failed: %s",
			mail_storage_get_last_error(&storage->storage, NULL));
		return -1;
	}

	if (storage->list->sep == '\0') {
		*error_r = "LIST didn't return hierarchy separator";
		return -1;
	}
	return sctx.ret;
}

static int
imapc_storage_create(struct mail_storage *_storage,
		     struct mail_namespace *ns,
		     const char **error_r)
{
	struct imapc_storage *storage = (struct imapc_storage *)_storage;
	struct imapc_client_settings set;
	string_t *str;

	storage->set = mail_storage_get_driver_settings(_storage);

	memset(&set, 0, sizeof(set));
	set.host = storage->set->imapc_host;
	if (*set.host == '\0') {
		*error_r = "missing imapc_host";
		return -1;
	}
	set.port = storage->set->imapc_port;
	set.username = storage->set->imapc_user;
	set.password = storage->set->imapc_password;
	if (*set.password == '\0') {
		*error_r = "missing imapc_password";
		return -1;
	}
	set.dns_client_socket_path =
		t_strconcat(_storage->user->set->base_dir, "/",
			    DNS_CLIENT_SOCKET_NAME, NULL);
	set.debug = _storage->set->mail_debug;

	str = t_str_new(128);
	mail_user_set_get_temp_prefix(str, _storage->user->set);
	set.temp_path_prefix = str_c(str);

	set.ssl_ca_dir = storage->set->imapc_ssl_ca_dir;
	if (strcmp(storage->set->imapc_ssl, "imaps") == 0)
		set.ssl_mode = IMAPC_CLIENT_SSL_MODE_IMMEDIATE;
	else if (strcmp(storage->set->imapc_ssl, "starttls") == 0)
		set.ssl_mode = IMAPC_CLIENT_SSL_MODE_STARTTLS;
	else
		set.ssl_mode = IMAPC_CLIENT_SSL_MODE_NONE;

	storage->list = (struct imapc_mailbox_list *)ns->list;
	storage->list->storage = storage;
	storage->client = imapc_client_init(&set);

	p_array_init(&storage->untagged_callbacks, _storage->pool, 16);
	imapc_client_register_untagged(storage->client,
				       imapc_storage_untagged_cb, storage);
	imapc_list_register_callbacks(storage->list);
	imapc_storage_register_untagged(storage, "STATUS",
					imapc_untagged_status);
	/* connect to imap server and get the hierarchy separator. */
	if (imapc_storage_get_hierarchy_sep(storage, error_r) < 0) {
		imapc_client_deinit(&storage->client);
		return -1;
	}
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
	pool_t pool;

	pool = pool_alloconly_create("imapc mailbox", 1024*3);
	mbox = p_new(pool, struct imapc_mailbox, 1);
	mbox->box = imapc_mailbox;
	mbox->box.pool = pool;
	mbox->box.storage = storage;
	mbox->box.list = list;
	mbox->box.mail_vfuncs = &imapc_mail_vfuncs;

	index_storage_mailbox_alloc(&mbox->box, vname, flags,
				    IMAPC_INDEX_PREFIX);

	mbox->storage = (struct imapc_storage *)storage;

	p_array_init(&mbox->untagged_callbacks, pool, 16);
	p_array_init(&mbox->resp_text_callbacks, pool, 16);
	p_array_init(&mbox->fetch_mails, pool, 16);
	p_array_init(&mbox->permanent_keywords, pool, 32);
	p_array_init(&mbox->delayed_expunged_uids, pool, 16);
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
	imapc_client_stop(ctx->mbox->storage->client);
}

static int imapc_mailbox_open(struct mailbox *box)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;
	struct imapc_open_context ctx;
	bool examine;

	if (index_storage_mailbox_open(box, FALSE) < 0)
		return -1;

	if (box->deleting || (box->flags & MAILBOX_FLAG_SAVEONLY) != 0) {
		/* We don't actually want to SELECT the mailbox. */
		return 0;
	}
	examine = (box->flags & MAILBOX_FLAG_READONLY) != 0 &&
		(box->flags & MAILBOX_FLAG_DROP_RECENT) == 0;

	if (*box->name == '\0' &&
	    (box->list->ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0) {
		/* trying to open INBOX as the namespace prefix.
		   Don't allow this. */
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
				       "Mailbox isn't selectable");
		mailbox_close(box);
		return -1;
	}

	mbox->opening = TRUE;
	ctx.mbox = mbox;
	ctx.ret = -2;
	mbox->client_box =
		imapc_client_mailbox_open(mbox->storage->client, box->name,
					  examine, imapc_mailbox_open_callback,
					  &ctx, mbox);
	while (ctx.ret == -2)
		imapc_storage_run(mbox->storage);
	mbox->opening = FALSE;
	if (ctx.ret < 0) {
		mailbox_close(box);
		return -1;
	}
	return 0;
}

static void imapc_mailbox_close(struct mailbox *box)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;

	if (mbox->client_box != NULL)
		imapc_client_mailbox_close(&mbox->client_box);
	if (mbox->delayed_sync_view != NULL)
		mail_index_view_close(&mbox->delayed_sync_view);
	if (mbox->delayed_sync_trans != NULL) {
		if (mail_index_transaction_commit(&mbox->delayed_sync_trans) < 0)
			mail_storage_set_index_error(&mbox->box);
	}
	if (mbox->sync_view != NULL)
		mail_index_view_close(&mbox->sync_view);
	if (mbox->to_idle_delay != NULL)
		timeout_remove(&mbox->to_idle_delay);
	if (mbox->to_idle_check != NULL)
		timeout_remove(&mbox->to_idle_check);
	return index_storage_mailbox_close(box);
}

static int
imapc_mailbox_create(struct mailbox *box,
		     const struct mailbox_update *update ATTR_UNUSED,
		     bool directory)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;
	struct imapc_simple_context sctx;
	const char *name = box->name;

	if (directory) {
		name = t_strdup_printf("%s%c", name,
				mailbox_list_get_hierarchy_sep(box->list));
	}
	imapc_simple_context_init(&sctx, mbox->storage);
	imapc_client_cmdf(mbox->storage->client, imapc_simple_callback, &sctx,
			  "CREATE %s", name);
	imapc_simple_run(&sctx);
	return sctx.ret;
}

static int imapc_mailbox_update(struct mailbox *box,
				const struct mailbox_update *update ATTR_UNUSED)
{
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			       "Not supported");
	return -1;
}

static void imapc_untagged_status(const struct imapc_untagged_reply *reply,
				  struct imapc_storage *storage)
{
	struct mailbox_status *status;
	const struct imap_arg *list;
	const char *name, *key, *value;
	uint32_t num;
	unsigned int i;

	if (!imap_arg_get_astring(&reply->args[0], &name) ||
	    !imap_arg_get_list(&reply->args[1], &list))
		return;

	if (storage->cur_status_box == NULL ||
	    strcmp(storage->cur_status_box->box.name, name) != 0)
		return;

	status = storage->cur_status;
	for (i = 0; list[i].type != IMAP_ARG_EOL; i += 2) {
		if (!imap_arg_get_atom(&list[i], &key) ||
		    !imap_arg_get_atom(&list[i+1], &value) ||
		    str_to_uint32(value, &num) < 0)
			return;

		if (strcasecmp(key, "MESSAGES") == 0)
			status->messages = num;
		else if (strcasecmp(key, "RECENT") == 0)
			status->recent = num;
		else if (strcasecmp(key, "UIDNEXT") == 0)
			status->uidnext = num;
		else if (strcasecmp(key, "UIDVALIDITY") == 0)
			status->uidvalidity = num;
		else if (strcasecmp(key, "UNSEEN") == 0)
			status->unseen = num;
		else if (strcasecmp(key, "HIGHESTMODSEQ") == 0)
			status->highest_modseq = num;
	}
}

static void imapc_mailbox_get_selected_status(struct imapc_mailbox *mbox,
					      enum mailbox_status_items items,
					      struct mailbox_status *status_r)
{
	index_storage_get_status(&mbox->box, items, status_r);
	if ((items & STATUS_KEYWORDS) != 0)
		status_r->keywords = &mbox->permanent_keywords;
	if ((items & STATUS_PERMANENT_FLAGS) != 0)
		status_r->permanent_flags = mbox->permanent_flags;
}

static int imapc_mailbox_get_status(struct mailbox *box,
				    enum mailbox_status_items items,
				    struct mailbox_status *status_r)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;
	struct imapc_simple_context sctx;
	string_t *str;

	memset(status_r, 0, sizeof(*status_r));

	if (box->opened) {
		imapc_mailbox_get_selected_status(mbox, items, status_r);
		return 0;
	}

	/* mailbox isn't opened yet */
	if ((items & (STATUS_FIRST_UNSEEN_SEQ | STATUS_KEYWORDS |
		      STATUS_PERMANENT_FLAGS)) != 0) {
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

	imapc_simple_context_init(&sctx, mbox->storage);
	mbox->storage->cur_status_box = mbox;
	mbox->storage->cur_status = status_r;
	imapc_client_cmdf(mbox->storage->client, imapc_simple_callback, &sctx,
			  "STATUS %s (%1s)", box->name, str_c(str)+1);
	imapc_simple_run(&sctx);
	mbox->storage->cur_status_box = NULL;
	mbox->storage->cur_status = NULL;
	return sctx.ret;
}

static int imapc_mailbox_get_metadata(struct mailbox *box,
				      enum mailbox_metadata_items items,
				      struct mailbox_metadata *metadata_r)
{
	if ((items & MAILBOX_METADATA_GUID) != 0) {
		/* a bit ugly way to do this, but better than nothing for now.
		   FIXME: if indexes are enabled, keep this there. */
		mail_generate_guid_128_hash(box->name, metadata_r->guid);
	}
	return index_mailbox_get_metadata(box, items, metadata_r);
}

static void imapc_idle_timeout(struct imapc_mailbox *mbox)
{
	imapc_client_mailbox_cmd(mbox->client_box, "NOOP",
				 imapc_noop_callback, mbox->storage);
}

static void imapc_idle_noop_callback(const struct imapc_command_reply *reply,
				     void *context)

{
	struct imapc_mailbox *mbox = context;

	imapc_noop_callback(reply, mbox->box.storage);
	imapc_client_mailbox_idle(mbox->client_box);
}

static void imapc_notify_changes(struct mailbox *box)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;
	enum imapc_capability capa;

	if (box->notify_min_interval == 0) {
		if (mbox->to_idle_check != NULL)
			timeout_remove(&mbox->to_idle_check);
		return;
	}

	capa = imapc_client_get_capabilities(mbox->storage->client);
	if ((capa & IMAPC_CAPABILITY_IDLE) != 0) {
		/* remote server is already in IDLE. but since some servers
		   don't notice changes immediately, we'll force them to check
		   here by sending a NOOP. this helps with clients that break
		   IDLE when clicking "get mail". */
		imapc_client_mailbox_cmd(mbox->client_box, "NOOP",
					 imapc_idle_noop_callback, mbox);
	} else {
		/* remote server doesn't support IDLE.
		   check for changes with NOOP every once in a while. */
		i_assert(!imapc_client_is_running(mbox->storage->client));
		mbox->to_idle_check =
			timeout_add(box->notify_min_interval * 1000,
				    imapc_idle_timeout, mbox);
	}
}

static bool imapc_is_inconsistent(struct mailbox *box)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;

	if (mail_index_view_is_inconsistent(box->view))
		return TRUE;

	return !imapc_client_mailbox_is_connected(mbox->client_box);
}

struct mail_storage imapc_storage = {
	.name = IMAPC_STORAGE_NAME,
	.class_flags = MAIL_STORAGE_CLASS_FLAG_NO_ROOT,

	.v = {
		imapc_get_setting_parser_info,
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
		imapc_mail_alloc,
		index_storage_search_init,
		index_storage_search_deinit,
		index_storage_search_next_nonblock,
		index_storage_search_next_update_seq,
		imapc_save_alloc,
		imapc_save_begin,
		imapc_save_continue,
		imapc_save_finish,
		imapc_save_cancel,
		imapc_copy,
		imapc_transaction_save_commit_pre,
		imapc_transaction_save_commit_post,
		imapc_transaction_save_rollback,
		imapc_is_inconsistent
	}
};
