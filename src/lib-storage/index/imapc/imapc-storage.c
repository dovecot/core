/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "imap-arg.h"
#include "imap-resp-code.h"
#include "mailbox-tree.h"
#include "imapc-client.h"
#include "imapc-connection.h"
#include "imapc-msgmap.h"
#include "imapc-mail.h"
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
				  struct imapc_storage_client *client);
static void imapc_untagged_namespace(const struct imapc_untagged_reply *reply,
				     struct imapc_storage_client *client);

bool imap_resp_text_code_parse(const char *str, enum mail_error *error_r)
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
	storage->root_ioloop = current_ioloop;
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
			       struct imapc_storage_client *client)
{
	memset(sctx, 0, sizeof(*sctx));
	sctx->client = client;
	sctx->ret = -2;
}

void imapc_simple_run(struct imapc_simple_context *sctx)
{
	while (sctx->ret == -2)
		imapc_client_run(sctx->client->client);
}

void imapc_storage_run(struct imapc_storage *storage)
{
	do {
		imapc_client_run(storage->client->client);
	} while (storage->reopen_count > 0);
}

void imapc_simple_callback(const struct imapc_command_reply *reply,
			   void *context)
{
	struct imapc_simple_context *ctx = context;

	if (reply->state == IMAPC_COMMAND_STATE_OK)
		ctx->ret = 0;
	else if (reply->state == IMAPC_COMMAND_STATE_NO) {
		imapc_copy_error_from_reply(ctx->client->_storage,
					    MAIL_ERROR_PARAMS, reply);
		ctx->ret = -1;
	} else {
		mail_storage_set_critical(&ctx->client->_storage->storage,
			"imapc: Command failed: %s", reply->text_full);
		ctx->ret = -1;
	}
	imapc_client_stop(ctx->client->client);
}

void imapc_mailbox_noop(struct imapc_mailbox *mbox)
{
	struct imapc_command *cmd;
	struct imapc_simple_context sctx;

	imapc_simple_context_init(&sctx, mbox->storage->client);
	cmd = imapc_client_mailbox_cmd(mbox->client_box,
				       imapc_simple_callback, &sctx);
	imapc_command_send(cmd, "NOOP");
	imapc_simple_run(&sctx);
}

static void
imapc_storage_client_untagged_cb(const struct imapc_untagged_reply *reply,
				 void *context)
{
	struct imapc_storage_client *client = context;
	struct imapc_mailbox *mbox = reply->untagged_box_context;
	const struct imapc_storage_event_callback *cb;
	const struct imapc_mailbox_event_callback *mcb;

	array_foreach(&client->untagged_callbacks, cb) {
		if (strcasecmp(reply->name, cb->name) == 0)
			cb->callback(reply, client);
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

int imapc_storage_client_create(struct mail_namespace *ns,
				const struct imapc_settings *imapc_set,
				const struct mail_storage_settings *mail_set,
				struct imapc_storage_client **client_r,
				const char **error_r)
{
	struct imapc_storage_client *client;
	struct imapc_client_settings set;
	string_t *str;

	memset(&set, 0, sizeof(set));
	set.host = imapc_set->imapc_host;
	if (*set.host == '\0') {
		*error_r = "missing imapc_host";
		return -1;
	}
	set.port = imapc_set->imapc_port;
	if (imapc_set->imapc_user[0] != '\0')
		set.username = imapc_set->imapc_user;
	else if (ns->owner != NULL)
		set.username = ns->owner->username;
	else
		set.username = ns->user->username;
	set.master_user = imapc_set->imapc_master_user;
	set.password = imapc_set->imapc_password;
	if (*set.password == '\0') {
		*error_r = "missing imapc_password";
		return -1;
	}
	set.max_idle_time = imapc_set->imapc_max_idle_time;
	set.dns_client_socket_path = *ns->user->set->base_dir == '\0' ? "" :
		t_strconcat(ns->user->set->base_dir, "/",
			    DNS_CLIENT_SOCKET_NAME, NULL);
	set.debug = mail_set->mail_debug;
	set.rawlog_dir = mail_user_home_expand(ns->user,
					       imapc_set->imapc_rawlog_dir);

	str = t_str_new(128);
	mail_user_set_get_temp_prefix(str, ns->user->set);
	set.temp_path_prefix = str_c(str);

	set.ssl_ca_dir = mail_set->ssl_client_ca_dir;
	set.ssl_ca_file = mail_set->ssl_client_ca_file;
	set.ssl_verify = imapc_set->imapc_ssl_verify;
	if (strcmp(imapc_set->imapc_ssl, "imaps") == 0)
		set.ssl_mode = IMAPC_CLIENT_SSL_MODE_IMMEDIATE;
	else if (strcmp(imapc_set->imapc_ssl, "starttls") == 0)
		set.ssl_mode = IMAPC_CLIENT_SSL_MODE_STARTTLS;
	else
		set.ssl_mode = IMAPC_CLIENT_SSL_MODE_NONE;
	set.ssl_crypto_device = mail_set->ssl_crypto_device;

	client = i_new(struct imapc_storage_client, 1);
	client->refcount = 1;
	i_array_init(&client->untagged_callbacks, 16);
	client->client = imapc_client_init(&set);
	imapc_client_register_untagged(client->client,
				       imapc_storage_client_untagged_cb, client);
	/* start logging in immediately */
	imapc_client_login(client->client, NULL, NULL);

	*client_r = client;
	return 0;
}

void imapc_storage_client_unref(struct imapc_storage_client **_client)
{
	struct imapc_storage_client *client = *_client;
	struct imapc_storage_event_callback *cb;

	*_client = NULL;

	i_assert(client->refcount > 0);
	if (--client->refcount > 0)
		return;
	imapc_client_deinit(&client->client);
	array_foreach_modifiable(&client->untagged_callbacks, cb)
		i_free(cb->name);
	array_free(&client->untagged_callbacks);
	i_free(client);
}

static int
imapc_storage_create(struct mail_storage *_storage,
		     struct mail_namespace *ns,
		     const char **error_r)
{
	struct imapc_storage *storage = (struct imapc_storage *)_storage;
	struct imapc_mailbox_list *imapc_list = NULL;

	storage->set = mail_storage_get_driver_settings(_storage);
	if (strcmp(ns->list->name, MAILBOX_LIST_NAME_IMAPC) == 0) {
		imapc_list = (struct imapc_mailbox_list *)ns->list;
		storage->client = imapc_list->client;
		storage->client->refcount++;
	} else {
		if (imapc_storage_client_create(ns, storage->set, _storage->set,
						&storage->client, error_r) < 0)
			return -1;
	}
	storage->client->_storage = storage;
	p_array_init(&storage->remote_namespaces, _storage->pool, 4);

	imapc_storage_client_register_untagged(storage->client, "STATUS",
					       imapc_untagged_status);
	imapc_storage_client_register_untagged(storage->client, "NAMESPACE",
					       imapc_untagged_namespace);
	return 0;
}

static void imapc_storage_destroy(struct mail_storage *_storage)
{
	struct imapc_storage *storage = (struct imapc_storage *)_storage;

	imapc_storage_client_unref(&storage->client);
	index_storage_destroy(_storage);
}

void imapc_storage_client_register_untagged(struct imapc_storage_client *client,
					    const char *name,
					    imapc_storage_callback_t *callback)
{
	struct imapc_storage_event_callback *cb;

	cb = array_append_space(&client->untagged_callbacks);
	cb->name = i_strdup(name);
	cb->callback = callback;
}

static void
imapc_storage_get_list_settings(const struct mail_namespace *ns ATTR_UNUSED,
				struct mailbox_list_settings *set)
{
	set->layout = MAILBOX_LIST_NAME_IMAPC;
	set->escape_char = IMAPC_LIST_ESCAPE_CHAR;
}

static struct mailbox *
imapc_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		    const char *vname, enum mailbox_flags flags)
{
	struct imapc_mailbox *mbox;
	pool_t pool;

	pool = pool_alloconly_create("imapc mailbox", 1024*4);
	mbox = p_new(pool, struct imapc_mailbox, 1);
	mbox->box = imapc_mailbox;
	mbox->box.pool = pool;
	mbox->box.storage = storage;
	mbox->box.list = list;
	mbox->box.mail_vfuncs = &imapc_mail_vfuncs;

	index_storage_mailbox_alloc(&mbox->box, vname, flags, MAIL_INDEX_PREFIX);

	mbox->storage = (struct imapc_storage *)storage;

	p_array_init(&mbox->untagged_callbacks, pool, 16);
	p_array_init(&mbox->resp_text_callbacks, pool, 16);
	p_array_init(&mbox->fetch_mails, pool, 16);
	p_array_init(&mbox->delayed_expunged_uids, pool, 16);
	mbox->prev_mail_cache.fd = -1;
	imapc_mailbox_register_callbacks(mbox);
	return &mbox->box;
}

static int
imapc_mailbox_exists(struct mailbox *box, bool auto_boxes ATTR_UNUSED,
		     enum mailbox_existence *existence_r)
{
	enum mailbox_info_flags flags;

	if (imapc_list_get_mailbox_flags(box->list, box->name, &flags) < 0)
		return -1;
	if ((flags & MAILBOX_NONEXISTENT) != 0)
		*existence_r = MAILBOX_EXISTENCE_NONE;
	else if ((flags & MAILBOX_NOSELECT) != 0)
		*existence_r = MAILBOX_EXISTENCE_NOSELECT;
	else
		*existence_r = MAILBOX_EXISTENCE_SELECT;
	return 0;
}

static bool imapc_mailbox_want_examine(struct imapc_mailbox *mbox)
{
	return (mbox->box.flags & MAILBOX_FLAG_DROP_RECENT) == 0 &&
		((mbox->box.flags & MAILBOX_FLAG_READONLY) != 0 ||
		 (mbox->box.flags & MAILBOX_FLAG_SAVEONLY) != 0);
}

static void
imapc_mailbox_reopen_callback(const struct imapc_command_reply *reply,
			      void *context)
{
	struct imapc_mailbox *mbox = context;

	i_assert(mbox->storage->reopen_count > 0);
	mbox->storage->reopen_count--;
	mbox->selecting = FALSE;
	if (reply->state != IMAPC_COMMAND_STATE_OK) {
		mail_storage_set_critical(mbox->box.storage,
			"imapc: Reopening mailbox '%s' failed: %s",
			mbox->box.name, reply->text_full);
		imapc_client_mailbox_reconnect(mbox->client_box);
	}
	imapc_client_stop(mbox->storage->client->client);
}

static void imapc_mailbox_reopen(void *context)
{
	struct imapc_mailbox *mbox = context;
	struct imapc_command *cmd;

	/* we're reconnecting and need to reopen the mailbox */
	mbox->initial_sync_done = FALSE;
	mbox->selecting = TRUE;
	mbox->prev_skipped_rseq = 0;
	mbox->prev_skipped_uid = 0;
	imapc_msgmap_reset(imapc_client_mailbox_get_msgmap(mbox->client_box));

	cmd = imapc_client_mailbox_cmd(mbox->client_box,
				       imapc_mailbox_reopen_callback, mbox);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_SELECT);
	if (imapc_mailbox_want_examine(mbox))
		imapc_command_sendf(cmd, "EXAMINE %s", mbox->box.name);
	else
		imapc_command_sendf(cmd, "SELECT %s", mbox->box.name);
	mbox->storage->reopen_count++;

	if (mbox->syncing)
		imapc_sync_mailbox_reopened(mbox);
}

static void
imapc_mailbox_open_callback(const struct imapc_command_reply *reply,
			    void *context)
{
	struct imapc_open_context *ctx = context;

	ctx->mbox->selecting = FALSE;
	ctx->mbox->selected = TRUE;
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
	imapc_client_stop(ctx->mbox->storage->client->client);
}

static void imapc_mailbox_get_extensions(struct imapc_mailbox *mbox)
{
	enum imapc_capability capa =
		imapc_client_get_capabilities(mbox->storage->client->client);

	if (mbox->guid_fetch_field_name == NULL) {
		/* see if we can get message GUIDs somehow */
		if ((capa & IMAPC_CAPABILITY_X_GM_EXT_1) != 0) {
			/* GMail */
			mbox->guid_fetch_field_name = "X-GM-MSGID";
		}
	}
}

int imapc_mailbox_select(struct imapc_mailbox *mbox)
{
	struct imapc_command *cmd;
	struct imapc_open_context ctx;

	i_assert(mbox->client_box == NULL);

	mbox->client_box =
		imapc_client_mailbox_open(mbox->storage->client->client, mbox);
	imapc_client_mailbox_set_reopen_cb(mbox->client_box,
					   imapc_mailbox_reopen, mbox);

	imapc_mailbox_get_extensions(mbox);

	mbox->selecting = TRUE;
	ctx.mbox = mbox;
	ctx.ret = -2;
	cmd = imapc_client_mailbox_cmd(mbox->client_box,
				       imapc_mailbox_open_callback, &ctx);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_SELECT);
	if (imapc_mailbox_want_examine(mbox))
		imapc_command_sendf(cmd, "EXAMINE %s", mbox->box.name);
	else
		imapc_command_sendf(cmd, "SELECT %s", mbox->box.name);

	while (ctx.ret == -2)
		imapc_storage_run(mbox->storage);
	return ctx.ret;
}

static int imapc_mailbox_open(struct mailbox *box)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;

	if (index_storage_mailbox_open(box, FALSE) < 0)
		return -1;

	if (box->deleting || (box->flags & MAILBOX_FLAG_SAVEONLY) != 0) {
		/* We don't actually want to SELECT the mailbox. */
		return 0;
	}

	if (*box->name == '\0' &&
	    (box->list->ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0) {
		/* trying to open INBOX as the namespace prefix.
		   Don't allow this. */
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
				       "Mailbox isn't selectable");
		mailbox_close(box);
		return -1;
	}

	if (imapc_mailbox_select(mbox) < 0) {
		mailbox_close(box);
		return -1;
	}
	return 0;
}

void imapc_mail_cache_free(struct imapc_mail_cache *cache)
{
	if (cache->fd != -1) {
		if (close(cache->fd) < 0)
			i_error("close(imapc cached mail) failed: %m");
		cache->fd = -1;
	}
	if (cache->buf != NULL)
		buffer_free(&cache->buf);
	cache->uid = 0;
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
			mailbox_set_index_error(&mbox->box);
	}
	if (mbox->sync_view != NULL)
		mail_index_view_close(&mbox->sync_view);
	if (mbox->to_idle_delay != NULL)
		timeout_remove(&mbox->to_idle_delay);
	if (mbox->to_idle_check != NULL)
		timeout_remove(&mbox->to_idle_check);
	imapc_mail_cache_free(&mbox->prev_mail_cache);
	index_storage_mailbox_close(box);
}

static int
imapc_mailbox_create(struct mailbox *box,
		     const struct mailbox_update *update ATTR_UNUSED,
		     bool directory)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;
	struct imapc_command *cmd;
	struct imapc_simple_context sctx;
	const char *name = box->name;

	if (directory) {
		name = t_strdup_printf("%s%c", name,
				mailbox_list_get_hierarchy_sep(box->list));
	}
	imapc_simple_context_init(&sctx, mbox->storage->client);
	cmd = imapc_client_cmd(mbox->storage->client->client,
			       imapc_simple_callback, &sctx);
	imapc_command_sendf(cmd, "CREATE %s", name);
	imapc_simple_run(&sctx);
	return sctx.ret;
}

static int imapc_mailbox_update(struct mailbox *box,
				const struct mailbox_update *update)
{
	if (!guid_128_is_empty(update->mailbox_guid) ||
	    update->uid_validity != 0 || update->min_next_uid != 0 ||
	    update->min_first_recent_uid != 0) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
				       "Not supported");
	}
	return index_storage_mailbox_update(box, update);
}

static void imapc_untagged_status(const struct imapc_untagged_reply *reply,
				  struct imapc_storage_client *client)
{
	struct imapc_storage *storage = client->_storage;
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
	}
}

static void imapc_untagged_namespace(const struct imapc_untagged_reply *reply,
				     struct imapc_storage_client *client)
{
	struct imapc_storage *storage = client->_storage;
	static enum mail_namespace_type ns_types[] = {
		MAIL_NAMESPACE_TYPE_PRIVATE,
		MAIL_NAMESPACE_TYPE_SHARED,
		MAIL_NAMESPACE_TYPE_PUBLIC
	};
	struct imapc_namespace *ns;
	const struct imap_arg *list, *list2;
	const char *prefix, *sep;
	unsigned int i;

	array_clear(&storage->remote_namespaces);
	for (i = 0; i < N_ELEMENTS(ns_types); i++) {
		if (reply->args[i].type == IMAP_ARG_NIL)
			continue;
		if (!imap_arg_get_list(&reply->args[i], &list))
			break;

		for (; list->type != IMAP_ARG_EOL; list++) {
			if (!imap_arg_get_list(list, &list2) ||
			    !imap_arg_get_astring(&list2[0], &prefix) ||
			    !imap_arg_get_nstring(&list2[1], &sep))
				break;

			ns = array_append_space(&storage->remote_namespaces);
			ns->prefix = p_strdup(storage->storage.pool, prefix);
			ns->separator = sep == NULL ? '\0' : sep[0];
			ns->type = ns_types[i];
		}
	}
}

static void imapc_mailbox_get_selected_status(struct imapc_mailbox *mbox,
					      enum mailbox_status_items items,
					      struct mailbox_status *status_r)
{
	index_storage_get_open_status(&mbox->box, items, status_r);
	if ((items & STATUS_PERMANENT_FLAGS) != 0)
		status_r->permanent_flags = mbox->permanent_flags;
}

static int imapc_mailbox_delete(struct mailbox *box)
{
	box->delete_skip_empty_check = TRUE;
	return index_storage_mailbox_delete(box);
}

static int imapc_mailbox_get_status(struct mailbox *box,
				    enum mailbox_status_items items,
				    struct mailbox_status *status_r)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;
	struct imapc_command *cmd;
	struct imapc_simple_context sctx;
	string_t *str;

	if (mbox->guid_fetch_field_name != NULL ||
	    IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_GUID_FORCED))
		status_r->have_guids = TRUE;

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

	if (str_len(str) == 0) {
		/* nothing requested */
		return 0;
	}

	imapc_simple_context_init(&sctx, mbox->storage->client);
	mbox->storage->cur_status_box = mbox;
	mbox->storage->cur_status = status_r;
	cmd = imapc_client_cmd(mbox->storage->client->client,
			       imapc_simple_callback, &sctx);
	imapc_command_sendf(cmd, "STATUS %s (%1s)", box->name, str_c(str)+1);
	imapc_simple_run(&sctx);
	mbox->storage->cur_status_box = NULL;
	mbox->storage->cur_status = NULL;
	return sctx.ret;
}

static int imapc_mailbox_get_namespaces(struct imapc_storage *storage)
{
	enum imapc_capability capa;
	struct imapc_command *cmd;
	struct imapc_simple_context sctx;

	if (storage->namespaces_requested)
		return 0;

	capa = imapc_client_get_capabilities(storage->client->client);
	if ((capa & IMAPC_CAPABILITY_NAMESPACE) == 0) {
		/* NAMESPACE capability not supported */
		return 0;
	}

	imapc_simple_context_init(&sctx, storage->client);
	cmd = imapc_client_cmd(storage->client->client,
			       imapc_simple_callback, &sctx);
	imapc_command_send(cmd, "NAMESPACE");
	imapc_simple_run(&sctx);

	if (sctx.ret < 0)
		return -1;
	storage->namespaces_requested = TRUE;
	return 0;
}

static const struct imapc_namespace *
imapc_namespace_find_mailbox(struct imapc_storage *storage, const char *name)
{
	const struct imapc_namespace *ns, *best_ns = NULL;
	unsigned int best_len = UINT_MAX, len;

	array_foreach(&storage->remote_namespaces, ns) {
		len = strlen(ns->prefix);
		if (strncmp(ns->prefix, name, len) == 0) {
			if (best_len > len) {
				best_ns = ns;
				best_len = len;
			}
		}
	}
	return best_ns;
}

static int imapc_mailbox_get_metadata(struct mailbox *box,
				      enum mailbox_metadata_items items,
				      struct mailbox_metadata *metadata_r)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;
	const struct imapc_namespace *ns;

	if ((items & MAILBOX_METADATA_GUID) != 0) {
		/* a bit ugly way to do this, but better than nothing for now.
		   FIXME: if indexes are enabled, keep this there. */
		mail_generate_guid_128_hash(box->name, metadata_r->guid);
		items &= ~MAILBOX_METADATA_GUID;
	}
	if ((items & MAILBOX_METADATA_BACKEND_NAMESPACE) != 0) {
		if (imapc_mailbox_get_namespaces(mbox->storage) < 0)
			return -1;

		ns = imapc_namespace_find_mailbox(mbox->storage, box->name);
		if (ns != NULL) {
			metadata_r->backend_ns_prefix = ns->prefix;
			metadata_r->backend_ns_type = ns->type;
		}
		items &= ~MAILBOX_METADATA_BACKEND_NAMESPACE;
	}
	if (items != 0) {
		if (index_mailbox_get_metadata(box, items, metadata_r) < 0)
			return -1;
	}
	return 0;
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

static void imapc_idle_timeout(struct imapc_mailbox *mbox)
{
	struct imapc_command *cmd;

	cmd = imapc_client_mailbox_cmd(mbox->client_box,
				       imapc_noop_callback, mbox->storage);
	imapc_command_send(cmd, "NOOP");
}

static void imapc_idle_noop_callback(const struct imapc_command_reply *reply,
				     void *context)

{
	struct imapc_mailbox *mbox = context;

	imapc_noop_callback(reply, mbox->box.storage);
	if (mbox->client_box != NULL)
		imapc_client_mailbox_idle(mbox->client_box);
}

static void imapc_notify_changes(struct mailbox *box)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;
	const struct mail_storage_settings *set = box->storage->set;
	struct imapc_command *cmd;
	enum imapc_capability capa;

	if (box->notify_callback == NULL) {
		if (mbox->to_idle_check != NULL)
			timeout_remove(&mbox->to_idle_check);
		return;
	}

	capa = imapc_client_get_capabilities(mbox->storage->client->client);
	if ((capa & IMAPC_CAPABILITY_IDLE) != 0) {
		/* remote server is already in IDLE. but since some servers
		   don't notice changes immediately, we'll force them to check
		   here by sending a NOOP. this helps with clients that break
		   IDLE when clicking "get mail". */
		cmd = imapc_client_mailbox_cmd(mbox->client_box,
					       imapc_idle_noop_callback, mbox);
		imapc_command_send(cmd, "NOOP");
	} else {
		/* remote server doesn't support IDLE.
		   check for changes with NOOP every once in a while. */
		i_assert(!imapc_client_is_running(mbox->storage->client->client));
		mbox->to_idle_check =
			timeout_add(set->mailbox_idle_check_interval * 1000,
				    imapc_idle_timeout, mbox);
	}
}

static bool imapc_is_inconsistent(struct mailbox *box)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)box;

	if (mail_index_view_is_inconsistent(box->view))
		return TRUE;

	return !imapc_client_mailbox_is_opened(mbox->client_box);
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
		imapc_mailbox_exists,
		imapc_mailbox_open,
		imapc_mailbox_close,
		index_storage_mailbox_free,
		imapc_mailbox_create,
		imapc_mailbox_update,
		imapc_mailbox_delete,
		index_storage_mailbox_rename,
		imapc_mailbox_get_status,
		imapc_mailbox_get_metadata,
		index_storage_set_subscribed,
		index_storage_attribute_set,
		index_storage_attribute_get,
		index_storage_attribute_iter_init,
		index_storage_attribute_iter_next,
		index_storage_attribute_iter_deinit,
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
