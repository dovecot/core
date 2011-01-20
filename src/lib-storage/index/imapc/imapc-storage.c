/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "imap-util.h"
#include "imap-arg.h"
#include "imap-resp-code.h"
#include "mail-copy.h"
#include "index-mail.h"
#include "mailbox-list-private.h"
#include "imapc-client.h"
#include "imapc-list.h"
#include "imapc-seqmap.h"
#include "imapc-sync.h"
#include "imapc-storage.h"

#include <sys/stat.h>

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
	const char *p;

	if (imap_resp_text_code_parse(reply->resp_text, &error)) {
		p = strchr(reply->text, ']');
		i_assert(p != NULL);
		mail_storage_set_error(&storage->storage, error, p + 1);
	} else {
		mail_storage_set_error(&storage->storage, default_error,
				       reply->text);
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
			"imapc: Command failed: %s", reply->text);
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
			"imapc: Command failed: %s", reply->text);
	}
	imapc_client_stop(storage->client);
}

static void
imapc_mailbox_map_new_msgs(struct imapc_mailbox *mbox,
			   struct imapc_seqmap *seqmap, uint32_t rcount)
{
	const struct mail_index_header *hdr;
	uint32_t next_lseq, next_rseq;

	next_lseq = mail_index_view_get_messages_count(mbox->box.view) + 1;
	next_rseq = imapc_seqmap_lseq_to_rseq(seqmap, next_lseq);
	if (next_rseq > rcount)
		return;

	hdr = mail_index_get_header(mbox->box.view);

	mbox->new_msgs = TRUE;
	imapc_client_mailbox_cmdf(mbox->client_box, imapc_async_stop_callback,
				  mbox->storage, "UID FETCH %u:* FLAGS",
				  hdr->next_uid);
}

static void
imapc_mailbox_map_fetch_reply(struct imapc_mailbox *mbox,
			      const struct imap_arg *args, uint32_t seq)
{
	struct imapc_seqmap *seqmap;
	const struct imap_arg *list, *flags_list;
	const char *atom;
	const struct mail_index_record *rec;
	enum mail_flags flags;
	uint32_t uid, old_count;
	unsigned int i, j;
	bool seen_flags = FALSE;

	if (seq == 0 || !imap_arg_get_list(args, &list))
		return;

	uid = 0; flags = 0;
	for (i = 0; list[i].type != IMAP_ARG_EOL; i += 2) {
		if (!imap_arg_get_atom(&list[i], &atom))
			return;

		if (strcasecmp(atom, "UID") == 0) {
			if (!imap_arg_get_atom(&list[i+1], &atom) ||
			    str_to_uint32(atom, &uid) < 0)
				return;
		} else if (strcasecmp(atom, "FLAGS") == 0) {
			if (!imap_arg_get_list(&list[i+1], &flags_list))
				return;

			seen_flags = TRUE;
			for (j = 0; flags_list[j].type != IMAP_ARG_EOL; j++) {
				if (!imap_arg_get_atom(&flags_list[j], &atom))
					return;
				if (atom[0] == '\\')
					flags |= imap_parse_system_flag(atom);
			}
		}
	}

	seqmap = imapc_client_mailbox_get_seqmap(mbox->client_box);
	seq = imapc_seqmap_rseq_to_lseq(seqmap, seq);

	if (mbox->cur_fetch_mail != NULL && mbox->cur_fetch_mail->seq == seq) {
		i_assert(uid == 0 || mbox->cur_fetch_mail->uid == uid);
		imapc_fetch_mail_update(mbox->cur_fetch_mail, list);
	}

	old_count = mail_index_view_get_messages_count(mbox->delayed_sync_view);
	if (seq > old_count) {
		if (uid == 0)
			return;
		i_assert(seq == old_count + 1);
		mail_index_append(mbox->delayed_sync_trans, uid, &seq);
	}
	rec = mail_index_lookup(mbox->delayed_sync_view, seq);
	if (seen_flags && rec->flags != flags) {
		mail_index_update_flags(mbox->delayed_sync_trans, seq,
					MODIFY_REPLACE, flags);
	}
}

static void imapc_storage_untagged_cb(const struct imapc_untagged_reply *reply,
				      void *context)
{
	struct imapc_storage *storage = context;
	struct imapc_mailbox *mbox = reply->untagged_box_context;
	struct imapc_seqmap *seqmap;
	uint32_t lseq;

	if (strcasecmp(reply->name, "LIST") == 0)
		imapc_list_update_mailbox(storage->list, reply->args);
	else if (strcasecmp(reply->name, "LSUB") == 0)
		imapc_list_update_subscription(storage->list, reply->args);

	if (mbox == NULL)
		return;

	if (reply->resp_text != NULL) {
		uint32_t uid_validity, uid_next;

		if (strncasecmp(reply->resp_text, "UIDVALIDITY ", 12) == 0 &&
		    str_to_uint32(reply->resp_text + 12, &uid_validity) == 0) {
			mail_index_update_header(mbox->delayed_sync_trans,
				offsetof(struct mail_index_header, uid_validity),
				&uid_validity, sizeof(uid_validity), TRUE);
		}
		if (strncasecmp(reply->resp_text, "UIDNEXT ", 8) == 0 &&
		    str_to_uint32(reply->resp_text + 8, &uid_next) == 0) {
			mail_index_update_header(mbox->delayed_sync_trans,
				offsetof(struct mail_index_header, next_uid),
				&uid_next, sizeof(uid_next), FALSE);
		}
	}

	seqmap = imapc_client_mailbox_get_seqmap(mbox->client_box);
	if (strcasecmp(reply->name, "EXISTS") == 0) {
		imapc_mailbox_map_new_msgs(mbox, seqmap, reply->num);
	} else if (strcasecmp(reply->name, "FETCH") == 0) {
		imapc_mailbox_map_fetch_reply(mbox, reply->args, reply->num);
	} else if (strcasecmp(reply->name, "EXPUNGE") == 0) {
		lseq = imapc_seqmap_rseq_to_lseq(seqmap, reply->num);
		mail_index_expunge(mbox->delayed_sync_trans, lseq);
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
	storage->list = (struct imapc_list *)ns->list;
	storage->list->storage = storage;
	storage->client = imapc_client_init(&set);
	imapc_client_register_untagged(storage->client,
				       imapc_storage_untagged_cb, storage);
	return 0;
}

static void imapc_storage_destroy(struct mail_storage *_storage)
{
	struct imapc_storage *storage = (struct imapc_storage *)_storage;

	imapc_client_deinit(&storage->client);
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
			ctx->mbox->box.name, reply->text);
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
		/* FIXME: hardcoded separator.. */
		name = t_strconcat(name, "/", NULL);
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
			ctx->mbox->box.name, reply->text);
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
