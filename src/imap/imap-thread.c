/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

/* doc/thread-refs.txt describes the incremental algorithm we use here. */

#include "common.h"
#include "array.h"
#include "ostream.h"
#include "message-id.h"
#include "mail-search.h"
#include "imap-thread-private.h"

/* FIXME: the mailbox accessing API needs some cleaning up. we shouldn't be
   including all kinds of private headers */
#include "../lib-storage/index/index-storage.h"
#include "mail-index-private.h"
#include "mail-index-sync-private.h"

#define IMAP_THREAD_CONTEXT(obj) \
	MODULE_CONTEXT(obj, imap_thread_storage_module)

/* how much memory to allocate initially. these are very rough
   approximations. */
#define APPROX_MSG_EXTRA_COUNT 10
#define APPROX_MSGID_SIZE 45

struct imap_thread_context {
	struct thread_context thread_ctx;
	struct client_command_context *cmd;
	struct mailbox_transaction_context *t;
	enum mail_thread_type thread_type;

	struct mail_search_context *search;
	struct mail_search_arg tmp_search_arg;
	struct mail_search_seqset seqset;

	unsigned int id_is_uid:1;
};

struct imap_thread_mailbox {
	union mailbox_module_context module_ctx;
	struct mail_hash *hash;

	/* set only temporarily while needed */
	struct thread_context *ctx;
};

static void (*next_hook_mailbox_opened)(struct mailbox *box);

static MODULE_CONTEXT_DEFINE_INIT(imap_thread_storage_module,
				  &mail_storage_module_register);

static unsigned int mail_thread_hash_key(const void *key)
{
	const struct msgid_search_key *key_rec = key;

	return key_rec->msgid_crc32;
}

static const char *
mail_thread_find_msgid_crc32(struct thread_context *ctx, uint32_t msgid_crc32)
{
	const char *msgids, *msgid;
	int ret;

	/* if there are any valid references, it's in them */
	ret = mail_get_first_header(ctx->tmp_mail, HDR_REFERENCES, &msgids);
	if (ret == 0) {
		/* no References: header, fallback to In-Reply-To: */
		if (mail_get_first_header(ctx->tmp_mail, HDR_IN_REPLY_TO,
					  &msgids) <= 0)
			return NULL;

		msgid = message_id_get_next(&msgids);
		if (msgid != NULL && crc32_str_nonzero(msgid) == msgid_crc32)
			return msgid;
		return NULL;
	}
	if (ret < 0)
		return NULL;

	while ((msgid = message_id_get_next(&msgids)) != NULL) {
		if (crc32_str_nonzero(msgid) == msgid_crc32) {
			/* found it. there aren't any colliding message-id
			   CRC32s in this message or it wouldn't have been
			   added as a reference UID. */
			return msgid;
		}
	}
	return NULL;

}

static const char *
mail_thread_node_get_msgid(struct thread_context *ctx,
			   const struct mail_thread_node *node, uint32_t idx)
{
	const char *msgids, *msgid, **p;

	p = array_idx_modifiable(&ctx->msgid_cache, idx);
	if (*p != NULL)
		return *p;

	if (node->uid == 0)
		return NULL;

	if (mail_set_uid(ctx->tmp_mail, node->uid) <= 0)
		return NULL;
	if (node->exists) {
		/* we can get the Message-ID directly */
		if (mail_get_first_header(ctx->tmp_mail, HDR_MESSAGE_ID,
					  &msgids) <= 0)
			return NULL;

		msgid = message_id_get_next(&msgids);
	} else {
		/* find from a referencing message */
		msgid = mail_thread_find_msgid_crc32(ctx, node->msgid_crc32);
	}

	if (msgid == NULL)
		return NULL;

	*p = p_strdup(ctx->msgid_pool, msgid);
	return *p;
}

static bool mail_thread_hash_cmp(struct mail_hash_transaction *trans,
				 const void *key, uint32_t idx, void *context)
{
	const struct msgid_search_key *key_rec = key;
	struct imap_thread_mailbox *tbox = context;
	struct thread_context *ctx = tbox->ctx;
	const struct mail_thread_node *node;
	const char *msgid;

	node = mail_hash_lookup_idx(trans, idx);
	if (key_rec->msgid_crc32 != node->msgid_crc32)
		return FALSE;

	ctx->cmp_match_count++;
	ctx->cmp_last_idx = idx;

	/* either a match or a collision, need to look closer */
	msgid = mail_thread_node_get_msgid(ctx, node, ctx->cmp_last_idx);
	if (msgid == NULL) {
		/* we couldn't figure out the Message-ID for whatever reason.
		   we'll need to fallback to rebuilding the whole thread */
		ctx->rebuild = TRUE;
		return FALSE;
	}
	return strcmp(msgid, key_rec->msgid) == 0;
}

static unsigned int mail_thread_hash_rec(const void *p)
{
	const struct mail_thread_node *rec = p;

	return rec->msgid_crc32;
}

static int
mail_thread_hash_remap(struct mail_hash_transaction *trans,
		       const uint32_t *map, unsigned int map_size,
		       void *context ATTR_UNUSED)
{
	const struct mail_hash_header *hdr;
	struct mail_thread_node *node;
	uint32_t idx;

	hdr = mail_hash_get_header(trans);
	for (idx = 1; idx < hdr->record_count; idx++) {
		node = mail_hash_lookup_idx(trans, idx);
		i_assert(!MAIL_HASH_RECORD_IS_DELETED(&node->rec));

		if (node->parent_idx >= map_size) {
			mail_hash_transaction_set_corrupted(trans,
				"invalid parent_idx");
			return -1;
		}

		node->parent_idx = map[node->parent_idx];
	}
	return 0;
}

static bool
imap_thread_try_use_hash(struct imap_thread_context *ctx,
			 struct mail_hash *hash,
			 const struct mailbox_status *status, bool reset,
			 struct mail_search_arg **search_args_p)
{
	struct mail_search_arg *search_args = *search_args_p;
	struct mailbox *box = ctx->cmd->client->mailbox;
	const struct mail_hash_header *hdr;
	struct mail_hash_transaction *hash_trans;
	uint32_t last_seq, last_uid;
	bool can_use = TRUE, shared_lock = FALSE;
	int ret;

	last_seq = status->messages;
	last_uid = status->uidnext - 1;

	/* Each search condition requires their own separate thread index.
	   Pretty much all the clients use only "search all" threading, so
	   we don't need to worry about anything else. */
	if (search_args->next != NULL) {
		/* too difficult to figure out if we could optimize this.
		   we most likely couldn't. */
		return FALSE;
	} else if (search_args->type == SEARCH_ALL) {
		/* optimize */
	} else if (search_args->type == SEARCH_SEQSET &&
		   search_args->value.seqset->seq1 == 1) {
		/* If we're searching 1..n, we might be able to optimize
		   this. This is at least useful for testing incremental
		   index updates if nothing else. :) */
		last_seq = search_args->value.seqset->seq2;
		last_uid = 0;
	} else {
		return FALSE;
	}

	if ((ret = mail_hash_lock_shared(hash)) < 0)
		return FALSE;
	if (ret == 0) {
		/* doesn't exist, creating a new hash */
		if (mail_hash_lock_exclusive(hash, TRUE) <= 0)
			return FALSE;
		ctx->thread_ctx.hash_trans =
			mail_hash_transaction_begin(hash, status->messages);
		return TRUE;
	}

again:
	hash_trans = mail_hash_transaction_begin(hash, status->messages);
	hdr = mail_hash_get_header(hash_trans);
	if (reset)
		mail_hash_reset(hash_trans);
	else if (hdr->message_count > last_seq) {
		if (hdr->last_uid > last_uid) {
			/* thread index is newer than our current mailbox view,
			   can't optimize */
			can_use = FALSE;
		} else {
			/* messages have been expunged, but not removed from
			   the thread index. we don't know their Message-IDs
			   anymore, so we have to rebuild the index. */
			mail_hash_reset(hash_trans);
		}
	} else if (hdr->message_count > 0) {
		/* non-empty hash. add only the new messages in there. */
		mailbox_get_uids(box, 1, hdr->last_uid,
				 &ctx->seqset.seq1, &ctx->seqset.seq2);

		if (ctx->seqset.seq2 != hdr->message_count ||
		    hdr->uid_validity != status->uidvalidity) {
			/* some messages have been expunged. have to rebuild. */
			mail_hash_reset(hash_trans);
		} else {
			/* after all these checks, this is the only case we
			   can actually optimize. */
			ctx->tmp_search_arg.type = SEARCH_SEQSET;
			if (ctx->seqset.seq2 == last_seq) {
				/* no need to update the index,
				   search nothing */
				ctx->tmp_search_arg.value.seqset = NULL;
				shared_lock = TRUE;
			} else {
				/* search next+1..n */
				ctx->seqset.seq1 = ctx->seqset.seq2 + 1;
				ctx->seqset.seq2 = last_seq;
				ctx->tmp_search_arg.value.seqset = &ctx->seqset;
			}
			*search_args_p = &ctx->tmp_search_arg;
		}
	} else {
		/* empty hash - make sure anyway that it gets reset */
		mail_hash_reset(hash_trans);
	}

	if (can_use && !shared_lock) {
		mail_hash_transaction_end(&hash_trans);
		mail_hash_unlock(hash);
		if (mail_hash_lock_exclusive(hash, TRUE) <= 0)
			return FALSE;
		shared_lock = TRUE;
		goto again;
	}
	if (!can_use) {
		mail_hash_transaction_end(&hash_trans);
		mail_hash_unlock(hash);
		return FALSE;
	} else {
		ctx->thread_ctx.hash_trans = hash_trans;
		return TRUE;
	}
}

static void
imap_thread_context_init(struct imap_thread_mailbox *tbox,
			 struct imap_thread_context *ctx,
			 const char *charset,
			 struct mail_search_arg *search_args, bool reset)
{
	struct mailbox *box = ctx->cmd->client->mailbox;
	struct mail_hash *hash = NULL;
	struct mailbox_status status;
	const struct mail_hash_header *hdr;
	unsigned int count;

	mailbox_get_status(box, STATUS_MESSAGES | STATUS_UIDNEXT, &status);
	if (imap_thread_try_use_hash(ctx, tbox->hash, &status,
				     reset, &search_args))
		hash = tbox->hash;
	else {
		/* fallback to using in-memory hash */
		struct index_mailbox *ibox = (struct index_mailbox *)box;

		hash = mail_hash_alloc(ibox->index, NULL,
				       sizeof(struct mail_thread_node),
				       mail_thread_hash_key,
				       mail_thread_hash_rec,
				       mail_thread_hash_cmp,
				       mail_thread_hash_remap,
				       tbox);
		if (mail_hash_lock_exclusive(hash, TRUE) <= 0)
			i_unreached();
		ctx->thread_ctx.hash_trans =
			mail_hash_transaction_begin(hash, 0);
	}
	ctx->thread_ctx.hash = hash;

	/* initialize searching */
	ctx->t = mailbox_transaction_begin(box, 0);
	ctx->search = mailbox_search_init(ctx->t, charset, search_args, NULL);
	ctx->thread_ctx.tmp_mail = mail_alloc(ctx->t, 0, NULL);

	hdr = mail_hash_get_header(ctx->thread_ctx.hash_trans);
	count = status.messages < hdr->record_count ? 0 :
		status.messages - hdr->record_count;
	count += APPROX_MSG_EXTRA_COUNT;
	ctx->thread_ctx.msgid_pool =
		pool_alloconly_create(MEMPOOL_GROWING"msgids",
				      count * APPROX_MSGID_SIZE);
	i_array_init(&ctx->thread_ctx.msgid_cache,
		     I_MAX(hdr->record_count, status.messages));
}

static int imap_thread_finish(struct imap_thread_mailbox *tbox,
			      struct imap_thread_context *ctx)
{
	int ret;

	ret = mailbox_search_deinit(&ctx->search);
	mail_free(&ctx->thread_ctx.tmp_mail);
	if (mailbox_transaction_commit(&ctx->t) < 0)
		ret = -1;

	mail_hash_unlock(ctx->thread_ctx.hash);
	if (ctx->thread_ctx.hash != tbox->hash)
		mail_hash_free(&ctx->thread_ctx.hash);

	array_free(&ctx->thread_ctx.msgid_cache);
	pool_unref(&ctx->thread_ctx.msgid_pool);
	return ret;
}

static int imap_thread_run(struct imap_thread_context *ctx)
{
	static const char *wanted_headers[] = {
		HDR_MESSAGE_ID, HDR_IN_REPLY_TO, HDR_REFERENCES, HDR_SUBJECT,
		NULL
	};
	struct mailbox *box = mailbox_transaction_get_mailbox(ctx->t);
	struct mailbox_header_lookup_ctx *headers_ctx;
	struct mail_hash_header *hdr;
	struct mail *mail;
	bool changed = FALSE;
	uint32_t prev_uid;
	int ret = 0;

	hdr = mail_hash_get_header(ctx->thread_ctx.hash_trans);
	prev_uid = hdr->last_uid;

	headers_ctx = mailbox_header_lookup_init(box, wanted_headers);
	mail = mail_alloc(ctx->t, MAIL_FETCH_DATE, headers_ctx);
	while (ret == 0 &&
	       mailbox_search_next(ctx->search, mail) > 0) {
		i_assert(mail->uid > prev_uid);
		prev_uid = mail->uid;
		changed = TRUE;

		T_BEGIN {
			ret = mail_thread_add(&ctx->thread_ctx, mail);
		} T_END;
	}
	mail_free(&mail);
	mailbox_header_lookup_deinit(&headers_ctx);

	if (ret < 0 || ctx->thread_ctx.failed || ctx->thread_ctx.rebuild) {
		mail_storage_set_internal_error(box->storage);
		return -1;
	}

	if (changed) {
		/* even if write failed, we can still finish the thread
		   building */
		(void)mail_hash_transaction_write(ctx->thread_ctx.hash_trans);
	}

	if (mail_thread_finish(ctx->thread_ctx.tmp_mail,
			       ctx->thread_ctx.hash_trans,
			       ctx->thread_type, ctx->cmd->client->output,
			       ctx->cmd->uid) < 0) {
		mail_storage_set_internal_error(box->storage);
		return -1;
	}
	return 0;
}

int imap_thread(struct client_command_context *cmd, const char *charset,
		struct mail_search_arg *args, enum mail_thread_type type)
{
	struct imap_thread_mailbox *tbox =
		IMAP_THREAD_CONTEXT(cmd->client->mailbox);
	struct imap_thread_context *ctx;
	int ret, try;

	i_assert(type == MAIL_THREAD_REFERENCES ||
		 type == MAIL_THREAD_REFERENCES2);

	ctx = t_new(struct imap_thread_context, 1);
	tbox->ctx = &ctx->thread_ctx;

	for (try = 0; try < 2; try++) {
		ctx->thread_type = type;
		ctx->cmd = cmd;
		imap_thread_context_init(tbox, ctx, charset, args, try == 1);
		ret = imap_thread_run(ctx);
		if (imap_thread_finish(tbox, ctx) < 0)
			ret = -1;

		if (ret < 0 && ctx->thread_ctx.hash == tbox->hash) {
			/* try again with in-memory hash */
			memset(ctx, 0, sizeof(*ctx));
		} else {
			break;
		}
	}

	tbox->ctx = NULL;
	return ret;
}

static int
imap_thread_expunge_handler(struct mail_index_sync_map_ctx *sync_ctx,
			    uint32_t seq, const void *data,
			    void **sync_context ATTR_UNUSED, void *context)
{
	struct mailbox *box = context;
	struct imap_thread_mailbox *tbox = IMAP_THREAD_CONTEXT(box);
	struct thread_context *ctx = tbox->ctx;
	struct mailbox_transaction_context *t;
	uint32_t uid;

	if (data == NULL) {
		/* deinit */
		if (ctx->hash != NULL) {
			t = ctx->tmp_mail->transaction;

			if (!ctx->failed)
				(void)mail_hash_transaction_write(ctx->hash_trans);
			mail_hash_transaction_end(&ctx->hash_trans);
			mail_hash_unlock(tbox->hash);

			mail_free(&ctx->tmp_mail);
			(void)mailbox_transaction_commit(&t);
			array_free(&ctx->msgid_cache);
			pool_unref(&ctx->msgid_pool);
		}
		i_free_and_null(tbox->ctx);
		return 0;
	}
	if (ctx == NULL) {
		/* init */
		tbox->ctx = ctx = i_new(struct thread_context, 1);

		if (mail_hash_lock_exclusive(tbox->hash, FALSE) <= 0)
			return 0;

		ctx->hash = tbox->hash;
		ctx->hash_trans = mail_hash_transaction_begin(ctx->hash, 0);
		ctx->msgid_pool = pool_alloconly_create(MEMPOOL_GROWING"msgids",
							20 * APPROX_MSGID_SIZE);
		i_array_init(&ctx->msgid_cache, 20);

		t = mailbox_transaction_begin(box, 0);
		ctx->tmp_mail = mail_alloc(t, 0, NULL);
	} else {
		if (ctx->hash == NULL) {
			/* locking had failed */
			return 0;
		}
		if (ctx->failed)
			return 0;
	}

	T_BEGIN {
		mail_index_lookup_uid(sync_ctx->view, seq, &uid);
		if (mail_thread_remove(ctx, uid) <= 0)
			ctx->failed = TRUE;
	} T_END;
	return 0;
}

static int imap_thread_mailbox_close(struct mailbox *box)
{
	struct imap_thread_mailbox *tbox = IMAP_THREAD_CONTEXT(box);
	int ret;

	mail_hash_free(&tbox->hash);
	ret = tbox->module_ctx.super.close(box);
	i_free(tbox);
	return ret;
}

static void imap_thread_mailbox_opened(struct mailbox *box)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;
	struct imap_thread_mailbox *tbox;
	uint32_t ext_id;

	if (next_hook_mailbox_opened != NULL)
		next_hook_mailbox_opened(box);

	tbox = i_new(struct imap_thread_mailbox, 1);
	tbox->module_ctx.super = box->v;
	box->v.close = imap_thread_mailbox_close;

	tbox->hash = mail_hash_alloc(ibox->index, ".thread",
				     sizeof(struct mail_thread_node),
				     mail_thread_hash_key,
				     mail_thread_hash_rec,
				     mail_thread_hash_cmp,
				     mail_thread_hash_remap,
				     tbox);

	ext_id = mail_index_ext_register(ibox->index, "thread", 0, 0, 0);
	mail_index_register_expunge_handler(ibox->index, ext_id, TRUE,
					    imap_thread_expunge_handler, box);

	MODULE_CONTEXT_SET(box, imap_thread_storage_module, tbox);
}

void imap_thread_init(void)
{
	next_hook_mailbox_opened = hook_mailbox_opened;
	hook_mailbox_opened = imap_thread_mailbox_opened;
}

void imap_thread_deinit(void)
{
	i_assert(hook_mailbox_opened == imap_thread_mailbox_opened);
	hook_mailbox_opened = next_hook_mailbox_opened;
}
