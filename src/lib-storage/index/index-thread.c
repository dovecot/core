/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

/* doc/thread-refs.txt describes the incremental algorithm we use here. */

#include "lib.h"
#include "array.h"
#include "message-id.h"
#include "mail-index-private.h"
#include "mail-index-sync-private.h"
#include "mail-search.h"
#include "mail-search-build.h"
#include "index-storage.h"
#include "index-thread-private.h"

#define MAIL_THREAD_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mail_thread_storage_module)

/* how much memory to allocate initially. these are very rough
   approximations. */
#define APPROX_MSG_EXTRA_COUNT 10
#define APPROX_MSGID_SIZE 45

struct mail_thread_context {
	struct mail_thread_update_context thread_ctx;

	struct mailbox *box;
	struct mailbox_transaction_context *t;

	struct mail_search_context *search;
	struct mail_search_args *search_args;
	struct mail_search_arg tmp_search_arg;
};

struct mail_thread_mailbox {
	union mailbox_module_context module_ctx;
	struct mail_hash *hash;

	struct mail_thread_list_context *list_ctx;

	/* set only temporarily while needed */
	struct mail_thread_update_context *ctx;
};

static MODULE_CONTEXT_DEFINE_INIT(mail_thread_storage_module,
				  &mail_storage_module_register);

static void mail_thread_clear(struct mail_thread_context *ctx);

bool mail_thread_type_parse(const char *str, enum mail_thread_type *type_r)
{
	if (strcasecmp(str, "REFERENCES") == 0)
		*type_r = MAIL_THREAD_REFERENCES;
	else if (strcasecmp(str, "X-REFERENCES2") == 0)
		*type_r = MAIL_THREAD_REFERENCES2;
	else
		return FALSE;
	return TRUE;
}

static unsigned int mail_thread_hash_key(const void *key)
{
	const struct msgid_search_key *key_rec = key;

	return key_rec->msgid_crc32;
}

static const char *
mail_thread_nth_last_refid_crc32(const char *msgids, unsigned int ref_index,
				 uint32_t msgid_crc32)
{
	const unsigned int idx_from_end =
		ref_index - MAIL_INDEX_NODE_REF_REFERENCES_LAST + 1;
	const char **last_msgids, *msgid;
	unsigned int idx = 0;

	last_msgids = t_new(const char *, idx_from_end);
	while ((msgid = message_id_get_next(&msgids)) != NULL) {
		if (crc32_str_nonzero(msgid) == msgid_crc32) {
			last_msgids[idx % idx_from_end] = msgid;
			idx++;
		}
	}
	return last_msgids[idx % idx_from_end];
}

static const char *
mail_thread_node_get_msgid(struct mail_hash_transaction *trans,
			   struct mail_thread_update_context *ctx,
			   const struct mail_thread_node *node, uint32_t idx)
{
	const char *msgids, *msgid = NULL, **p;
	int ret;

	if (node->ref_index == MAIL_INDEX_NODE_REF_EXT) {
		if (mail_thread_list_lookup(ctx->thread_list_ctx,
					    node->uid_or_id, &msgid) < 0)
			return NULL;
		if (msgid == NULL) {
			mail_hash_transaction_set_corrupted(trans,
				"Referenced list msgid lost");
		}
		return msgid;
	}

	p = array_idx_modifiable(&ctx->msgid_cache, idx);
	if (*p != NULL)
		return *p;

	ret = mail_set_uid(ctx->tmp_mail, node->uid_or_id);
	if (ret <= 0) {
		if (ret == 0) {
			mail_hash_transaction_set_corrupted(trans,
				t_strdup_printf("Referenced UID %u lost",
						node->uid_or_id));
		}
		return NULL;
	}
	switch (node->ref_index) {
	case MAIL_INDEX_NODE_REF_MSGID:
		/* Message-ID: header */
		if (mail_get_first_header(ctx->tmp_mail, HDR_MESSAGE_ID,
					  &msgids) < 0)
			return NULL;
		msgid = message_id_get_next(&msgids);
		break;
	case MAIL_INDEX_NODE_REF_INREPLYTO:
		/* In-Reply-To: header */
		if (mail_get_first_header(ctx->tmp_mail, HDR_IN_REPLY_TO,
					  &msgids) < 0)
			return NULL;
		msgid = message_id_get_next(&msgids);
		break;
	default:
		/* References: header */
		if (mail_get_first_header(ctx->tmp_mail, HDR_REFERENCES,
					  &msgids) < 0)
			return NULL;
		msgid = mail_thread_nth_last_refid_crc32(msgids,
							 node->ref_index,
							 node->msgid_crc32);
		break;
	}

	if (msgid == NULL) {
		/* shouldn't have happened */
		mail_hash_transaction_set_corrupted(trans, "Message ID lost");
		return NULL;
	}

	*p = p_strdup(ctx->msgid_pool, msgid);
	return *p;
}

static bool mail_thread_hash_cmp(struct mail_hash_transaction *trans,
				 const void *key, uint32_t idx, void *context)
{
	const struct msgid_search_key *key_rec = key;
	struct mail_thread_mailbox *tbox = context;
	struct mail_thread_update_context *ctx = tbox->ctx;
	const struct mail_thread_node *node;
	const char *msgid;
	bool ret;

	node = mail_hash_lookup_idx(trans, idx);
	if (key_rec->msgid_crc32 != node->msgid_crc32)
		return FALSE;

	ctx->cmp_match_count++;
	ctx->cmp_last_idx = idx;

	/* either a match or a collision, need to look closer */
	T_BEGIN {
		msgid = mail_thread_node_get_msgid(trans, ctx, node, idx);
		if (msgid != NULL)
			ret = strcmp(msgid, key_rec->msgid) == 0;
		else {
			/* we couldn't figure out the Message-ID for whatever
			   reason. we'll need to fallback to rebuilding the
			   whole thread. */
			ctx->rebuild = TRUE;
			ret = FALSE;
		}
	} T_END;
	return ret;
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
mail_thread_try_use_hash(struct mail_thread_context *ctx,
			 struct mail_hash *hash,
			 const struct mailbox_status *status, bool reset)
{
	struct mail_search_args *search_args = ctx->search_args;
	struct mail_search_arg *limit_arg = NULL;
	const struct mail_hash_header *hdr;
	struct mail_hash_transaction *hash_trans;
	uint32_t last_seq, last_uid, seq1, seq2;
	bool can_use = TRUE, shared_lock = FALSE;
	int try, ret;

	last_seq = status->messages;
	last_uid = status->uidnext - 1;

	/* Each search condition requires their own separate thread index.
	   Pretty much all the clients use only "search all" threading, so
	   we don't need to worry about anything else. */
	if (search_args->args->next != NULL) {
		/* too difficult to figure out if we could optimize this.
		   we most likely couldn't. */
		return FALSE;
	} else if (search_args->args->type == SEARCH_ALL) {
		/* optimize */
	} else if (search_args->args->type == SEARCH_SEQSET) {
		const struct seq_range *range;
		unsigned int count;

		range = array_get(&search_args->args->value.seqset, &count);
		if (count == 1 && range[0].seq1 == 1) {
			/* If we're searching 1..n, we might be able to
			   optimize this. This is at least useful for testing
			   incremental index updates if nothing else. :) */
			last_seq = range[0].seq2;
			last_uid = 0;
		} else {
			return FALSE;
		}
	} else {
		return FALSE;
	}

	for (try = 0;; try++) {
		if ((ret = mail_hash_lock_shared(hash)) < 0)
			return FALSE;
		if (ret > 0)
			break;
		if (try == 5) {
			/* enough tries */
			return FALSE;
		}

		/* doesn't exist, create a new hash */
		if ((ret = mail_hash_create_excl_locked(hash)) < 0)
			return FALSE;
		if (ret > 0) {
			ctx->thread_ctx.hash_trans =
				mail_hash_transaction_begin(hash,
							    status->messages);
			return TRUE;
		}
	}

again:
	hash_trans = mail_hash_transaction_begin(hash, status->messages);
	hdr = mail_hash_get_header(hash_trans);
	if (reset)
		mail_hash_reset(hash_trans);
	else if (hdr->last_uid > last_uid) {
		/* thread index is newer than our current mailbox view,
		   can't optimize */
		can_use = FALSE;
	} else if (hdr->message_count > last_seq) {
		/* messages have been expunged, but not removed from
		   the thread index. we don't know their Message-IDs
		   anymore, so we have to rebuild the index. */
		mail_hash_reset(hash_trans);
	} else if (hdr->message_count > 0) {
		/* non-empty hash. add only the new messages in there. */
		mailbox_get_seq_range(ctx->box, 1, hdr->last_uid, &seq1, &seq2);

		if (seq2 != hdr->message_count ||
		    hdr->uid_validity != status->uidvalidity) {
			/* some messages have been expunged. have to rebuild. */
			mail_hash_reset(hash_trans);
		} else {
			/* after all these checks, this is the only case we
			   can actually optimize. */
			struct mail_search_arg *arg = &ctx->tmp_search_arg;

			arg->type = SEARCH_SEQSET;
			p_array_init(&arg->value.seqset, search_args->pool, 1);
			if (seq2 == last_seq) {
				/* no need to update the index,
				   search nothing */
				shared_lock = TRUE;
			} else {
				/* search next+1..n */
				seq_range_array_add_range(&arg->value.seqset,
							  seq2 + 1, last_seq);
			}
			limit_arg = &ctx->tmp_search_arg;
		}
	} else {
		/* empty hash - make sure anyway that it gets reset */
		mail_hash_reset(hash_trans);
	}

	if (can_use && !shared_lock) {
		mail_hash_transaction_end(&hash_trans);
		mail_hash_unlock(hash);
		if (mail_hash_lock_exclusive(hash,
				MAIL_HASH_LOCK_FLAG_CREATE_MISSING) <= 0)
			return FALSE;
		shared_lock = TRUE;
		limit_arg = NULL;
		goto again;
	}
	if (!can_use) {
		mail_hash_transaction_end(&hash_trans);
		mail_hash_unlock(hash);
		return FALSE;
	} else {
		ctx->thread_ctx.hash_trans = hash_trans;
		if (limit_arg != NULL) {
			limit_arg->next = search_args->args;
			search_args->args = limit_arg;
		}
		return TRUE;
	}
}

static void
mail_thread_update_init(struct mail_thread_context *ctx, bool reset)
{
	struct mail_thread_mailbox *tbox = MAIL_THREAD_CONTEXT(ctx->box);
	struct mail_hash *hash = NULL;
	struct mailbox_status status;
	const struct mail_hash_header *hdr;
	unsigned int count;

	mailbox_get_status(ctx->box, STATUS_MESSAGES | STATUS_UIDNEXT, &status);
	if (mail_thread_try_use_hash(ctx, tbox->hash, &status, reset))
		hash = tbox->hash;
	else {
		/* fallback to using in-memory hash */
		struct index_mailbox *ibox = (struct index_mailbox *)ctx->box;

		hash = mail_hash_alloc(ibox->index, NULL,
				       sizeof(struct mail_thread_node),
				       mail_thread_hash_key,
				       mail_thread_hash_rec,
				       mail_thread_hash_cmp,
				       mail_thread_hash_remap,
				       tbox);
		if (mail_hash_lock_exclusive(hash,
				MAIL_HASH_LOCK_FLAG_CREATE_MISSING) <= 0)
			i_unreached();
		ctx->thread_ctx.hash_trans =
			mail_hash_transaction_begin(hash, 0);
	}
	ctx->thread_ctx.hash = hash;

	/* initialize searching */
	ctx->t = mailbox_transaction_begin(ctx->box, 0);
	ctx->search = mailbox_search_init(ctx->t, ctx->search_args, NULL);
	ctx->thread_ctx.tmp_mail = mail_alloc(ctx->t, 0, NULL);
	ctx->thread_ctx.thread_list_ctx =
		mail_thread_list_update_begin(tbox->list_ctx,
					      ctx->thread_ctx.hash_trans);

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

static int
mail_thread_update(struct mail_thread_context *ctx, bool reset)
{
	static const char *wanted_headers[] = {
		HDR_MESSAGE_ID, HDR_IN_REPLY_TO, HDR_REFERENCES, HDR_SUBJECT,
		NULL
	};
	struct mailbox *box;
	struct mailbox_header_lookup_ctx *headers_ctx;
	struct mail_hash_header *hdr;
	struct mail *mail;
	bool changed = FALSE;
	uint32_t prev_uid;
	int ret = 0;

	mail_thread_update_init(ctx, reset);
	box = mailbox_transaction_get_mailbox(ctx->t);

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
	mailbox_header_lookup_unref(&headers_ctx);

	if (ret < 0 || ctx->thread_ctx.failed || ctx->thread_ctx.rebuild)
		return -1;

	if (changed) {
		/* even if write failed, we can still finish the thread
		   building */
		(void)mail_hash_transaction_write(ctx->thread_ctx.hash_trans);
	}
	return 0;
}

int mail_thread_init(struct mailbox *box, bool reset,
		     struct mail_search_args *args,
		     struct mail_thread_context **ctx_r)
{
	struct mail_thread_mailbox *tbox = MAIL_THREAD_CONTEXT(box);
	struct mail_thread_context *ctx;
	int ret;

	i_assert(tbox->ctx == NULL);

	if (args != NULL)
		mail_search_args_ref(args);
	else {
		args = mail_search_build_init();
		mail_search_build_add_all(args);
	}

	ctx = i_new(struct mail_thread_context, 1);
	tbox->ctx = &ctx->thread_ctx;
	ctx->box = box;
	ctx->search_args = args;

	while ((ret = mail_thread_update(ctx, reset)) < 0) {
		if (ctx->thread_ctx.hash != tbox->hash) {
			/* failed with in-memory hash */
			mail_storage_set_critical(box->storage,
				"Threading mailbox %s failed unexpectedly",
				box->name);
			mail_thread_deinit(&ctx);
			return -1;
		}

		/* try again with in-memory hash */
		mail_thread_clear(ctx);
		reset = TRUE;
		memset(ctx, 0, sizeof(*ctx));
		ctx->box = box;
		ctx->search_args = args;
	}

	*ctx_r = ctx;
	return 0;
}

static void mail_thread_clear(struct mail_thread_context *ctx)
{
	struct mail_thread_mailbox *tbox = MAIL_THREAD_CONTEXT(ctx->box);

	if (ctx->thread_ctx.thread_list_ctx != NULL)
		mail_thread_list_rollback(&ctx->thread_ctx.thread_list_ctx);

	mail_hash_transaction_end(&ctx->thread_ctx.hash_trans);

	(void)mailbox_search_deinit(&ctx->search);
	mail_free(&ctx->thread_ctx.tmp_mail);
	(void)mailbox_transaction_commit(&ctx->t);

	mail_hash_unlock(ctx->thread_ctx.hash);
	if (ctx->thread_ctx.hash != tbox->hash)
		mail_hash_free(&ctx->thread_ctx.hash);

	if (ctx->search_args->args == &ctx->tmp_search_arg)
		ctx->search_args->args = ctx->tmp_search_arg.next;

	array_free(&ctx->thread_ctx.msgid_cache);
	pool_unref(&ctx->thread_ctx.msgid_pool);
}

void mail_thread_deinit(struct mail_thread_context **_ctx)
{
	struct mail_thread_context *ctx = *_ctx;
	struct mail_thread_mailbox *tbox = MAIL_THREAD_CONTEXT(ctx->box);

	*_ctx = NULL;

	mail_thread_clear(ctx);
	mail_search_args_unref(&ctx->search_args);
 	i_assert(!tbox->ctx->syncing);
 	tbox->ctx = NULL;
	i_free(ctx);
}

struct mail_thread_iterate_context *
mail_thread_iterate_init(struct mail_thread_context *ctx,
			 enum mail_thread_type thread_type, bool write_seqs)
{
	struct mail_thread_mailbox *tbox = MAIL_THREAD_CONTEXT(ctx->box);

	return mail_thread_iterate_init_full(ctx->thread_ctx.tmp_mail,
					     ctx->thread_ctx.hash_trans,
					     tbox->list_ctx,
					     thread_type, write_seqs);
}

static bool
mail_thread_index_is_up_to_date(struct mail_thread_update_context *ctx,
				struct mail_index_view *view)
{
	const struct mail_index_header *hdr;
	struct mail_hash_header *hash_hdr;
	uint32_t seq1, seq2;

	hdr = mail_index_get_header(view);
	hash_hdr = mail_hash_get_header(ctx->hash_trans);
	if (hash_hdr->last_uid + 1 == hdr->next_uid) {
		/* all messages have been added to hash */
		return hash_hdr->message_count == hdr->messages_count;
	}

	if (!mail_index_lookup_seq_range(view, 1, hash_hdr->last_uid,
					 &seq1, &seq2))
		seq2 = 0;
	return seq2 == hash_hdr->message_count;
}

static void
mail_thread_expunge_handler_deinit(struct mail_thread_mailbox *tbox,
				   struct mail_thread_update_context *ctx)
{
	struct mailbox_transaction_context *t;

	t = ctx->tmp_mail->transaction;

	if (ctx->failed)
		mail_thread_list_rollback(&ctx->thread_list_ctx);
	else {
		if (mail_thread_list_commit(&ctx->thread_list_ctx) < 0)
			ctx->failed = TRUE;
	}
	if (!ctx->failed)
		(void)mail_hash_transaction_write(ctx->hash_trans);
	mail_hash_transaction_end(&ctx->hash_trans);
	mail_hash_unlock(tbox->hash);

	mail_free(&ctx->tmp_mail);
	/* don't commit. we're in the middle of syncing and
	   this transaction isn't marked as external. */
	(void)mailbox_transaction_rollback(&t);
	array_free(&ctx->msgid_cache);
	pool_unref(&ctx->msgid_pool);
}

static int
mail_thread_expunge_handler(struct mail_index_sync_map_ctx *sync_ctx,
			    uint32_t seq, const void *data,
			    void **sync_context ATTR_UNUSED, void *context)
{
	struct mailbox *box = context;
	struct mail_thread_mailbox *tbox = MAIL_THREAD_CONTEXT(box);
	struct mail_thread_update_context *ctx = tbox->ctx;
	struct mailbox_transaction_context *t;
	uint32_t uid;

	if (data == NULL) {
		/* deinit */
		if (!ctx->syncing)
			return 0;
		if (ctx->hash != NULL)
			mail_thread_expunge_handler_deinit(tbox, ctx);
		i_free_and_null(tbox->ctx);
		return 0;
	}
	if (ctx == NULL) {
		/* init */
		if (tbox->ctx != NULL) {
			/* we're already in the middle of threading */
			return 0;
		}
		tbox->ctx = ctx = i_new(struct mail_thread_update_context, 1);
		ctx->syncing = TRUE;

		/* we can't wait the lock in here or we could deadlock. */
		if (mail_hash_lock_exclusive(tbox->hash,
					     MAIL_HASH_LOCK_FLAG_TRY) <= 0)
			return 0;

		ctx->hash = tbox->hash;
		ctx->hash_trans = mail_hash_transaction_begin(ctx->hash, 0);
		ctx->thread_list_ctx =
			mail_thread_list_update_begin(tbox->list_ctx,
						      ctx->hash_trans);
		ctx->msgid_pool = pool_alloconly_create(MEMPOOL_GROWING"msgids",
							20 * APPROX_MSGID_SIZE);
		i_array_init(&ctx->msgid_cache, 20);

		t = mailbox_transaction_begin(box, 0);
		ctx->tmp_mail = mail_alloc(t, 0, NULL);

		if (!mail_thread_index_is_up_to_date(ctx, sync_ctx->view)) {
			ctx->failed = TRUE;
			return 0;
		}
	} else {
		if (ctx->hash == NULL) {
			/* locking had failed */
			return 0;
		}
		if (!ctx->syncing || ctx->failed)
			return 0;
	}

	T_BEGIN {
		mail_index_lookup_uid(sync_ctx->view, seq, &uid);
		if (mail_thread_remove(ctx, uid) <= 0)
			ctx->failed = TRUE;
	} T_END;
	return 0;
}

static int mail_thread_mailbox_close(struct mailbox *box)
{
	struct mail_thread_mailbox *tbox = MAIL_THREAD_CONTEXT(box);
	int ret;

	i_assert(tbox->ctx == NULL);

	mail_thread_list_deinit(&tbox->list_ctx);
	mail_hash_free(&tbox->hash);
	ret = tbox->module_ctx.super.close(box);
	i_free(tbox);
	return ret;
}

void index_thread_mailbox_index_opened(struct index_mailbox *ibox)
{
	struct mailbox *box = &ibox->box;
	struct mail_thread_mailbox *tbox;
	uint32_t ext_id;

	tbox = i_new(struct mail_thread_mailbox, 1);
	tbox->module_ctx.super = box->v;
	box->v.close = mail_thread_mailbox_close;

	tbox->list_ctx = mail_thread_list_init(box);
	tbox->hash = mail_hash_alloc(ibox->index, MAIL_THREAD_INDEX_SUFFIX,
				     sizeof(struct mail_thread_node),
				     mail_thread_hash_key,
				     mail_thread_hash_rec,
				     mail_thread_hash_cmp,
				     mail_thread_hash_remap,
				     tbox);

	ext_id = mail_index_ext_register(ibox->index, "thread", 0, 0, 0);
	mail_index_register_expunge_handler(ibox->index, ext_id, TRUE,
					    mail_thread_expunge_handler, box);

	MODULE_CONTEXT_SET(box, mail_thread_storage_module, tbox);
}
