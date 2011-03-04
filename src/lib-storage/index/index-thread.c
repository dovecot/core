/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

/* doc/thread-refs.txt describes the incremental algorithm we use here. */

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "hash2.h"
#include "message-id.h"
#include "mail-index-private.h"
#include "mail-index-sync-private.h"
#include "mail-search.h"
#include "mail-search-build.h"
#include "mailbox-search-result-private.h"
#include "index-storage.h"
#include "index-thread-private.h"

#include <stdlib.h>

#define MAIL_THREAD_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mail_thread_storage_module)

struct mail_thread_context {
	struct mailbox *box;
	struct mailbox_transaction_context *t;
	struct mail_index_strmap_view_sync *strmap_sync;

	struct mail *tmp_mail;
	struct mail_search_args *search_args;
	ARRAY_TYPE(seq_range) added_uids;

	unsigned int failed:1;
};

struct mail_thread_mailbox {
	union mailbox_module_context module_ctx;

	unsigned int next_msgid_idx;
	struct mail_thread_cache *cache;

	struct mail_index_strmap *strmap;
	struct mail_index_strmap_view *strmap_view;
	/* sorted by UID, ref_index */
	const ARRAY_TYPE(mail_index_strmap_rec) *msgid_map;
	const struct hash2_table *msgid_hash;

	/* set only temporarily while needed */
	struct mail_thread_context *ctx;
};

static MODULE_CONTEXT_DEFINE_INIT(mail_thread_storage_module,
				  &mail_storage_module_register);

static void mail_thread_clear(struct mail_thread_context *ctx);

static int
mail_strmap_rec_get_msgid(struct mail *mail,
			  const struct mail_index_strmap_rec *rec,
			  const char **msgid_r)
{
	const char *msgids = NULL, *msgid;
	unsigned int n = 0;
	int ret;

	if (!mail_set_uid(mail, rec->uid))
		return 0;

	switch (rec->ref_index) {
	case MAIL_THREAD_NODE_REF_MSGID:
		/* Message-ID: header */
		ret = mail_get_first_header(mail, HDR_MESSAGE_ID, &msgids);
		break;
	case MAIL_THREAD_NODE_REF_INREPLYTO:
		/* In-Reply-To: header */
		ret = mail_get_first_header(mail, HDR_IN_REPLY_TO, &msgids);
		break;
	default:
		/* References: header */
		ret = mail_get_first_header(mail, HDR_REFERENCES, &msgids);
		n = rec->ref_index - MAIL_THREAD_NODE_REF_REFERENCES1;
		break;
	}

	if (ret < 0) {
		if (mail->expunged) {
			/* treat it as if it didn't exist. trying to add it
			   again will result in failure. */
			return 0;
		}
		return -1;
	}

	/* get the nth message-id */
	msgid = message_id_get_next(&msgids);
	if (msgid != NULL) {
		for (; n > 0 && *msgids != '\0'; n--)
			msgid = message_id_get_next(&msgids);
	}

	if (msgid == NULL) {
		/* shouldn't have happened */
		mail_storage_set_critical(mail->box->storage,
					  "Threading lost Message ID");
		return -1;
	}
	*msgid_r = msgid;
	return 1;
}

static bool
mail_thread_hash_key_cmp(const char *key,
			 const struct mail_index_strmap_rec *rec,
			 void *context)
{
	struct mail_thread_mailbox *tbox = context;
	struct mail_thread_context *ctx = tbox->ctx;
	const char *msgid;
	bool cmp_ret;
	int ret;

	/* either a match or a collision, need to look closer */
	T_BEGIN {
		ret = mail_strmap_rec_get_msgid(ctx->tmp_mail, rec, &msgid);
		if (ret <= 0) {
			if (ret < 0)
				ctx->failed = TRUE;
			cmp_ret = FALSE;
		} else {
			cmp_ret = strcmp(msgid, key) == 0;
		}
	} T_END;
	return cmp_ret;
}

static int
mail_thread_hash_rec_cmp(const struct mail_index_strmap_rec *rec1,
			 const struct mail_index_strmap_rec *rec2,
			 void *context)
{
	struct mail_thread_mailbox *tbox = context;
	struct mail_thread_context *ctx = tbox->ctx;
	const char *msgid1, *msgid2;
	int ret;

	T_BEGIN {
		ret = mail_strmap_rec_get_msgid(ctx->tmp_mail, rec1, &msgid1);
		if (ret > 0) {
			msgid1 = t_strdup(msgid1);
			ret = mail_strmap_rec_get_msgid(ctx->tmp_mail, rec2,
							&msgid2);
		}
		ret = ret <= 0 ? -1 :
			strcmp(msgid1, msgid2) == 0;
	} T_END;
	return ret;
}

static void mail_thread_strmap_remap(const uint32_t *idx_map,
				     unsigned int old_count,
				     unsigned int new_count, void *context)
{
	struct mail_thread_mailbox *tbox = context;
	struct mail_thread_cache *cache = tbox->cache;
	ARRAY_TYPE(mail_thread_node) new_nodes;
	const struct mail_thread_node *old_nodes;
	struct mail_thread_node *node;
	unsigned int i, nodes_count, max, new_first_invalid, invalid_count;

	if (cache->search_result == NULL)
		return;

	if (new_count == 0) {
		/* strmap was reset, we'll need to rebuild thread */
		mailbox_search_result_free(&cache->search_result);
		return;
	}

	invalid_count = cache->next_invalid_msgid_str_idx -
		cache->first_invalid_msgid_str_idx;

	old_nodes = array_get(&cache->thread_nodes, &nodes_count);
	i_array_init(&new_nodes, new_count + invalid_count + 32);

	/* optimization: allocate all nodes initially */
	(void)array_idx_modifiable(&new_nodes, new_count-1);

	/* renumber existing valid nodes. all existing records in old_nodes
	   should also exist in idx_map since we've removed expunged messages
	   from the cache before committing the sync. */
	max = I_MIN(I_MIN(old_count, nodes_count),
		    cache->first_invalid_msgid_str_idx);
	for (i = 0; i < max; i++) {
		if (idx_map[i] == 0) {
			/* expunged record. */
			i_assert(old_nodes[i].uid == 0);
		} else {
			node = array_idx_modifiable(&new_nodes, idx_map[i]);
			*node = old_nodes[i];
			if (node->parent_idx != 0) {
				node->parent_idx = idx_map[node->parent_idx];
				i_assert(node->parent_idx != 0);
			}
		}
	}

	/* copy invalid nodes, if any. no other messages point to them,
	   so this is safe. we still need to update their parent_idx
	   pointers though. */
	new_first_invalid = new_count + 1 +
		THREAD_INVALID_MSGID_STR_IDX_SKIP_COUNT;
	for (i = 0; i < invalid_count; i++) {
		node = array_idx_modifiable(&new_nodes, new_first_invalid + i);
		*node = old_nodes[cache->first_invalid_msgid_str_idx + i];
		if (node->parent_idx != 0) {
			node->parent_idx = idx_map[node->parent_idx];
			i_assert(node->parent_idx != 0);
		}
	}
	cache->first_invalid_msgid_str_idx = new_first_invalid;
	cache->next_invalid_msgid_str_idx = new_first_invalid + invalid_count;

	/* replace the old nodes with the renumbered ones */
	array_free(&cache->thread_nodes);
	cache->thread_nodes = new_nodes;
}

static int thread_get_mail_header(struct mail *mail, const char *name,
				  const char **value_r)
{
	if (mail_get_first_header(mail, name, value_r) < 0) {
		if (!mail->expunged)
			return -1;

		/* Message is expunged. Instead of failing the entire THREAD
		   command, just treat the header as nonexistent. */
		*value_r = NULL;
	}
	return 0;
}

static int
mail_thread_map_add_mail(struct mail_thread_context *ctx, struct mail *mail)
{
	const char *message_id, *in_reply_to, *references, *msgid;
	uint32_t ref_index;

	if (thread_get_mail_header(mail, HDR_MESSAGE_ID, &message_id) < 0 ||
	    thread_get_mail_header(mail, HDR_REFERENCES, &references) < 0)
		return -1;

	/* add Message-ID: */
	msgid = message_id_get_next(&message_id);
	if (msgid != NULL) {
		mail_index_strmap_view_sync_add(ctx->strmap_sync, mail->uid,
						MAIL_THREAD_NODE_REF_MSGID,
						msgid);
	} else {
		mail_index_strmap_view_sync_add_unique(ctx->strmap_sync,
					mail->uid, MAIL_THREAD_NODE_REF_MSGID);
	}

	/* add References: if there are any valid ones */
	msgid = message_id_get_next(&references);
	if (msgid != NULL) {
		ref_index = MAIL_THREAD_NODE_REF_REFERENCES1;
		do {
			mail_index_strmap_view_sync_add(ctx->strmap_sync,
							mail->uid,
							ref_index, msgid);
			ref_index++;
			msgid = message_id_get_next(&references);
		} while (msgid != NULL);
	} else {
		/* no References:, use In-Reply-To: */
		if (thread_get_mail_header(mail, HDR_IN_REPLY_TO,
					   &in_reply_to) < 0)
			return -1;

		msgid = message_id_get_next(&in_reply_to);
		if (msgid != NULL) {
			mail_index_strmap_view_sync_add(ctx->strmap_sync,
				mail->uid, MAIL_THREAD_NODE_REF_INREPLYTO,
				msgid);
		}
	}
	if (ctx->failed) {
		/* message-id lookup failed in hash compare */
		return -1;
	}
	return 0;
}

static int mail_thread_index_map_build(struct mail_thread_context *ctx)
{
	static const char *wanted_headers[] = {
		HDR_MESSAGE_ID, HDR_IN_REPLY_TO, HDR_REFERENCES,
		NULL
	};
	struct mail_thread_mailbox *tbox = MAIL_THREAD_CONTEXT(ctx->box);
	struct mailbox_header_lookup_ctx *headers_ctx;
	struct mail_search_args *search_args;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	uint32_t last_uid, seq1, seq2;
	int ret = 0;

	if (tbox->strmap_view == NULL) {
		/* first time we're threading this mailbox */
		tbox->strmap_view =
			mail_index_strmap_view_open(tbox->strmap,
						    ctx->box->view,
						    mail_thread_hash_key_cmp,
						    mail_thread_hash_rec_cmp,
						    mail_thread_strmap_remap,
						    tbox, &tbox->msgid_map,
						    &tbox->msgid_hash);
	}

	headers_ctx = mailbox_header_lookup_init(ctx->box, wanted_headers);
	ctx->tmp_mail = mail_alloc(ctx->t, 0, headers_ctx);

	/* add all missing UIDs */
	ctx->strmap_sync = mail_index_strmap_view_sync_init(tbox->strmap_view,
							    &last_uid);
	mailbox_get_seq_range(ctx->box, last_uid + 1, (uint32_t)-1,
			      &seq1, &seq2);
	if (seq1 == 0) {
		/* nothing is missing */
		mailbox_header_lookup_unref(&headers_ctx);
		mail_index_strmap_view_sync_commit(&ctx->strmap_sync);
		return 0;
	}

	search_args = mail_search_build_init();
	mail_search_build_add_seqset(search_args, seq1, seq2);
	search_ctx = mailbox_search_init(ctx->t, search_args, NULL);

	mail = mail_alloc(ctx->t, 0, headers_ctx);
	mailbox_header_lookup_unref(&headers_ctx);

	while (mailbox_search_next(search_ctx, mail)) {
		if (mail_thread_map_add_mail(ctx, mail) < 0) {
			ret = -1;
			break;
		}
	}
	mail_free(&mail);
	if (mailbox_search_deinit(&search_ctx) < 0)
		ret = -1;

	if (ret < 0)
		mail_index_strmap_view_sync_rollback(&ctx->strmap_sync);
	else
		mail_index_strmap_view_sync_commit(&ctx->strmap_sync);
	return ret;
}

static int msgid_map_cmp(const void *key, const void *value)
{
	const uint32_t *uid = key;
	const struct mail_index_strmap_rec *rec = value;

	return *uid < rec->uid ? -1 :
		(*uid > rec->uid ? 1 : 0);
}

static bool mail_thread_cache_update_removes(struct mail_thread_mailbox *tbox,
					     ARRAY_TYPE(seq_range) *added_uids)
{
	struct mail_thread_cache *cache = tbox->cache;
	ARRAY_TYPE(seq_range) removed_uids;
	const struct seq_range *uids;
	const struct mail_index_strmap_rec *msgid_map;
	unsigned int i, j, idx, map_count, uid_count;
	uint32_t uid;

	t_array_init(&removed_uids, 64);
	mailbox_search_result_sync(cache->search_result,
				   &removed_uids, added_uids);

	/* first check that we're not inserting any messages in the middle */
	uids = array_get(added_uids, &uid_count);
	if (uid_count > 0 && uids[0].seq1 <= cache->last_uid)
		return FALSE;

	/* next remove messages so we'll see early if we have to rebuild.
	   we expect to find all removed UIDs from msgid_map that are <= max
	   UID in msgid_map */
	msgid_map = array_get(tbox->msgid_map, &map_count);
	uids = array_get(&removed_uids, &uid_count);
	for (i = j = 0; i < uid_count; i++) {
		/* find and remove from the map */
		bsearch_insert_pos(&uids[i].seq1, &msgid_map[j], map_count - j,
				   sizeof(*msgid_map), msgid_map_cmp, &idx);
		j += idx;
		if (j == map_count) {
			/* all removals after this are about messages we never
			   even added to the cache */
			i_assert(uids[i].seq1 > cache->last_uid);
			break;
		}
		while (j > 0 && msgid_map[j-1].uid == msgid_map[j].uid)
			j--;

		/* remove the messages from cache */
		for (uid = uids[i].seq1; uid <= uids[i].seq2; uid++) {
			if (j == map_count) {
				i_assert(uid > cache->last_uid);
				break;
			}
			i_assert(msgid_map[j].uid == uid);
			if (!mail_thread_remove(cache, msgid_map + j, &j))
				return FALSE;
		}
	}
	return TRUE;
}

static void mail_thread_cache_update_adds(struct mail_thread_mailbox *tbox,
					  ARRAY_TYPE(seq_range) *added_uids)
{
	struct mail_thread_cache *cache = tbox->cache;
	const struct seq_range *uids;
	const struct mail_index_strmap_rec *msgid_map;
	unsigned int i, j, map_count, uid_count;
	uint32_t uid;

	/* everything removed successfully, add the new messages. all of them
	   should already be in msgid_map. */
	uids = array_get(added_uids, &uid_count);
	if (uid_count == 0)
		return;

	(void)array_bsearch_insert_pos(tbox->msgid_map, &uids[0].seq1,
				       msgid_map_cmp, &j);
	msgid_map = array_get(tbox->msgid_map, &map_count);
	i_assert(j < map_count);
	while (j > 0 && msgid_map[j-1].uid == msgid_map[j].uid)
		j--;

	for (i = 0; i < uid_count; i++) {
		for (uid = uids[i].seq1; uid <= uids[i].seq2; uid++) {
			while (j < map_count && msgid_map[j].uid < uid)
				j++;
			i_assert(j < map_count && msgid_map[j].uid == uid);
			mail_thread_add(cache, msgid_map+j, &j);
		}
	}
}

static void
mail_thread_cache_fix_invalid_indexes(struct mail_thread_mailbox *tbox)
{
	struct mail_thread_cache *cache = tbox->cache;
	uint32_t highest_idx, new_first_idx, count;

	highest_idx = mail_index_strmap_view_get_highest_idx(tbox->strmap_view);
	new_first_idx = highest_idx + 1 +
		THREAD_INVALID_MSGID_STR_IDX_SKIP_COUNT;
	count = cache->next_invalid_msgid_str_idx -
		cache->first_invalid_msgid_str_idx;

	if (count == 0) {
		/* there are no invalid indexes yet, we can update the first
		   invalid index position to delay conflicts. */
		cache->first_invalid_msgid_str_idx =
			cache->next_invalid_msgid_str_idx = new_first_idx;
	} else if (highest_idx >= cache->first_invalid_msgid_str_idx) {
		/* conflict - move the invalid indexes forward */
		array_copy(&cache->thread_nodes.arr, new_first_idx,
			   &cache->thread_nodes.arr,
			   cache->first_invalid_msgid_str_idx, count);
		cache->first_invalid_msgid_str_idx = new_first_idx;
		cache->next_invalid_msgid_str_idx = new_first_idx + count;
	}
}

static void mail_thread_cache_sync_remove(struct mail_thread_mailbox *tbox,
					  struct mail_thread_context *ctx)
{
	struct mail_thread_cache *cache = tbox->cache;

	if (cache->search_result == NULL)
		return;

	if (mail_search_args_equal(ctx->search_args,
				   cache->search_result->search_args)) {
		t_array_init(&ctx->added_uids, 64);
		if (mail_thread_cache_update_removes(tbox, &ctx->added_uids)) {
			/* successfully updated the cache */
			return;
		}
	}
	/* failed to use the cache, rebuild */
	mailbox_search_result_free(&cache->search_result);
}

static void mail_thread_cache_sync_add(struct mail_thread_mailbox *tbox,
				       struct mail_thread_context *ctx,
				       struct mail_search_context *search_ctx)
{
	struct mail_thread_cache *cache = tbox->cache;
	struct mail *mail;
	const struct mail_index_strmap_rec *msgid_map;
	unsigned int i, count;

	mail_thread_cache_fix_invalid_indexes(tbox);

	if (cache->search_result != NULL) {
		/* we already checked at sync_remove that we can use this
		   search result. */
		mail_thread_cache_update_adds(tbox, &ctx->added_uids);
		return;
	}

	cache->last_uid = 0;
	cache->first_invalid_msgid_str_idx = cache->next_invalid_msgid_str_idx =
		mail_index_strmap_view_get_highest_idx(tbox->strmap_view) + 1 +
		THREAD_INVALID_MSGID_STR_IDX_SKIP_COUNT;
	array_clear(&cache->thread_nodes);

	mail = mail_alloc(ctx->t, 0, NULL);

	cache->search_result =
		mailbox_search_result_save(search_ctx,
			MAILBOX_SEARCH_RESULT_FLAG_UPDATE |
			MAILBOX_SEARCH_RESULT_FLAG_QUEUE_SYNC);

	msgid_map = array_get(tbox->msgid_map, &count);
	/* we're relying on the array being zero-terminated (outside used
	   count - kind of kludgy) */
	i_assert(msgid_map[count].uid == 0);
	i = 0;
	while (i < count && mailbox_search_next(search_ctx, mail)) {
		while (msgid_map[i].uid < mail->uid)
			i++;
		i_assert(i < count);
		mail_thread_add(cache, msgid_map+i, &i);
	}
	mail_free(&mail);
}

int mail_thread_init(struct mailbox *box, struct mail_search_args *args,
		     struct mail_thread_context **ctx_r)
{
	struct mail_thread_mailbox *tbox = MAIL_THREAD_CONTEXT(box);
	struct mail_thread_context *ctx;
	struct mail_search_context *search_ctx;
	int ret;

	i_assert(tbox->ctx == NULL);

	if (args != NULL)
		mail_search_args_ref(args);
	else {
		args = mail_search_build_init();
		mail_search_build_add_all(args);
		mail_search_args_init(args, box, FALSE, NULL);
	}

	ctx = i_new(struct mail_thread_context, 1);
	ctx->box = box;
	ctx->search_args = args;
	ctx->t = mailbox_transaction_begin(ctx->box, 0);
	/* perform search first, so we don't break if there are INTHREAD keys */
	search_ctx = mailbox_search_init(ctx->t, args, NULL);

	tbox->ctx = ctx;

	mail_thread_cache_sync_remove(tbox, ctx);
	ret = mail_thread_index_map_build(ctx);
	if (ret == 0)
		mail_thread_cache_sync_add(tbox, ctx, search_ctx);
	if (mailbox_search_deinit(&search_ctx) < 0)
		ret = -1;

	if (ret < 0) {
		mail_thread_deinit(&ctx);
		return -1;
	} else {
		memset(&ctx->added_uids, 0, sizeof(ctx->added_uids));
		*ctx_r = ctx;
		return 0;
	}
}

static void mail_thread_clear(struct mail_thread_context *ctx)
{
	mail_free(&ctx->tmp_mail);
	(void)mailbox_transaction_commit(&ctx->t);
}

void mail_thread_deinit(struct mail_thread_context **_ctx)
{
	struct mail_thread_context *ctx = *_ctx;
	struct mail_thread_mailbox *tbox = MAIL_THREAD_CONTEXT(ctx->box);

	*_ctx = NULL;

	mail_thread_clear(ctx);
	mail_search_args_unref(&ctx->search_args);
	tbox->ctx = NULL;
	i_free(ctx);
}

struct mail_thread_iterate_context *
mail_thread_iterate_init(struct mail_thread_context *ctx,
			 enum mail_thread_type thread_type, bool write_seqs)
{
	struct mail_thread_mailbox *tbox = MAIL_THREAD_CONTEXT(ctx->box);

	return mail_thread_iterate_init_full(tbox->cache, ctx->tmp_mail,
					     thread_type, write_seqs);
}

static void mail_thread_mailbox_close(struct mailbox *box)
{
	struct mail_thread_mailbox *tbox = MAIL_THREAD_CONTEXT(box);

	i_assert(tbox->ctx == NULL);

	if (tbox->strmap_view != NULL)
		mail_index_strmap_view_close(&tbox->strmap_view);
	if (tbox->cache->search_result != NULL)
		mailbox_search_result_free(&tbox->cache->search_result);
	tbox->module_ctx.super.close(box);
}

static void mail_thread_mailbox_free(struct mailbox *box)
{
	struct mail_thread_mailbox *tbox = MAIL_THREAD_CONTEXT(box);

	mail_index_strmap_deinit(&tbox->strmap);
	tbox->module_ctx.super.free(box);

	array_free(&tbox->cache->thread_nodes);
	i_free(tbox->cache);
	i_free(tbox);
}

void index_thread_mailbox_opened(struct mailbox *box)
{
	struct mail_thread_mailbox *tbox = MAIL_THREAD_CONTEXT(box);

	if (tbox != NULL) {
		/* mailbox was already opened+closed once. */
		return;
	}

	tbox = i_new(struct mail_thread_mailbox, 1);
	tbox->module_ctx.super = box->v;
	box->v.close = mail_thread_mailbox_close;
	box->v.free = mail_thread_mailbox_free;

	tbox->strmap = mail_index_strmap_init(box->index,
					      MAIL_THREAD_INDEX_SUFFIX);
	tbox->next_msgid_idx = 1;

	tbox->cache = i_new(struct mail_thread_cache, 1);
	i_array_init(&tbox->cache->thread_nodes, 128);

	MODULE_CONTEXT_SET(box, mail_thread_storage_module, tbox);
}
