/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "index-storage.h"
#include "index-sync-changes.h"

struct index_sync_changes_context {
	struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *sync_trans;

	ARRAY(struct mail_index_sync_rec) syncs;
	struct mail_index_sync_rec sync_rec;
	bool dirty_flag_updates;
};

struct index_sync_changes_context *
index_sync_changes_init(struct mail_index_sync_ctx *index_sync_ctx,
			struct mail_index_view *sync_view,
			struct mail_index_transaction *sync_trans,
			bool dirty_flag_updates)
{
	struct index_sync_changes_context *ctx;

	ctx = i_new(struct index_sync_changes_context, 1);
	ctx->index_sync_ctx = index_sync_ctx;
	ctx->sync_view = sync_view;
	ctx->sync_trans = sync_trans;
	ctx->dirty_flag_updates = dirty_flag_updates;
	i_array_init(&ctx->syncs, 16);
	return ctx;
}

void index_sync_changes_deinit(struct index_sync_changes_context **_ctx)
{
	struct index_sync_changes_context *ctx = *_ctx;

	*_ctx = NULL;
	array_free(&ctx->syncs);
	i_free(ctx);
}

void index_sync_changes_reset(struct index_sync_changes_context *ctx)
{
	array_clear(&ctx->syncs);
	i_zero(&ctx->sync_rec);
}

void index_sync_changes_delete_to(struct index_sync_changes_context *ctx,
				  uint32_t last_uid)
{
	struct mail_index_sync_rec *syncs;
	unsigned int src, dest, count;

	syncs = array_get_modifiable(&ctx->syncs, &count);

	for (src = dest = 0; src < count; src++) {
		i_assert(last_uid >= syncs[src].uid1);
		if (last_uid <= syncs[src].uid2) {
			/* keep it */
			if (src != dest)
				syncs[dest] = syncs[src];
			dest++;
		}
	}

	array_delete(&ctx->syncs, dest, count - dest);
}

static bool
index_sync_changes_have_expunges(struct index_sync_changes_context *ctx,
				 unsigned int count,
				 guid_128_t expunged_guid_128_r)
{
	const struct mail_index_sync_rec *syncs;
	unsigned int i;

	syncs = array_front(&ctx->syncs);
	for (i = 0; i < count; i++) {
		if (syncs[i].type == MAIL_INDEX_SYNC_TYPE_EXPUNGE) {
			memcpy(expunged_guid_128_r, syncs[i].guid_128,
			       GUID_128_SIZE);
			return TRUE;
		}
	}
	return FALSE;
}

void index_sync_changes_read(struct index_sync_changes_context *ctx,
			     uint32_t uid, bool *sync_expunge_r,
			     guid_128_t expunged_guid_128_r)
{
	struct mail_index_sync_rec *sync_rec = &ctx->sync_rec;
	uint32_t seq1, seq2;
	unsigned int orig_count;

	*sync_expunge_r = FALSE;

	index_sync_changes_delete_to(ctx, uid);
	orig_count = array_count(&ctx->syncs);

	while (uid >= sync_rec->uid1) {
		if (uid <= sync_rec->uid2) {
			array_push_back(&ctx->syncs, sync_rec);

			if (sync_rec->type == MAIL_INDEX_SYNC_TYPE_EXPUNGE) {
				*sync_expunge_r = TRUE;
				memcpy(expunged_guid_128_r, sync_rec->guid_128,
				       GUID_128_SIZE);
			}
		}

		if (!mail_index_sync_next(ctx->index_sync_ctx, sync_rec)) {
			i_zero(sync_rec);
			break;
		}

		switch (sync_rec->type) {
		case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
			break;
		case MAIL_INDEX_SYNC_TYPE_FLAGS:
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
			if (!ctx->dirty_flag_updates)
				break;

			/* mark the changes as dirty */
			(void)mail_index_lookup_seq_range(ctx->sync_view,
							  sync_rec->uid1,
							  sync_rec->uid2,
							  &seq1, &seq2);
			i_zero(sync_rec);

			if (seq1 == 0)
				break;

			mail_index_update_flags_range(ctx->sync_trans,
				seq1, seq2, MODIFY_ADD,
				(enum mail_flags)MAIL_INDEX_MAIL_FLAG_DIRTY);
			break;
		}
	}

	if (!*sync_expunge_r && orig_count > 0) {
		*sync_expunge_r =
			index_sync_changes_have_expunges(ctx, orig_count,
							 expunged_guid_128_r);
	}
}

bool index_sync_changes_have(struct index_sync_changes_context *ctx)
{
	return array_count(&ctx->syncs) > 0;
}

uint32_t
index_sync_changes_get_next_uid(struct index_sync_changes_context *ctx)
{
	return ctx->sync_rec.uid1;
}

void index_sync_changes_apply(struct index_sync_changes_context *ctx,
			      pool_t pool, uint8_t *flags,
			      ARRAY_TYPE(keyword_indexes) *keywords,
			      enum mail_index_sync_type *sync_type_r)
{
	const struct mail_index_sync_rec *syncs;
	unsigned int i, count;
	enum mail_index_sync_type sync_type = 0;

	syncs = array_get(&ctx->syncs, &count);
	for (i = 0; i < count; i++) {
		switch (syncs[i].type) {
		case MAIL_INDEX_SYNC_TYPE_FLAGS:
			mail_index_sync_flags_apply(&syncs[i], flags);
			sync_type |= MAIL_INDEX_SYNC_TYPE_FLAGS;
			break;
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
			if (!array_is_created(keywords)) {
				/* no existing keywords */
				if (syncs[i].type !=
				    MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD)
					break;

				/* adding, create the array */
				p_array_init(keywords, pool,
					     I_MIN(10, count - i));
			}
			if (mail_index_sync_keywords_apply(&syncs[i], keywords))
				sync_type |= syncs[i].type;
			break;
		default:
			break;
		}
	}

	*sync_type_r = sync_type;
}
