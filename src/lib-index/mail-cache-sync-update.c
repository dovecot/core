/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "file-cache.h"
#include "mail-cache-private.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"

struct mail_cache_sync_context {
	unsigned int locked:1;
	unsigned int lock_failed:1;
};

static void mail_cache_handler_deinit(struct mail_index_sync_map_ctx *sync_ctx,
				      struct mail_cache_sync_context *ctx)
{
	if (ctx == NULL)
		return;

	if (ctx->locked)
		(void)mail_cache_unlock(sync_ctx->view->index->cache);
	i_free(ctx);
}

static int mail_cache_handler_init(struct mail_cache_sync_context **ctx_r,
				   struct mail_cache *cache)
{
	struct mail_cache_sync_context *ctx = *ctx_r;
	int ret;

	if (ctx == NULL)
		ctx = *ctx_r = i_new(struct mail_cache_sync_context, 1);

	if (ctx->locked)
		return 1;
	if (ctx->lock_failed)
		return 0;

	if (!ctx->locked) {
		if ((ret = mail_cache_lock(cache)) <= 0) {
                        ctx->lock_failed = TRUE;
			return ret;
		}
		ctx->locked = TRUE;
	}
	return 1;
}

static int get_cache_file_seq(struct mail_index_view *view,
			      uint32_t *cache_file_seq_r)
{
	const struct mail_index_ext *ext;

	ext = mail_index_view_get_ext(view, view->index->cache->ext_id);
	if (ext == NULL)
		return 0;

	*cache_file_seq_r = ext->reset_id;
	return 1;
}

int mail_cache_expunge_handler(struct mail_index_sync_map_ctx *sync_ctx,
			       uint32_t seq __attr_unused__, const void *data,
			       void **sync_context, void *context)
{
	struct mail_cache *cache = context;
	struct mail_cache_sync_context *ctx = *sync_context;
	const uint32_t *cache_offset = data;
	uint32_t cache_file_seq;
	int ret;

	if (data == NULL) {
		mail_cache_handler_deinit(sync_ctx, ctx);
		*sync_context = NULL;
		return 0;
	}

	if (*cache_offset == 0)
		return 0;

	if (MAIL_CACHE_IS_UNUSABLE(cache))
		return 0;

	ret = mail_cache_handler_init(&ctx, cache);
	*sync_context = ctx;
	if (ret <= 0)
		return ret;

	if (!get_cache_file_seq(sync_ctx->view, &cache_file_seq))
		return 0;

	if (!MAIL_CACHE_IS_UNUSABLE(cache) &&
	    cache_file_seq == cache->hdr->file_seq)
		(void)mail_cache_delete(cache, *cache_offset);
	return 0;
}

int mail_cache_sync_handler(struct mail_index_sync_map_ctx *sync_ctx,
			    uint32_t seq __attr_unused__,
			    void *old_data, const void *new_data,
			    void **context)
{
	struct mail_index_view *view = sync_ctx->view;
	struct mail_cache *cache = view->index->cache;
	struct mail_cache_sync_context *ctx = *context;
	const uint32_t *old_cache_offset = old_data;
	const uint32_t *new_cache_offset = new_data;
	uint32_t cache_file_seq, cur_seq, tail_seq;
	uoff_t cur_offset, tail_offset;
	int ret;

	if (new_cache_offset == NULL) {
		mail_cache_handler_deinit(sync_ctx, ctx);
		*context = NULL;
		return 1;
	}

	if (MAIL_CACHE_IS_UNUSABLE(cache))
		return 1;

	if (cache->file_cache != NULL) {
		file_cache_invalidate(cache->file_cache, *new_cache_offset,
				      (uoff_t)-1);
	}

	if (*old_cache_offset == 0 || *old_cache_offset == *new_cache_offset ||
	    sync_ctx->type == MAIL_INDEX_SYNC_HANDLER_VIEW)
		return 1;

	mail_transaction_log_view_get_prev_pos(view->log_view,
					       &cur_seq, &cur_offset);
	mail_transaction_log_get_mailbox_sync_pos(view->index->log,
						  &tail_seq, &tail_offset);
	if (LOG_IS_BEFORE(cur_seq, cur_offset, tail_seq, tail_offset)) {
		/* already been linked */
		return 1;
	}

	/* we'll need to link the old and new cache records */
	ret = mail_cache_handler_init(&ctx, cache);
	*context = ctx;
	if (ret <= 0)
		return ret < 0 ? -1 : 1;

	if (!get_cache_file_seq(view, &cache_file_seq))
		return 1;

	if (cache_file_seq != cache->hdr->file_seq) {
		/* cache has been compressed, don't modify it */
		return 1;
	}

	if (mail_cache_link(cache, *old_cache_offset, *new_cache_offset) < 0)
		return -1;

	return 1;
}

void mail_cache_sync_lost_handler(struct mail_index *index)
{
	file_cache_invalidate(index->cache->file_cache, 0, (uoff_t)-1);
}
