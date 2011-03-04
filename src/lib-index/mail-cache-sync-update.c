/* Copyright (c) 2004-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "file-cache.h"
#include "mail-cache-private.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"

struct mail_cache_sync_context {
	uoff_t invalidate_highwater;

	unsigned int locked:1;
	unsigned int lock_failed:1;
	unsigned int nfs_read_cache_flushed:1;
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

static struct mail_cache_sync_context *mail_cache_handler_init(void **context)
{
	struct mail_cache_sync_context *ctx;

	if (*context != NULL)
		ctx = *context;
	else {
		*context = i_new(struct mail_cache_sync_context, 1);
		ctx = *context;
		ctx->invalidate_highwater = (uoff_t)-1;
	}
	return ctx;
}

static int mail_cache_handler_lock(struct mail_cache_sync_context *ctx,
				   struct mail_cache *cache)
{
	int ret;

	if (ctx->locked)
		return MAIL_CACHE_IS_UNUSABLE(cache) ? 0 : 1;
	if (ctx->lock_failed)
		return 0;

	if (!ctx->locked) {
		if ((ret = mail_cache_lock(cache, TRUE)) <= 0) {
                        ctx->lock_failed = TRUE;
			return ret;
		}
		ctx->locked = TRUE;
	}
	return 1;
}

static bool get_cache_file_seq(struct mail_index_view *view,
			      uint32_t *cache_file_seq_r)
{
	const struct mail_index_ext *ext;

	ext = mail_index_view_get_ext(view, view->index->cache->ext_id);
	if (ext == NULL)
		return FALSE;

	*cache_file_seq_r = ext->reset_id;
	return TRUE;
}

int mail_cache_expunge_handler(struct mail_index_sync_map_ctx *sync_ctx,
			       uint32_t seq ATTR_UNUSED, const void *data,
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

	ctx = mail_cache_handler_init(sync_context);
	ret = mail_cache_handler_lock(ctx, cache);
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
			    uint32_t seq ATTR_UNUSED,
			    void *old_data, const void *new_data,
			    void **context)
{
	struct mail_index_view *view = sync_ctx->view;
	struct mail_index *index = view->index;
	struct mail_cache *cache = index->cache;
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

	ctx = mail_cache_handler_init(context);
	if (cache->file_cache != NULL && !MAIL_CACHE_IS_UNUSABLE(cache)) {
		/* flush read cache only once per sync */
		if (!ctx->nfs_read_cache_flushed &&
		    (index->flags & MAIL_INDEX_OPEN_FLAG_NFS_FLUSH) != 0) {
			ctx->nfs_read_cache_flushed = TRUE;
			mail_index_flush_read_cache(index,
						    cache->filepath, cache->fd,
						    cache->locked);
		}
		/* don't invalidate anything that's already been invalidated
		   within this sync. */
		if (*new_cache_offset < ctx->invalidate_highwater) {
			file_cache_invalidate(cache->file_cache,
					      *new_cache_offset,
					      ctx->invalidate_highwater -
					      *new_cache_offset);
			ctx->invalidate_highwater = *new_cache_offset;
		}
	}

	if (*old_cache_offset == 0 || *old_cache_offset == *new_cache_offset ||
	    sync_ctx->type == MAIL_INDEX_SYNC_HANDLER_VIEW)
		return 1;

	mail_transaction_log_view_get_prev_pos(view->log_view,
					       &cur_seq, &cur_offset);
	mail_transaction_log_get_mailbox_sync_pos(index->log,
						  &tail_seq, &tail_offset);
	if (LOG_IS_BEFORE(cur_seq, cur_offset, tail_seq, tail_offset)) {
		/* already been linked */
		return 1;
	}

	/* we'll need to link the old and new cache records */
	ret = mail_cache_handler_lock(ctx, cache);
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
	struct mail_cache *cache = index->cache;

	if (!MAIL_CACHE_IS_UNUSABLE(cache)) {
		mail_index_flush_read_cache(cache->index, cache->filepath,
					    cache->fd, cache->locked);
	}
	file_cache_invalidate(cache->file_cache, 0, (uoff_t)-1);
}
