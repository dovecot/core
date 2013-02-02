/* Copyright (c) 2004-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-cache-private.h"
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

static struct mail_cache_sync_context *mail_cache_handler_init(void **context)
{
	struct mail_cache_sync_context *ctx;

	if (*context != NULL)
		ctx = *context;
	else {
		*context = i_new(struct mail_cache_sync_context, 1);
		ctx = *context;
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
		mail_cache_delete(cache);
	return 0;
}
