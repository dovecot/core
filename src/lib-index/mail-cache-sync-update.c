/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-cache-private.h"
#include "mail-index-sync-private.h"

struct mail_cache_sync_context {
	unsigned expunge_count;
};

void mail_cache_expunge_count(struct mail_cache *cache, unsigned int count)
{
	if (mail_cache_lock(cache) > 0) {
		cache->hdr_copy.deleted_record_count += count;
		if (cache->hdr_copy.record_count >= count)
			cache->hdr_copy.record_count -= count;
		else
			 cache->hdr_copy.record_count = 0;
		cache->hdr_modified = TRUE;
		(void)mail_cache_flush_and_unlock(cache);
	}
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

static void mail_cache_handler_deinit(struct mail_index_sync_map_ctx *sync_ctx,
				      struct mail_cache_sync_context *ctx)
{
	struct mail_cache *cache = sync_ctx->view->index->cache;

	if (ctx == NULL)
		return;

	mail_cache_expunge_count(cache, ctx->expunge_count);

	i_free(ctx);
}

int mail_cache_expunge_handler(struct mail_index_sync_map_ctx *sync_ctx,
			       uint32_t seq ATTR_UNUSED, const void *data,
			       void **sync_context, void *context ATTR_UNUSED)
{
	struct mail_cache_sync_context *ctx = *sync_context;
	const uint32_t *cache_offset = data;

	if (data == NULL) {
		mail_cache_handler_deinit(sync_ctx, ctx);
		*sync_context = NULL;
		return 0;
	}

	if (*cache_offset == 0)
		return 0;

	ctx = mail_cache_handler_init(sync_context);
	ctx->expunge_count++;
	return 0;
}
