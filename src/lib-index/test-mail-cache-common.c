/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "test-mail-cache.h"

static const struct mail_cache_field cache_field_foo = {
	.name = "foo",
	.type = MAIL_CACHE_FIELD_STRING,
	.decision = MAIL_CACHE_DECISION_YES,
};
static const struct mail_cache_field cache_field_bar = {
	.name = "bar",
	.type = MAIL_CACHE_FIELD_STRING,
	.decision = MAIL_CACHE_DECISION_YES,
};
static const struct mail_cache_field cache_field_baz = {
	.name = "baz",
	.type = MAIL_CACHE_FIELD_STRING,
	.decision = MAIL_CACHE_DECISION_YES,
};

void test_mail_cache_init(struct mail_index *index,
			  struct test_mail_cache_ctx *ctx_r)
{
	i_zero(ctx_r);
	ctx_r->index = index;
	ctx_r->cache = index->cache;
	ctx_r->view = mail_index_view_open(index);

	ctx_r->cache_field = cache_field_foo;
	ctx_r->cache_field2 = cache_field_bar;
	ctx_r->cache_field3 = cache_field_baz;
	/* Try to use different file_field_maps for different index instances
	   by randomizing the registration order. This only works for the 2nd
	   index that is opened, because the initial cache is always created
	   with all cache fields in the same order. */
	if (i_rand_limit(2) == 0) {
		mail_cache_register_fields(ctx_r->cache, &ctx_r->cache_field, 1);
		mail_cache_register_fields(ctx_r->cache, &ctx_r->cache_field2, 1);
		mail_cache_register_fields(ctx_r->cache, &ctx_r->cache_field3, 1);
	} else {
		mail_cache_register_fields(ctx_r->cache, &ctx_r->cache_field3, 1);
		mail_cache_register_fields(ctx_r->cache, &ctx_r->cache_field2, 1);
		mail_cache_register_fields(ctx_r->cache, &ctx_r->cache_field, 1);
	}
}

void test_mail_cache_deinit(struct test_mail_cache_ctx *ctx)
{
	if (ctx->view != NULL)
		mail_index_view_close(&ctx->view);
	test_mail_index_close(&ctx->index);
}

unsigned int test_mail_cache_get_purge_count(struct test_mail_cache_ctx *ctx)
{
	const struct mail_cache_header *hdr = ctx->cache->hdr;

	return hdr->file_seq - hdr->indexid;
}

void test_mail_cache_index_sync(struct test_mail_cache_ctx *ctx)
{
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	struct mail_index_sync_rec sync_rec;

	test_assert(mail_index_sync_begin(ctx->index, &sync_ctx,
					  &view, &trans, 0) == 1);
	while (mail_index_sync_next(sync_ctx, &sync_rec)) {
		if (sync_rec.type == MAIL_INDEX_SYNC_TYPE_EXPUNGE) {
			/* we're a bit kludgily assuming that there's only
			   one UID and also that uid==seq */
			mail_index_expunge(trans, sync_rec.uid1);
		}
	}
	test_assert(mail_index_sync_commit(&sync_ctx) == 0);
}

void test_mail_cache_view_sync(struct test_mail_cache_ctx *ctx)
{
	struct mail_index_view_sync_ctx *sync_ctx;
	struct mail_index_view_sync_rec sync_rec;
	bool delayed_expunges;

	sync_ctx = mail_index_view_sync_begin(ctx->view, MAIL_INDEX_VIEW_SYNC_FLAG_FIX_INCONSISTENT);
	while (mail_index_view_sync_next(sync_ctx, &sync_rec)) ;
	test_assert(mail_index_view_sync_commit(&sync_ctx, &delayed_expunges) == 0);
}

void test_mail_cache_purge(void)
{
	struct test_mail_cache_ctx ctx;

	test_mail_cache_init(test_mail_index_open(), &ctx);
	test_assert(mail_cache_purge(ctx.cache, (uint32_t)-1, "test") == 0);
	test_mail_cache_deinit(&ctx);
}

void test_mail_cache_add_mail(struct test_mail_cache_ctx *ctx,
			      unsigned int cache_field_idx,
			      const char *cache_data)
{
	const struct mail_index_header *hdr = mail_index_get_header(ctx->view);
	struct mail_index_transaction *trans;
	struct mail_index_view *updated_view;
	struct mail_cache_view *cache_view;
	struct mail_cache_transaction_ctx *cache_trans;
	uint32_t seq, uid_validity = 12345;

	trans = mail_index_transaction_begin(ctx->view, 0);
	updated_view = mail_index_transaction_open_updated_view(trans);
	cache_view = mail_cache_view_open(ctx->cache, updated_view);
	cache_trans = mail_cache_get_transaction(cache_view, trans);

	if (hdr->uid_validity == 0) {
		mail_index_update_header(trans,
			offsetof(struct mail_index_header, uid_validity),
			&uid_validity, sizeof(uid_validity), TRUE);
	}

	mail_index_append(trans, hdr->next_uid, &seq);
	if (cache_field_idx != UINT_MAX) {
		mail_cache_add(cache_trans, seq, cache_field_idx,
			       cache_data, strlen(cache_data));
	}
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(&updated_view);
	mail_cache_view_close(&cache_view);

	/* View needs to have the latest changes before purge transaction
	   is created. */
	test_mail_cache_view_sync(ctx);
}

void test_mail_cache_add_field(struct test_mail_cache_ctx *ctx, uint32_t seq,
			       unsigned int cache_field_idx,
			       const char *cache_data)
{
	struct mail_index_transaction *trans;
	struct mail_cache_view *cache_view;
	struct mail_cache_transaction_ctx *cache_trans;

	cache_view = mail_cache_view_open(ctx->cache, ctx->view);
	trans = mail_index_transaction_begin(ctx->view, 0);
	cache_trans = mail_cache_get_transaction(cache_view, trans);
	mail_cache_add(cache_trans, seq, cache_field_idx,
		       cache_data, strlen(cache_data));
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_cache_view_close(&cache_view);
}

void test_mail_cache_update_day_first_uid7(struct test_mail_cache_ctx *ctx,
					   uint32_t first_new_uid)
{
	struct mail_index_transaction *trans;

	trans = mail_index_transaction_begin(ctx->view, 0);
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, day_first_uid[7]),
		&first_new_uid, sizeof(first_new_uid), FALSE);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	test_mail_cache_view_sync(ctx);
}
