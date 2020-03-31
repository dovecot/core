#ifndef TEST_MAIL_CACHE_H
#define TEST_MAIL_CACHE_H

#include "test-mail-index.h"
#include "mail-cache-private.h"

struct test_mail_cache_ctx {
	struct mail_index *index;
	struct mail_cache *cache;
	struct mail_index_view *view;

	struct mail_cache_field cache_field, cache_field2, cache_field3;
};

void test_mail_cache_init(struct mail_index *index,
			  struct test_mail_cache_ctx *ctx_r);
void test_mail_cache_deinit(struct test_mail_cache_ctx *ctx);

unsigned int test_mail_cache_get_purge_count(struct test_mail_cache_ctx *ctx);
void test_mail_cache_index_sync(struct test_mail_cache_ctx *ctx);
void test_mail_cache_view_sync(struct test_mail_cache_ctx *ctx);
void test_mail_cache_purge(void);
void test_mail_cache_add_mail(struct test_mail_cache_ctx *ctx,
			      unsigned int cache_field_idx,
			      const char *cache_data);
void test_mail_cache_add_field(struct test_mail_cache_ctx *ctx, uint32_t seq,
			       unsigned int cache_field_idx,
			       const char *cache_data);
void test_mail_cache_update_day_first_uid7(struct test_mail_cache_ctx *ctx,
					   uint32_t first_new_uid);

#endif
