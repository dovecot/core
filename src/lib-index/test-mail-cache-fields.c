/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "test-mail-cache.h"

static void test_mail_cache_fields_read_write(void)
{
	struct mail_cache_field cache_field = {
		.name = "testfield",
		.type = MAIL_CACHE_FIELD_STRING,
		.decision = MAIL_CACHE_DECISION_NO,
		.last_used = 0x12345678,
	};
	struct mail_cache_field cache_field2 = {
		.name = "testfield2",
		.type = MAIL_CACHE_FIELD_STRING,
		.decision = MAIL_CACHE_DECISION_NO,
		.last_used = 0xaabbccdd,
	};
	struct test_mail_cache_ctx ctx;

	test_begin("mail cache fields read-write");

	test_mail_cache_init(test_mail_index_init(), &ctx);
	mail_cache_register_fields(ctx.cache, &cache_field, 1,
				   unsafe_data_stack_pool);
	test_assert(mail_cache_purge(ctx.cache, (uint32_t)-1, "test") == 0);
	/* after writing the initial cache file, register another cache field
	   that doesn't exist in it. */
	mail_cache_register_fields(ctx.cache, &cache_field2, 1,
				   unsafe_data_stack_pool);

	struct mail_cache_field_private *priv =
		&ctx.cache->fields[cache_field.idx];
	struct mail_cache_field_private *priv2 =
		&ctx.cache->fields[cache_field2.idx];

	/* No changes */
	test_assert(mail_cache_header_fields_update(ctx.cache) == 0);
	test_assert(mail_cache_header_fields_read(ctx.cache) == 0);
	test_assert(cache_field.last_used == priv->field.last_used &&
		    cache_field.decision == priv->field.decision);
	test_assert(cache_field2.last_used == priv2->field.last_used &&
		    cache_field2.decision == priv2->field.decision);

	/* Replace decision without marking it dirty. Make sure reading
	   overwrites it. Also make sure an old last_used is overwritten. */
	priv->field.decision = MAIL_CACHE_DECISION_YES;
	priv->field.last_used = cache_field.last_used - 1;
	test_assert(mail_cache_header_fields_read(ctx.cache) == 0);
	test_assert(cache_field.last_used == priv->field.last_used &&
		    cache_field.decision == priv->field.decision);
	test_assert(cache_field2.last_used == priv2->field.last_used &&
		    cache_field2.decision == priv2->field.decision);

	/* Replace decision and set it dirty. Make sure reading doesn't
	   overwrite it. Also make sure an old last_used is overwritten. */
	priv->decision_dirty = TRUE;
	priv2->decision_dirty = TRUE;
	priv->field.last_used = cache_field.last_used - 1;
	priv->field.decision = MAIL_CACHE_DECISION_YES;
	cache_field.decision = MAIL_CACHE_DECISION_YES;
	priv2->field.decision = MAIL_CACHE_DECISION_YES;
	cache_field2.decision = MAIL_CACHE_DECISION_YES;
	test_assert(mail_cache_header_fields_read(ctx.cache) == 0);
	test_assert(cache_field.last_used == priv->field.last_used &&
		    cache_field.decision == priv->field.decision);
	test_assert(cache_field2.last_used == priv2->field.last_used &&
		    cache_field2.decision == priv2->field.decision);
	test_assert(priv->decision_dirty);
	test_assert(priv2->decision_dirty);

	/* Make sure a new last_used won't get overwritten by read. */
	priv->field.last_used = ++cache_field.last_used;
	priv2->field.last_used = ++cache_field2.last_used;
	test_assert(mail_cache_header_fields_read(ctx.cache) == 0);
	test_assert(cache_field.last_used == priv->field.last_used &&
		    cache_field.decision == priv->field.decision);
	test_assert(cache_field2.last_used == priv2->field.last_used &&
		    cache_field2.decision == priv2->field.decision);

	/* Write the new decision and last_used. Note that cache_field2
	   isn't written, because it doesn't exist in the cache file. */
	test_assert(mail_cache_header_fields_update(ctx.cache) == 0);
	test_assert(!priv->decision_dirty);
	test_assert(priv2->decision_dirty);
	/* make sure reading reads them back, even if they're changed */
	priv->field.decision = MAIL_CACHE_DECISION_NO;
	priv->field.last_used = 1;
	priv2->field.decision = MAIL_CACHE_DECISION_TEMP;
	priv2->field.last_used = 2;
	cache_field2.decision = MAIL_CACHE_DECISION_TEMP;
	cache_field2.last_used = 2;
	test_assert(mail_cache_header_fields_read(ctx.cache) == 0);
	test_assert(cache_field.last_used == priv->field.last_used &&
		    cache_field.decision == priv->field.decision);
	test_assert(cache_field2.last_used == priv2->field.last_used &&
		    cache_field2.decision == priv2->field.decision);

	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_cache_fields_read_write,
		NULL
	};
	return test_run(test_functions);
}
