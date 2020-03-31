/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "test-common.h"
#include "test-mail-cache.h"

struct test_header_data {
	uint32_t line1, line2;
	uint32_t end_of_lines;
	char headers[8];
};

enum {
	TEST_FIELD_NO,
	TEST_FIELD_NO_FORCED,
	TEST_FIELD_TEMP,
	TEST_FIELD_TEMP_FORCED,
	TEST_FIELD_YES,
	TEST_FIELD_YES_FORCED,
	TEST_FIELD_COUNT,
};
static const struct mail_cache_field decision_cache_fields[TEST_FIELD_COUNT] = {
	{
		.name = "no",
		.type = MAIL_CACHE_FIELD_STRING,
		.decision = MAIL_CACHE_DECISION_NO,
	},
	{
		.name = "no-forced",
		.type = MAIL_CACHE_FIELD_STRING,
		.decision = MAIL_CACHE_DECISION_NO | MAIL_CACHE_DECISION_FORCED,
	},
	{
		.name = "temp",
		.type = MAIL_CACHE_FIELD_STRING,
		.decision = MAIL_CACHE_DECISION_TEMP,
	},
	{
		.name = "temp-forced",
		.type = MAIL_CACHE_FIELD_STRING,
		.decision = MAIL_CACHE_DECISION_TEMP | MAIL_CACHE_DECISION_FORCED,
	},
	{
		.name = "yes",
		.type = MAIL_CACHE_FIELD_STRING,
		.decision = MAIL_CACHE_DECISION_YES,
	},
	{
		.name = "yes-forced",
		.type = MAIL_CACHE_FIELD_STRING,
		.decision = MAIL_CACHE_DECISION_YES | MAIL_CACHE_DECISION_FORCED,
	},
};

static void test_mail_cache_fields(void)
{
	enum {
		TEST_FIELD_FIXED,
		TEST_FIELD_VARIABLE,
		TEST_FIELD_STRING,
		TEST_FIELD_BITMASK,
		TEST_FIELD_HEADER1,
		TEST_FIELD_HEADER2,
	};
	struct mail_cache_field cache_fields[] = {
		{
			.name = "fixed",
			.type = MAIL_CACHE_FIELD_FIXED_SIZE,
			.field_size = 4,
			.decision = MAIL_CACHE_DECISION_YES,
		},
		{
			.name = "variable",
			.type = MAIL_CACHE_FIELD_VARIABLE_SIZE,
			.decision = MAIL_CACHE_DECISION_YES,
		},
		{
			.name = "string",
			.type = MAIL_CACHE_FIELD_STRING,
			.decision = MAIL_CACHE_DECISION_YES,
		},
		{
			.name = "bitmask",
			.type = MAIL_CACHE_FIELD_BITMASK,
			.field_size = 4,
			.decision = MAIL_CACHE_DECISION_YES,
		},
		{
			.name = "header1",
			.type = MAIL_CACHE_FIELD_HEADER,
			.decision = MAIL_CACHE_DECISION_YES,
		},
		{
			.name = "header2",
			.type = MAIL_CACHE_FIELD_HEADER,
			.decision = MAIL_CACHE_DECISION_YES,
		},
	};
	struct test_mail_cache_ctx ctx;
	struct mail_index_transaction *trans;
	struct mail_cache_view *cache_view;
	struct mail_cache_transaction_ctx *cache_trans;
	string_t *str = t_str_new(16);

	test_begin("mail cache uncommitted lookups");
	test_mail_cache_init(test_mail_index_init(), &ctx);
	mail_cache_register_fields(ctx.cache, cache_fields,
				   N_ELEMENTS(cache_fields));

	test_mail_cache_add_mail(&ctx, UINT_MAX, NULL);

	/* add the cache fields */
	cache_view = mail_cache_view_open(ctx.cache, ctx.view);
	trans = mail_index_transaction_begin(ctx.view, 0);
	cache_trans = mail_cache_get_transaction(cache_view, trans);

	const uint8_t fixed_data[] = { 0x12, 0x34, 0x56, 0x78 };
	mail_cache_add(cache_trans, 1, cache_fields[TEST_FIELD_FIXED].idx,
		       fixed_data, sizeof(fixed_data));
	const uint8_t variable_data[] = { 0xab, 0xcd, 0xef };
	mail_cache_add(cache_trans, 1, cache_fields[TEST_FIELD_VARIABLE].idx,
		       variable_data, sizeof(variable_data));
	const char string_data[] = { 's', 't', 'r' };
	mail_cache_add(cache_trans, 1, cache_fields[TEST_FIELD_STRING].idx,
		       string_data, sizeof(string_data));
	uint8_t bitmask_data[] = { 0x00, 0x01, 0x10, 0x11 };
	mail_cache_add(cache_trans, 1, cache_fields[TEST_FIELD_BITMASK].idx,
		       bitmask_data, sizeof(bitmask_data));
	struct test_header_data header_data1 = {
		.line1 = 15,
		.line2 = 30,
		.headers = "foo\nbar\n",
	};
	struct test_header_data header_data2 = {
		.line1 = 10,
		.line2 = 20,
		.headers = "123\n456\n",
	};
	mail_cache_add(cache_trans, 1, cache_fields[TEST_FIELD_HEADER1].idx,
		       &header_data1, sizeof(header_data1));
	mail_cache_add(cache_trans, 1, cache_fields[TEST_FIELD_HEADER2].idx,
		       &header_data2, sizeof(header_data2));

	/* make sure the fields can be looked up even though they're
	   not committed */
	for (int i = 0;; i++) {
		str_truncate(str, 0);
		test_assert_idx(mail_cache_lookup_field(cache_view, str, 1,
			cache_fields[TEST_FIELD_FIXED].idx) == 1, i);
		test_assert_idx(str_len(str) == sizeof(fixed_data) &&
			memcmp(str_data(str), fixed_data, str_len(str)) == 0, i);
		str_truncate(str, 0);
		test_assert_idx(mail_cache_lookup_field(cache_view, str, 1,
			cache_fields[TEST_FIELD_VARIABLE].idx) == 1, i);
		test_assert_idx(str_len(str) == sizeof(variable_data) &&
			memcmp(str_data(str), variable_data, str_len(str)) == 0, i);
		str_truncate(str, 0);
		test_assert_idx(mail_cache_lookup_field(cache_view, str, 1,
			cache_fields[TEST_FIELD_STRING].idx) == 1, i);
		test_assert_idx(str_len(str) == sizeof(string_data) &&
			memcmp(str_data(str), string_data, str_len(str)) == 0, i);
		str_truncate(str, 0);
		test_assert_idx(mail_cache_lookup_field(cache_view, str, 1,
			cache_fields[TEST_FIELD_BITMASK].idx) == 1, i);
		test_assert_idx(str_len(str) == sizeof(bitmask_data) &&
			memcmp(str_data(str), bitmask_data, str_len(str)) == 0, i);
		const unsigned int lookup_header_fields[] = {
			cache_fields[TEST_FIELD_HEADER2].idx,
			cache_fields[TEST_FIELD_HEADER1].idx,
		};
		str_truncate(str, 0);
		test_assert_idx(mail_cache_lookup_headers(cache_view, str, 1,
			lookup_header_fields,
			N_ELEMENTS(lookup_header_fields)) == 1, i);
		test_assert_strcmp(str_c(str), "123\nfoo\n456\nbar\n");

		if (trans == NULL)
			break;

		/* add more bitmask data within the same transaction */
		uint8_t bitmask_add[4] = { 0x20, 0x20, 0x20, 0x20 };
		for (unsigned int j = 0; j < sizeof(bitmask_data); j++)
			bitmask_data[j] |= bitmask_add[j];
		mail_cache_add(cache_trans, 1, cache_fields[TEST_FIELD_BITMASK].idx,
			       bitmask_add, sizeof(bitmask_add));
		/* check that we can still read it */
		str_truncate(str, 0);
		test_assert_idx(mail_cache_lookup_field(cache_view, str, 1,
			cache_fields[TEST_FIELD_BITMASK].idx) == 1, i);
		test_assert_idx(str_len(str) == sizeof(bitmask_data) &&
			memcmp(str_data(str), bitmask_data, str_len(str)) == 0, i);

		/* commit the transaction and lookup the fields again */
		test_assert(mail_index_transaction_commit(&trans) == 0);
	}

	/* add more bitmask data in separate transactions */
	for (unsigned int i = 0; i < 4; i++) {
		uint8_t bitmask_add[4] = { 0, 0, 0, 0 };
		bitmask_add[i] = 0x40;
		bitmask_data[i] |= 0x40;

		trans = mail_index_transaction_begin(ctx.view, 0);
		cache_trans = mail_cache_get_transaction(cache_view, trans);
		mail_cache_add(cache_trans, 1, cache_fields[TEST_FIELD_BITMASK].idx,
			       bitmask_add, sizeof(bitmask_add));
		test_assert(mail_index_transaction_commit(&trans) == 0);
	}

	/* verify that bitmask is still as expected */
	str_truncate(str, 0);
	test_assert(mail_cache_lookup_field(cache_view, str, 1,
		cache_fields[TEST_FIELD_BITMASK].idx) == 1);
	test_assert(str_len(str) == sizeof(bitmask_data) &&
		    memcmp(str_data(str), bitmask_data, str_len(str)) == 0);

	/* verify that bitmask is still as expected after purging */
	test_assert(mail_cache_purge(ctx.cache, (uint32_t)-1, "test") == 0);
	test_mail_cache_view_sync(&ctx);

	str_truncate(str, 0);
	test_assert(mail_cache_lookup_field(cache_view, str, 1,
		cache_fields[TEST_FIELD_BITMASK].idx) == 1);
	test_assert(str_len(str) == sizeof(bitmask_data) &&
		    memcmp(str_data(str), bitmask_data, str_len(str)) == 0);

	test_assert(test_mail_cache_get_purge_count(&ctx) == 1);
	mail_cache_view_close(&cache_view);
	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
	test_end();
}

static void test_mail_cache_record_max_size_int(unsigned int field3_size)
{
	const struct mail_index_optimization_settings optimization_set = {
		.cache = {
			/* lets assume we can write 2 cache fields,
			   each containing 8 bytes */
			.record_max_size = sizeof(struct mail_cache_record) +
				2 * (sizeof(uint32_t) + /* field_idx */
				     sizeof(uint32_t) + /* data_size */
				     8), /* content max length */
		},
	};
	struct test_mail_cache_ctx ctx;
	struct mail_index_transaction *trans;
	struct mail_cache_view *cache_view;
	struct mail_cache_transaction_ctx *cache_trans;
	string_t *str = t_str_new(16);

	test_mail_cache_init(test_mail_index_init(), &ctx);
	mail_index_set_optimization_settings(ctx.index, &optimization_set);

	/* Add the first cache field. In a chain of cache records each one
	   has independent max size. Although this isn't really ideal, because
	   purging merges them and drops the records entirely if the combined
	   length is too large. But for now test least test what is
	   implemented. */
	test_mail_cache_add_mail(&ctx, ctx.cache_field.idx, "12345678");

	/* add the other field(s) */
	cache_view = mail_cache_view_open(ctx.cache, ctx.view);
	trans = mail_index_transaction_begin(ctx.view, 0);
	cache_trans = mail_cache_get_transaction(cache_view, trans);
	mail_cache_add(cache_trans, 1, ctx.cache_field2.idx, "abcdefgh", 8);
	if (field3_size > 0)
		mail_cache_add(cache_trans, 1, ctx.cache_field3.idx, "ijklmnopq", field3_size);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_cache_view_close(&cache_view);

	/* make sure all the fields are visible */
	test_mail_cache_view_sync(&ctx);

	cache_view = mail_cache_view_open(ctx.cache, ctx.view);
	test_assert(mail_cache_lookup_field(cache_view, str, 1,
					    ctx.cache_field.idx) == 1);
	test_assert(mail_cache_lookup_field(cache_view, str, 1,
					    ctx.cache_field2.idx) == 1);
	if (field3_size == 8) {
		test_assert(mail_cache_lookup_field(cache_view, str, 1,
						    ctx.cache_field3.idx) == 1);
		test_assert_strcmp(str_c(str), "12345678abcdefghijklmnop");
	} else {
		test_assert_strcmp(str_c(str), "12345678abcdefgh");
	}
	mail_cache_view_close(&cache_view);
	test_assert(test_mail_cache_get_purge_count(&ctx) == 0);

	/* if there are 3 fields, purging realizes that the record is too
	   large and drops it */
	test_assert(mail_cache_purge(ctx.cache, (uint32_t)-1, "test") == 0);
	test_assert(mail_cache_reopen(ctx.cache) == 1);

	cache_view = mail_cache_view_open(ctx.cache, ctx.view);
	if (field3_size == 8) {
		/* test that none of the fields are in cache */
		test_assert(mail_cache_lookup_field(cache_view, str, 1,
						    ctx.cache_field.idx) == 0);
		test_assert(mail_cache_lookup_field(cache_view, str, 1,
						    ctx.cache_field2.idx) == 0);
		test_assert(mail_cache_lookup_field(cache_view, str, 1,
						    ctx.cache_field3.idx) == 0);
	} else {
		str_truncate(str, 0);
		test_assert(mail_cache_lookup_field(cache_view, str, 1,
						    ctx.cache_field.idx) == 1);
		test_assert(mail_cache_lookup_field(cache_view, str, 1,
						    ctx.cache_field2.idx) == 1);
		test_assert_strcmp(str_c(str), "12345678abcdefgh");
	}
	mail_cache_view_close(&cache_view);
	test_assert(test_mail_cache_get_purge_count(&ctx) == 1);

	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
}

static void test_mail_cache_record_max_size(void)
{
	test_begin("mail cache record max size");
	test_mail_cache_record_max_size_int(0);
	test_end();
}

static void test_mail_cache_record_max_size2(void)
{
	test_begin("mail cache record max size (2)");
	test_mail_cache_record_max_size_int(8);
	test_end();
}

static void test_mail_cache_record_max_size3(void)
{
	test_begin("mail cache record max size (3)");
	test_mail_cache_record_max_size_int(9);
	test_end();
}

static void test_mail_cache_record_max_size4(void)
{
	const struct mail_index_optimization_settings optimization_set = {
		.cache = {
			.record_max_size = sizeof(struct mail_cache_record) +
				sizeof(uint32_t) + /* field_idx */
				sizeof(uint32_t) + /* data_size */
				8, /* content max length */
		},
	};
	struct test_mail_cache_ctx ctx;
	struct mail_index_transaction *trans;
	struct mail_cache_view *cache_view;
	struct mail_cache_transaction_ctx *cache_trans;
	string_t *str = t_str_new(16);

	test_begin("mail cache record max size (4)");
	test_mail_cache_init(test_mail_index_init(), &ctx);
	mail_index_set_optimization_settings(ctx.index, &optimization_set);

	test_mail_cache_add_mail(&ctx, UINT_MAX, NULL);
	test_mail_cache_add_mail(&ctx, UINT_MAX, NULL);

	cache_view = mail_cache_view_open(ctx.cache, ctx.view);
	trans = mail_index_transaction_begin(ctx.view, 0);
	cache_trans = mail_cache_get_transaction(cache_view, trans);
	mail_cache_add(cache_trans, 1, ctx.cache_field.idx, "123456789", 9);
	mail_cache_add(cache_trans, 2, ctx.cache_field.idx, "123456789", 9);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_cache_view_close(&cache_view);

	/* make sure none of the fields are visible */
	test_mail_cache_view_sync(&ctx);

	cache_view = mail_cache_view_open(ctx.cache, ctx.view);
	test_assert(mail_cache_lookup_field(cache_view, str, 1,
					    ctx.cache_field.idx) == 0);
	test_assert(mail_cache_lookup_field(cache_view, str, 2,
					    ctx.cache_field.idx) == 0);
	mail_cache_view_close(&cache_view);
	test_assert(ctx.cache->hdr == NULL); /* never created */

	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
	test_end();
}

static void test_mail_cache_add_decisions(void)
{
	struct mail_cache_field cache_fields[TEST_FIELD_COUNT];
	enum mail_cache_decision_type expected_decisions[TEST_FIELD_COUNT];
	struct test_mail_cache_ctx ctx;
	struct mail_index_transaction *trans;
	struct mail_cache_view *cache_view;
	struct mail_cache_transaction_ctx *cache_trans;
	unsigned int i;

	test_begin("mail cache add decisions");

	test_mail_cache_init(test_mail_index_init(), &ctx);
	memcpy(cache_fields, decision_cache_fields, sizeof(cache_fields));
	mail_cache_register_fields(ctx.cache, cache_fields, TEST_FIELD_COUNT);
	for (i = 0; i < TEST_FIELD_COUNT; i++)
		expected_decisions[i] = cache_fields[i].decision;

	/* create the initial cache file */
	test_mail_cache_add_mail(&ctx, UINT_MAX, NULL);
	test_mail_cache_add_mail(&ctx, UINT_MAX, NULL);
	test_assert(mail_cache_purge(ctx.cache, (uint32_t)-1, "test") == 0);

	/* purging changes YES -> TEMP */
	expected_decisions[TEST_FIELD_YES] = MAIL_CACHE_DECISION_TEMP;
	for (i = 0; i < TEST_FIELD_COUNT; i++)
		test_assert_idx(ctx.cache->fields[cache_fields[i].idx].field.decision == expected_decisions[i], i);
	/* but change it back */
	ctx.cache->fields[cache_fields[TEST_FIELD_YES].idx].field.decision =
		MAIL_CACHE_DECISION_YES;
	ctx.cache->fields[cache_fields[TEST_FIELD_YES].idx].decision_dirty = TRUE;
	expected_decisions[TEST_FIELD_YES] = MAIL_CACHE_DECISION_YES;

	cache_view = mail_cache_view_open(ctx.cache, ctx.view);
	trans = mail_index_transaction_begin(ctx.view, 0);
	cache_trans = mail_cache_get_transaction(cache_view, trans);

	/* test that when cache decisions are disabled, it doesn't affect the
	   NO state change */
	mail_cache_view_update_cache_decisions(cache_view, FALSE);
	mail_cache_add(cache_trans, 2, cache_fields[TEST_FIELD_NO].idx, "bar", 3);
	mail_cache_view_update_cache_decisions(cache_view, TRUE);
	test_assert(ctx.cache->fields[cache_fields[TEST_FIELD_NO].idx].field.decision == MAIL_CACHE_DECISION_NO);

	/* add a cache field of each type */
	for (i = 0; i < TEST_FIELD_COUNT; i++)
		mail_cache_add(cache_trans, 1, cache_fields[i].idx, "foo", 3);
	/* quick check before commit that the state is as expected */
	test_assert(ctx.cache->fields[cache_fields[TEST_FIELD_NO].idx].field.decision == MAIL_CACHE_DECISION_TEMP);
	test_assert(ctx.cache->fields[cache_fields[TEST_FIELD_NO].idx].decision_dirty);
	test_assert(ctx.cache->fields[cache_fields[TEST_FIELD_NO].idx].uid_highwater == 1);

	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_cache_view_close(&cache_view);

	/* verify the state: NO state becomes TEMP, others are unchanged */
	expected_decisions[TEST_FIELD_NO] = MAIL_CACHE_DECISION_TEMP;
	test_assert(!ctx.cache->field_header_write_pending);
	for (i = 0; i < TEST_FIELD_COUNT; i++) {
		const struct mail_cache_field_private *priv =
			&ctx.cache->fields[cache_fields[i].idx];
		test_assert_idx(priv->field.decision == expected_decisions[i], i);
		test_assert_idx(!priv->decision_dirty, i);
		/* uid_highwater is updated only for the changed state */
		uint32_t uid_highwater = priv->uid_highwater;
		if (i == TEST_FIELD_NO)
			test_assert_idx(uid_highwater == 1, i);
		else
			test_assert_idx(uid_highwater == 0, i);
	}

	test_assert(test_mail_cache_get_purge_count(&ctx) == 0);
	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
	test_end();
}

static void test_mail_cache_lookup_decisions_int(bool header_lookups)
{
	struct mail_cache_field cache_fields[TEST_FIELD_COUNT];
	enum mail_cache_decision_type expected_decisions[TEST_FIELD_COUNT];
	uint32_t expected_uid_highwater[TEST_FIELD_COUNT];
	time_t expected_last_used[TEST_FIELD_COUNT];
	struct test_mail_cache_ctx ctx;
	struct mail_index_transaction *trans;
	struct mail_cache_view *cache_view;
	unsigned int i;
	string_t *str = t_str_new(16);

	test_mail_cache_init(test_mail_index_init(), &ctx);
	/* create the initial mails and the cache file */
	test_mail_cache_add_mail(&ctx, UINT_MAX, NULL);
	test_mail_cache_add_mail(&ctx, UINT_MAX, NULL);
	test_mail_cache_add_mail(&ctx, UINT_MAX, NULL);
	test_assert(mail_cache_purge(ctx.cache, (uint32_t)-1, "test") == 0);

	/* register fields after the initial purge create the cache */
	memcpy(cache_fields, decision_cache_fields, sizeof(cache_fields));
	mail_cache_register_fields(ctx.cache, cache_fields, TEST_FIELD_COUNT);
	for (i = 0; i < TEST_FIELD_COUNT; i++) {
		expected_decisions[i] = cache_fields[i].decision;
		expected_uid_highwater[i] = 0;
	}

	/* day_first_uid[7] is used to determine which mails are "old" and
	   which mails are "new". [7] is the first "new" mail. */
	test_mail_cache_update_day_first_uid7(&ctx, 2);

	trans = mail_index_transaction_begin(ctx.view, 0);
	cache_view = mail_cache_view_open(ctx.cache, ctx.view);

	/* test that nothing changes when cache decision updates are disabled */
	mail_cache_view_update_cache_decisions(cache_view, FALSE);
	for (i = 0; i < TEST_FIELD_COUNT; i++) T_BEGIN {
		const struct mail_cache_field_private *priv =
			&ctx.cache->fields[cache_fields[i].idx];
		if (!header_lookups) {
			test_assert_idx(mail_cache_lookup_field(cache_view,
				str, 1, cache_fields[i].idx) == 0, i);
		} else {
			/* it's a bit wrong to lookup headers using a STRING
			   type cache field, but this is simpler and at least
			   currently there's no assert for it.. */
			test_assert_idx(mail_cache_lookup_headers(cache_view,
				str, 2, &cache_fields[i].idx, 1) == 0, i);
		}
		test_assert_idx(priv->field.decision == expected_decisions[i], i);
		test_assert_idx(!priv->decision_dirty, i);
		test_assert_idx(priv->uid_highwater == 0, i);
		test_assert_idx(priv->field.last_used == 0, i);
	} T_END;
	test_assert(!ctx.cache->field_header_write_pending);
	mail_cache_view_update_cache_decisions(cache_view, TRUE);

	/* set cache fields for the first "new" mail (seq/UID 2) */
	ioloop_time = 123456789;
	for (i = 0; i < TEST_FIELD_COUNT; i++) T_BEGIN {
		const struct mail_cache_field_private *priv =
			&ctx.cache->fields[cache_fields[i].idx];

		ioloop_time++;
		if (!header_lookups) {
			test_assert_idx(mail_cache_lookup_field(cache_view,
				str, 2, cache_fields[i].idx) == 0, i);
		} else {
			test_assert_idx(mail_cache_lookup_headers(cache_view,
				str, 2, &cache_fields[i].idx, 1) == 0, i);
		}
		expected_last_used[i] = ioloop_time;
		switch (i) {
		case TEST_FIELD_NO_FORCED:
			expected_last_used[i] = 0;
			/* fall through */
		case TEST_FIELD_NO:
			/* Note that just doing a cache lookup won't change
			   caching decision. Higher level code needs to figure
			   out itself if it wants the field to become cached.
			   This happens only by calling mail_cache_add(). */
			break;
		case TEST_FIELD_TEMP:
			/* Note that uid_highwater isn't permanently saved to
			   the cache file. It's used only within a single
			   session. */
			expected_uid_highwater[i] = 2;
			break;
		}
		test_assert_idx(priv->field.decision == expected_decisions[i], i);
		test_assert_idx(priv->uid_highwater == expected_uid_highwater[i], i);
		test_assert_idx(priv->field.last_used == expected_last_used[i], i);
		test_assert_idx(!priv->decision_dirty, i);
	} T_END;
	test_assert(!ctx.cache->field_header_write_pending);

	test_assert(mail_index_transaction_commit(&trans) == 0);

	/* test that after commit and reopening the decisions are still the
	   same. */
	test_assert(mail_cache_reopen(ctx.cache) == 1);
	for (i = 0; i < TEST_FIELD_COUNT; i++) {
		const struct mail_cache_field_private *priv =
			&ctx.cache->fields[cache_fields[i].idx];
		test_assert_idx(priv->field.decision == expected_decisions[i], i);
		test_assert_idx(priv->uid_highwater == expected_uid_highwater[i], i);
		test_assert_idx(priv->field.last_used == expected_last_used[i], i);
		test_assert_idx(!priv->decision_dirty, i);
	}

	/* update the day_first_uid so all mails are now "old" */
	test_mail_cache_update_day_first_uid7(&ctx, 4);

	for (uint32_t seq = 2; seq >= 1; seq--) {
		/* Reading a 3rd mail, which is also now "old". It causes
		   TEMP -> YES cache decision (don't read backwards yet,
		   that's a separate test). */
		expected_decisions[TEST_FIELD_TEMP] = MAIL_CACHE_DECISION_YES;
		for (i = 0; i < TEST_FIELD_COUNT; i++) T_BEGIN {
			const struct mail_cache_field_private *priv =
				&ctx.cache->fields[cache_fields[i].idx];

			/* Keep increasing ioloop_time just to make sure that
			   last_used doesn't change. (It changes only once per
			   24h) */
			ioloop_time++;
			if (!header_lookups) {
				test_assert_idx(mail_cache_lookup_field(
					cache_view, str, seq,
					cache_fields[i].idx) == 0, i);
			} else {
				test_assert_idx(mail_cache_lookup_headers(
					cache_view, str, seq,
					&cache_fields[i].idx, 1) == 0, i);
			}
			test_assert_idx(priv->field.decision == expected_decisions[i], i);
			test_assert_idx(priv->uid_highwater == expected_uid_highwater[i], i);
			test_assert_idx(priv->field.last_used == expected_last_used[i], i);
			test_assert_idx(priv->decision_dirty == (i == TEST_FIELD_TEMP), i);
		} T_END;
		/* restore caching decision */
		ctx.cache->fields[cache_fields[TEST_FIELD_TEMP].idx].field.decision =
			MAIL_CACHE_DECISION_TEMP;
		/* reading mails backwards also causes TEMP -> YES cache
		   decision, even if all mails are "new" */
		test_mail_cache_update_day_first_uid7(&ctx, 1);
	}

	test_assert(test_mail_cache_get_purge_count(&ctx) == 0);
	mail_cache_view_close(&cache_view);
	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
}

static void test_mail_cache_lookup_decisions(void)
{
	test_begin("mail cache lookup decisions");
	test_mail_cache_lookup_decisions_int(FALSE);
	test_end();
}

static void test_mail_cache_lookup_decisions2(void)
{
	test_begin("mail cache lookup decisions (2)");
	test_mail_cache_lookup_decisions_int(TRUE);
	test_end();
}

static void test_mail_cache_in_memory(void)
{
	const struct mail_index_optimization_settings optimization_set = {
		.cache = {
			.record_max_size = MAIL_CACHE_MAX_WRITE_BUFFER*2,
		},
	};
	struct test_mail_cache_ctx ctx;
	struct mail_index *index;
	struct mail_index_transaction *trans;
	struct mail_cache_view *cache_view;
	struct mail_cache_transaction_ctx *cache_trans;

	test_begin("mail cache add in-memory");

	index = mail_index_alloc(NULL, NULL, "(in-memory)");
	test_assert(mail_index_open_or_create(index, MAIL_INDEX_OPEN_FLAG_CREATE) == 0);
	test_mail_cache_init(index, &ctx);
	mail_index_set_optimization_settings(ctx.index, &optimization_set);
	cache_view = mail_cache_view_open(ctx.cache, ctx.view);

	test_mail_cache_add_mail(&ctx, UINT_MAX, NULL);
	test_mail_cache_add_mail(&ctx, UINT_MAX, NULL);

	trans = mail_index_transaction_begin(ctx.view, 0);
	cache_trans = mail_cache_get_transaction(cache_view, trans);

	size_t blob_size = 1024*130;
	char *blob = i_malloc(blob_size);
	memset(blob, 'x', blob_size);
	mail_cache_add(cache_trans, 1, ctx.cache_field.idx, blob, blob_size);
	mail_cache_add(cache_trans, 1, ctx.cache_field2.idx, "foo1", 4);
	mail_cache_add(cache_trans, 2, ctx.cache_field2.idx, "foo2", 4);

	/* all fields are still available */
	string_t *str = str_new(default_pool, blob_size + 1024);
	test_assert(mail_cache_lookup_field(cache_view, str, 1,
					    ctx.cache_field.idx) == 1);
	test_assert(str_len(str) == blob_size);
	str_truncate(str, 0);
	test_assert(mail_cache_lookup_field(cache_view, str, 1,
					    ctx.cache_field2.idx) == 1);
	test_assert_strcmp(str_c(str), "foo1");
	str_truncate(str, 0);
	test_assert(mail_cache_lookup_field(cache_view, str, 2,
					    ctx.cache_field2.idx) == 1);
	test_assert_strcmp(str_c(str), "foo2");

	/* adding a second blob grows memory usage beyond
	   MAIL_CACHE_MAX_WRITE_BUFFER and frees the first cached mail
	   entirely (although in theory it could drop just the big blob) */
	mail_cache_add(cache_trans, 2, ctx.cache_field.idx, blob, blob_size);
	test_assert(mail_cache_lookup_field(cache_view, str, 1,
					    ctx.cache_field.idx) == 0);
	test_assert(mail_cache_lookup_field(cache_view, str, 1,
					    ctx.cache_field2.idx) == 0);
	str_truncate(str, 0);
	test_assert(mail_cache_lookup_field(cache_view, str, 2,
					    ctx.cache_field.idx) == 1);
	test_assert(str_len(str) == blob_size);
	str_truncate(str, 0);
	test_assert(mail_cache_lookup_field(cache_view, str, 2,
					    ctx.cache_field2.idx) == 1);
	test_assert_strcmp(str_c(str), "foo2");

	test_assert(mail_index_transaction_commit(&trans) == 0);

	str_free(&str);
	i_free(blob);

	mail_cache_view_close(&cache_view);
	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_cache_fields,
		test_mail_cache_record_max_size,
		test_mail_cache_record_max_size2,
		test_mail_cache_record_max_size3,
		test_mail_cache_record_max_size4,
		test_mail_cache_add_decisions,
		test_mail_cache_lookup_decisions,
		test_mail_cache_lookup_decisions2,
		test_mail_cache_in_memory,
		NULL
	};
	return test_run(test_functions);
}
