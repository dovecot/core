/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "array.h"
#include "test-common.h"
#include "test-mail-cache.h"

#include <stdio.h>
#include <sys/wait.h>

static void test_mail_cache_read_during_purge2(void)
{
	struct test_mail_cache_ctx ctx;
	struct mail_cache_view *cache_view;
	string_t *str = t_str_new(16);

	i_set_failure_prefix("index2: ");

	/* read from cache via 2nd index */
	test_mail_cache_init(test_mail_index_open(), &ctx);

	cache_view = mail_cache_view_open(ctx.cache, ctx.view);
	test_assert(mail_cache_lookup_field(cache_view, str, 1,
					    ctx.cache_field.idx) == 1);
	test_assert(strcmp(str_c(str), "foo1") == 0);
	mail_cache_view_close(&cache_view);

	test_mail_cache_deinit(&ctx);
}

static void test_mail_cache_read_during_purge(void)
{
	struct test_mail_cache_ctx ctx;
	struct mail_index_transaction *trans;
	int status;

	test_begin("mail cache read during purge");
	test_mail_cache_init(test_mail_index_init(), &ctx);
	test_mail_cache_add_mail(&ctx, ctx.cache_field.idx, "foo1");

	/* lock the index for cache purge */
	uint32_t log_seq;
	uoff_t log_offset;
	test_assert(mail_transaction_log_sync_lock(ctx.index->log, "purge", &log_seq, &log_offset) == 0);

	/* start purging cache using the 1st index, but don't commit yet */
	trans = mail_index_transaction_begin(ctx.view, 0);
	test_assert(mail_cache_purge_with_trans(ctx.cache, trans, (uint32_t)-1, "test") == 0);

	switch (fork()) {
	case (pid_t)-1:
		i_fatal("fork() failed: %m");
	case 0:
		test_mail_cache_read_during_purge2();
		/* cleanup so valgrind doesn't complain about memory leaks */
		mail_index_transaction_rollback(&trans);
		mail_transaction_log_sync_unlock(ctx.index->log, "purge");
		test_mail_cache_deinit(&ctx);
		test_exit(test_has_failed() ? 10 : 0);
	default:
		break;
	}

	/* Wait a bit to make sure the child function has had a chance to run.
	   It's supposed to be waiting on the locked .log file. */
	usleep(100000);
	/* finish cache purging */
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_transaction_log_sync_unlock(ctx.index->log, "purge");
	mail_index_view_close(&ctx.view);

	/* wait for child to finish execution */
	if (wait(&status) == -1)
		i_error("wait() failed: %m");
	test_assert(status == 0);

	test_assert(test_mail_cache_get_purge_count(&ctx) == 1);
	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
	test_end();
}

static void test_mail_cache_write_during_purge2(void)
{
	struct test_mail_cache_ctx ctx;

	i_set_failure_prefix("index2: ");

	/* add to cache via 2nd index */
	test_mail_cache_init(test_mail_index_open(), &ctx);
	test_mail_cache_add_field(&ctx, 1, ctx.cache_field2.idx, "bar2");
	test_mail_cache_deinit(&ctx);
}

static void test_mail_cache_write_during_purge(void)
{
	struct test_mail_cache_ctx ctx;
	struct mail_index_view *view;
	struct mail_cache_view *cache_view;
	struct mail_index_transaction *trans;
	string_t *str = t_str_new(16);
	int status;

	test_begin("mail cache write during purge");
	test_mail_cache_init(test_mail_index_init(), &ctx);
	test_mail_cache_add_mail(&ctx, ctx.cache_field.idx, "foo1");

	/* lock the index for cache purge */
	uint32_t log_seq;
	uoff_t log_offset;
	test_assert(mail_transaction_log_sync_lock(ctx.index->log, "purge", &log_seq, &log_offset) == 0);

	/* start purging cache using the 1st index, but don't commit yet */
	trans = mail_index_transaction_begin(ctx.view, 0);
	test_assert(mail_cache_purge_with_trans(ctx.cache, trans, (uint32_t)-1, "test") == 0);

	switch (fork()) {
	case (pid_t)-1:
		i_fatal("fork() failed: %m");
	case 0:
		test_mail_cache_write_during_purge2();
		/* cleanup so valgrind doesn't complain about memory leaks */
		mail_index_transaction_rollback(&trans);
		mail_transaction_log_sync_unlock(ctx.index->log, "purge");
		test_mail_cache_deinit(&ctx);
		test_exit(test_has_failed() ? 10 : 0);
	default:
		break;
	}

	/* Wait a bit to make sure the child function has had a chance to run.
	   It's supposed to be waiting on the locked .log file. */
	usleep(100000);
	/* finish cache purge */
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_transaction_log_sync_unlock(ctx.index->log, "purge");
	mail_index_view_close(&ctx.view);

	/* wait for child to finish execution */
	if (wait(&status) == -1)
		i_error("wait() failed: %m");
	test_assert(status == 0);

	/* make sure both cache fields are visible */
	test_assert(mail_index_refresh(ctx.index) == 0);

	view = mail_index_view_open(ctx.index);
	cache_view = mail_cache_view_open(ctx.cache, view);
	test_assert(mail_cache_lookup_field(cache_view, str, 1,
					    ctx.cache_field.idx) == 1);
	test_assert(strcmp(str_c(str), "foo1") == 0);
	str_truncate(str, 0);
	test_assert(mail_cache_lookup_field(cache_view, str, 1,
					    ctx.cache_field2.idx) == 1);
	test_assert(strcmp(str_c(str), "bar2") == 0);
	mail_cache_view_close(&cache_view);
	mail_index_view_close(&view);

	test_assert(test_mail_cache_get_purge_count(&ctx) == 1);
	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
	test_end();
}

static void test_mail_cache_purge_while_cache_locked(void)
{
	struct test_mail_cache_ctx ctx;
	struct mail_cache_view *cache_view;
	string_t *str = t_str_new(16);
	int status;

	test_begin("mail cache purge while cache locked");
	test_mail_cache_init(test_mail_index_init(), &ctx);
	test_mail_cache_add_mail(&ctx, ctx.cache_field.idx, "foo1");

	/* lock the cache */
	test_assert(mail_cache_lock(ctx.cache) == 1);

	/* purge the cache in another process */
	switch (fork()) {
	case (pid_t)-1:
		i_fatal("fork() failed: %m");
	case 0:
		test_mail_cache_purge();
		test_mail_cache_deinit(&ctx);
		test_exit(test_has_failed() ? 10 : 0);
	default:
		break;
	}

	/* Wait a bit to make sure the child function has had a chance to run.
	   It should start purging, which would wait for our cache lock. */
	usleep(100000);

	mail_cache_unlock(ctx.cache);

	/* wait for child to finish execution */
	if (wait(&status) == -1)
		i_error("wait() failed: %m");
	test_assert(status == 0);

	/* make sure the cache is still usable */
	test_assert(mail_index_refresh(ctx.index) == 0);
	test_mail_cache_view_sync(&ctx);

	cache_view = mail_cache_view_open(ctx.cache, ctx.view);
	test_assert(mail_cache_lookup_field(cache_view, str, 1,
					    ctx.cache_field.idx) == 1);
	test_assert(strcmp(str_c(str), "foo1") == 0);
	mail_cache_view_close(&cache_view);

	test_assert(test_mail_cache_get_purge_count(&ctx) == 1);
	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
	test_end();
}

static bool cache_equals(struct mail_cache_view *cache_view, uint32_t seq,
			 unsigned int field_idx, const char *value)
{
	string_t *str = str_new(default_pool, 128);
	int ret = mail_cache_lookup_field(cache_view, str, seq, field_idx);
	bool match;

	if (value != NULL) {
		test_assert_idx(ret == 1, seq);
		match = strcmp(str_c(str), value) == 0;
		test_assert_idx(match, seq);
	} else {
		test_assert_idx(ret == 0, seq);
		match = ret == 0;
	}
	str_free(&str);
	return match;
}

static void test_mail_cache_write_lost_during_purge_n(unsigned int num_mails)
{
	const struct mail_index_optimization_settings optimization_set = {
		.cache = {
			.record_max_size = 1024*1024,
		},
	};
	struct test_mail_cache_ctx ctx;
	struct mail_index_view *updated_view;
	struct mail_cache_view *cache_view;
	struct mail_cache_transaction_ctx *cache_trans;
	struct mail_index_transaction *trans;
	uint32_t seq;

	test_mail_cache_init(test_mail_index_init(), &ctx);
	mail_index_set_optimization_settings(ctx.index, &optimization_set);

	/* Add mails */
	test_mail_cache_add_mail(&ctx, UINT_MAX, "");
	trans = mail_index_transaction_begin(ctx.view, 0);
	for (seq = 2; seq <= num_mails; seq++)
		mail_index_append(trans, seq, &seq);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	test_mail_cache_view_sync(&ctx);

	/* start adding a small cached field to mail1 */
	trans = mail_index_transaction_begin(ctx.view, 0);
	updated_view = mail_index_transaction_open_updated_view(trans);
	cache_view = mail_cache_view_open(ctx.cache, updated_view);
	cache_trans = mail_cache_get_transaction(cache_view, trans);
	mail_cache_add(cache_trans, 1, ctx.cache_field.idx, "foo1", 4);

	/* add a huge field to mail2, which triggers flushing */
	size_t huge_field_size = MAIL_CACHE_MAX_WRITE_BUFFER + 1024;
	char *huge_field = i_malloc(huge_field_size + 1);
	memset(huge_field, 'x', huge_field_size);
	mail_cache_add(cache_trans, 2, ctx.cache_field.idx,
		       huge_field, huge_field_size);

	/* verify that cached fields are still accessible */
	test_assert(cache_equals(cache_view, 1, ctx.cache_field.idx, "foo1"));
	test_assert(cache_equals(cache_view, 2, ctx.cache_field.idx, huge_field));

	/* purge using a 2nd index */
	test_mail_cache_purge();

	if (num_mails == 2) {
		/* the mails are still accessible after purge */
		test_assert(cache_equals(cache_view, 1, ctx.cache_field.idx, "foo1"));
		test_assert(cache_equals(cache_view, 2, ctx.cache_field.idx, huge_field));
	} else {
		/* add 3rd mail, which attempts to flush 2nd mail and finds
		   that the first mail is already lost */
		test_expect_error_string("Purging lost 1 written cache records");
		mail_cache_add(cache_trans, 3, ctx.cache_field.idx, "foo3", 4);
		test_expect_no_more_errors();

		test_assert(cache_equals(cache_view, 1, ctx.cache_field.idx, NULL));
		test_assert(cache_equals(cache_view, 2, ctx.cache_field.idx, huge_field));
		test_assert(cache_equals(cache_view, 3, ctx.cache_field.idx, "foo3"));
	}

	/* finish committing cached fields */
	if (num_mails == 2)
		test_expect_error_string("Purging lost 1 written cache records");
	test_assert(mail_index_transaction_commit(&trans) == 0);
	test_expect_no_more_errors();
	mail_index_view_close(&updated_view);
	mail_cache_view_close(&cache_view);

	/* see that we lost the first flush, but not the others */
	test_mail_cache_view_sync(&ctx);
	cache_view = mail_cache_view_open(ctx.cache, ctx.view);
	test_assert(cache_equals(cache_view, 1, ctx.cache_field.idx, NULL));
	test_assert(cache_equals(cache_view, 2, ctx.cache_field.idx, huge_field));
	if (num_mails >= 3)
		test_assert(cache_equals(cache_view, 3, ctx.cache_field.idx, "foo3"));
	mail_cache_view_close(&cache_view);

	mail_index_view_close(&ctx.view);
	test_assert(test_mail_cache_get_purge_count(&ctx) == 1);
	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
	i_free(huge_field);
}

static void test_mail_cache_write_lost_during_purge(void)
{
	test_begin("mail cache write lost during purge");
	test_mail_cache_write_lost_during_purge_n(2);
	test_end();
}

static void test_mail_cache_write_lost_during_purge2(void)
{
	test_begin("mail cache write lost during purge (2)");
	test_mail_cache_write_lost_during_purge_n(3);
	test_end();
}

static size_t max_field_size(size_t max_size, size_t current_size)
{
	return max_size - current_size
		- sizeof(struct mail_cache_record)
		- sizeof(uint32_t) /* field_idx */
		- sizeof(uint32_t); /* data_size */
}

static void test_mail_cache_delete_too_large_int(bool exceed_on_first_write)
{
	const struct mail_index_optimization_settings optimization_set = {
		.cache = {
			.max_size = 1024,
		},
	};
	struct test_mail_cache_ctx ctx;
	struct stat st;

	test_mail_cache_init(test_mail_index_init(), &ctx);
	mail_index_set_optimization_settings(ctx.index, &optimization_set);
	test_mail_cache_add_mail(&ctx, ctx.cache_field.idx, "foo1");
	test_mail_cache_add_mail(&ctx, ctx.cache_field.idx, "foo2");

	test_assert(stat(ctx.index->cache->filepath, &st) == 0);

	/* create cache file that is exactly max_size */
	size_t field_size =
		max_field_size(optimization_set.cache.max_size, st.st_size);
	if (exceed_on_first_write) {
		test_expect_error_string("Cache file too large");
		field_size++;
	}
	char *field = i_malloc(field_size + 1);
	memset(field, 'x', field_size);
	test_mail_cache_add_field(&ctx, 1, ctx.cache_field2.idx, field);
	test_expect_no_more_errors();
	i_free(field);

	if (!exceed_on_first_write) {
		test_assert(stat(ctx.index->cache->filepath, &st) == 0);
		test_assert(st.st_size == 1024);

		/* adding anything more will delete the cache. */
		test_expect_error_string("Cache file too large");
		test_mail_cache_add_field(&ctx, 1, ctx.cache_field2.idx, "bar1");
		test_expect_no_more_errors();
	}
	test_assert(stat(ctx.index->cache->filepath, &st) < 0 && errno == ENOENT);

	mail_index_view_close(&ctx.view);
	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
}

static void test_mail_cache_delete_too_large(void)
{
	test_begin("mail cache delete too large");
	test_mail_cache_delete_too_large_int(FALSE);
	test_end();
}

static void test_mail_cache_delete_too_large2(void)
{
	test_begin("mail cache delete too large (2)");
	test_mail_cache_delete_too_large_int(TRUE);
	test_end();
}

static void test_mail_cache_purge_too_large_int(bool exceed_size)
{
	const struct mail_index_optimization_settings optimization_set = {
		.cache = {
			.max_size = 1024,
		},
	};
	struct mail_index_transaction *trans;
	struct mail_cache_view *cache_view;
	struct test_mail_cache_ctx ctx;
	struct stat st;

	test_mail_cache_init(test_mail_index_init(), &ctx);
	mail_index_set_optimization_settings(ctx.index, &optimization_set);

	/* add two mails with some cache field and expunge the first mail */
	test_mail_cache_add_mail(&ctx, ctx.cache_field.idx, "foo1");
	test_mail_cache_add_mail(&ctx, ctx.cache_field.idx, "bar2");
	trans = mail_index_transaction_begin(ctx.view, 0);
	mail_index_expunge(trans, 1);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	test_mail_cache_index_sync(&ctx);

	/* Add a second mail whose cache field size is exactly the
	   max_size [+1 if exceed_size] */
	test_assert(stat(ctx.index->cache->filepath, &st) == 0);
	size_t field_size = (exceed_size ? 1 : 0) +
		max_field_size(optimization_set.cache.max_size, st.st_size);
	char *field = i_malloc(field_size + 1);
	memset(field, 'x', field_size);
	test_mail_cache_add_mail(&ctx, ctx.cache_field.idx, field);

	test_assert(stat(ctx.index->cache->filepath, &st) == 0);
	if (exceed_size)
		test_assert((uoff_t)st.st_size < optimization_set.cache.max_size);
	else
		test_assert((uoff_t)st.st_size == optimization_set.cache.max_size);

	/* make sure we still find the cache fields */
	test_mail_cache_view_sync(&ctx);
	cache_view = mail_cache_view_open(ctx.cache, ctx.view);
	test_assert(cache_equals(cache_view, 1, ctx.cache_field.idx, "bar2"));
	test_assert(cache_equals(cache_view, 2, ctx.cache_field.idx, field));
	mail_cache_view_close(&cache_view);

	i_free(field);
	if (exceed_size)
		test_assert(test_mail_cache_get_purge_count(&ctx) == 1);
	else
		test_assert(test_mail_cache_get_purge_count(&ctx) == 0);
	mail_index_view_close(&ctx.view);
	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
}

static void test_mail_cache_purge_too_large(void)
{
	test_begin("mail cache purge too large");
	test_mail_cache_purge_too_large_int(FALSE);
	test_end();
}

static void test_mail_cache_purge_too_large2(void)
{
	test_begin("mail cache purge too large (2)");
	test_mail_cache_purge_too_large_int(TRUE);
	test_end();
}

static void test_mail_cache_unexpectedly_lost_int(bool read_first)
{
	struct test_mail_cache_ctx ctx;
	struct mail_cache_view *cache_view;

	test_mail_cache_init(test_mail_index_init(), &ctx);
	test_mail_cache_add_mail(&ctx, ctx.cache_field.idx, "foo1");

	test_mail_cache_purge();

	/* Unexpectedly delete the cache file under us */
	i_unlink(ctx.cache->filepath);

	if (read_first) {
		/* the cache file is already open, so initial reading should
		   work without errors */
		cache_view = mail_cache_view_open(ctx.cache, ctx.view);
		test_assert(cache_equals(cache_view, 1, ctx.cache_field.idx, "foo1"));
		mail_cache_view_close(&cache_view);

		/* if we refresh the index we get new reset_id, which requires
		   reopening the cache and that fails */
		test_assert(mail_index_refresh(ctx.index) == 0);
		test_mail_cache_view_sync(&ctx);
		cache_view = mail_cache_view_open(ctx.cache, ctx.view);
		test_expect_error_string("test.dovecot.index.cache: No such file or directory");
		test_assert(cache_equals(cache_view, 1, ctx.cache_field.idx, NULL));
		test_expect_no_more_errors();
		mail_cache_view_close(&cache_view);
	} else {
		test_expect_error_string("test.dovecot.index.cache: No such file or directory");
	}

	/* writing after losing the cache should still work */
	test_mail_cache_add_field(&ctx, 1, ctx.cache_field2.idx, "bar1");
	test_expect_no_more_errors();

	/* verify that the second cache field is found, but first is lost */
	cache_view = mail_cache_view_open(ctx.cache, ctx.view);
	test_assert(cache_equals(cache_view, 1, ctx.cache_field.idx, NULL));
	test_assert(cache_equals(cache_view, 1, ctx.cache_field2.idx, "bar1"));
	mail_cache_view_close(&cache_view);

	test_assert(test_mail_cache_get_purge_count(&ctx) == 2);
	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
}

static void test_mail_cache_unexpectedly_lost(void)
{
	test_begin("mail cache unexpectedly lost");
	test_mail_cache_unexpectedly_lost_int(FALSE);
	test_end();
}

static void test_mail_cache_unexpectedly_lost2(void)
{
	test_begin("mail cache unexpectedly lost (2)");
	test_mail_cache_unexpectedly_lost_int(TRUE);
	test_end();
}

static void test_mail_cache_resetid_mismatch_int(bool read_first)
{
	struct test_mail_cache_ctx ctx;
	struct mail_cache_view *cache_view;
	const char *temp_cache_path;

	test_mail_cache_init(test_mail_index_init(), &ctx);
	test_mail_cache_add_mail(&ctx, ctx.cache_field.idx, "foo1");

	/* make a copy of the first cache file */
	temp_cache_path = t_strdup_printf("%s.test", ctx.cache->filepath);
	test_assert(link(ctx.cache->filepath, temp_cache_path) == 0);

	if (read_first) {
		/* use a secondary index to purge the cache */
		test_mail_cache_purge();

		/* Replace the new cache file with an old one */
		test_assert(rename(temp_cache_path, ctx.cache->filepath) == 0);

		/* the cache file is already open, so initial reading should
		   work without errors */
		cache_view = mail_cache_view_open(ctx.cache, ctx.view);
		test_assert(cache_equals(cache_view, 1, ctx.cache_field.idx, "foo1"));
		mail_cache_view_close(&cache_view);

		/* if we refresh the index we get new reset_id, which requires
		   reopening the cache and that fails */
		test_assert(mail_index_refresh(ctx.index) == 0);
		test_mail_cache_view_sync(&ctx);
		cache_view = mail_cache_view_open(ctx.cache, ctx.view);

		test_expect_error_string("reset_id mismatch even after locking");
		test_assert(cache_equals(cache_view, 1, ctx.cache_field.idx, NULL));
		test_expect_no_more_errors();
		mail_cache_view_close(&cache_view);
	} else {
		/* purge cache to update reset_id in index */
		test_assert(mail_cache_purge(ctx.cache, (uint32_t)-1, "test") == 0);

		/* Replace the new cache file with an old one */
		test_assert(rename(temp_cache_path, ctx.cache->filepath) == 0);

		test_expect_error_string("reset_id mismatch even after locking");
	}

	/* writing should automatically fix the reset_id mismatch */
	test_mail_cache_add_field(&ctx, 1, ctx.cache_field2.idx, "bar1");
	test_expect_no_more_errors();

	/* verify that the second cache field is found, but first is lost */
	cache_view = mail_cache_view_open(ctx.cache, ctx.view);
	test_assert(cache_equals(cache_view, 1, ctx.cache_field.idx, NULL));
	test_assert(cache_equals(cache_view, 1, ctx.cache_field2.idx, "bar1"));
	mail_cache_view_close(&cache_view);

	test_assert(test_mail_cache_get_purge_count(&ctx) == 2);
	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
}

static void test_mail_cache_resetid_mismatch(void)
{
	test_begin("mail cache resetid mismatch");
	test_mail_cache_resetid_mismatch_int(FALSE);
	test_end();
}

static void test_mail_cache_resetid_mismatch2(void)
{
	test_begin("mail cache resetid mismatch (2)");
	test_mail_cache_resetid_mismatch_int(TRUE);
	test_end();
}

static void test_mail_cache_purge_field_changes_int(bool drop_fields)
{
	enum {
		TEST_FIELD_NO,
		TEST_FIELD_NO_FORCED,
		TEST_FIELD_TEMP,
		TEST_FIELD_TEMP_FORCED,
		TEST_FIELD_YES,
		TEST_FIELD_YES_FORCED,
	};
	struct mail_cache_field cache_fields[] = {
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
	const struct mail_index_optimization_settings optimization_set = {
		.cache = {
			.unaccessed_field_drop_secs = 61,
		},
	};
	struct test_mail_cache_ctx ctx;
	struct mail_cache_view *cache_view;
	struct mail_cache_transaction_ctx *cache_trans;
	struct mail_index_transaction *trans;
	unsigned int i;

	test_mail_cache_init(test_mail_index_init(), &ctx);
	mail_index_set_optimization_settings(ctx.index, &optimization_set);

	/* add two mails with all of the cache fields */
	test_mail_cache_add_mail(&ctx, UINT_MAX, NULL);
	test_mail_cache_add_mail(&ctx, UINT_MAX, NULL);

	/* Create the cache file before registering any of the cache_fields
	   that we're testing. Otherwise our caching decisions are messed up
	   by purging (which is called to auto-create the cache). */
	test_assert(mail_cache_purge(ctx.cache, (uint32_t)-1, "test") == 0);
	mail_cache_register_fields(ctx.cache, cache_fields,
				   N_ELEMENTS(cache_fields));

	trans = mail_index_transaction_begin(ctx.view, 0);
	cache_view = mail_cache_view_open(ctx.cache, ctx.view);
	cache_trans = mail_cache_get_transaction(cache_view, trans);
	for (i = 0; i < N_ELEMENTS(cache_fields); i++) {
		const char *value = t_strdup_printf("%s-value",
						    cache_fields[i].name);
		if ((cache_fields[i].decision & ~MAIL_CACHE_DECISION_FORCED) !=
		    MAIL_CACHE_DECISION_NO) {
			mail_cache_add(cache_trans, 1, cache_fields[i].idx,
				       value, strlen(value));
			mail_cache_add(cache_trans, 2, cache_fields[i].idx,
				       value, strlen(value));
		}
	}

	/* day_stamp in index is used for deciding when a cache field needs to
	   be dropped. */
	uint32_t day_stamp = 123456789;
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, day_stamp),
		&day_stamp, sizeof(day_stamp), FALSE);
	/* day_first_uid[7] is used to determine which mails are "old" and
	   which mails are "new". [7] is the first "new" mail. */
	uint32_t first_new_uid = 2;
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, day_first_uid[7]),
		&first_new_uid, sizeof(first_new_uid), FALSE);
	test_assert(mail_index_transaction_commit(&trans) == 0);

	/* set the last_used time just at the boundary of being dropped or
	   being kept */
	for (i = 0; i < ctx.cache->fields_count; i++) {
		ctx.cache->fields[i].field.last_used = day_stamp -
			(drop_fields ? 1 : 0) -
			optimization_set.cache.unaccessed_field_drop_secs;
	}
	test_assert(mail_cache_purge(ctx.cache, (uint32_t)-1, "test") == 0);
	test_mail_cache_view_sync(&ctx);

	/* verify that caching decisions are as expected after purging */
	test_assert(ctx.cache->fields[cache_fields[TEST_FIELD_NO].idx].field.decision ==
		    MAIL_CACHE_DECISION_NO);
	test_assert(ctx.cache->fields[cache_fields[TEST_FIELD_NO_FORCED].idx].field.decision ==
		    (MAIL_CACHE_DECISION_NO | MAIL_CACHE_DECISION_FORCED));
	test_assert(ctx.cache->fields[cache_fields[TEST_FIELD_TEMP_FORCED].idx].field.decision ==
		    (MAIL_CACHE_DECISION_TEMP | MAIL_CACHE_DECISION_FORCED));
	test_assert(ctx.cache->fields[cache_fields[TEST_FIELD_YES_FORCED].idx].field.decision ==
		    (MAIL_CACHE_DECISION_YES | MAIL_CACHE_DECISION_FORCED));

	if (drop_fields) {
		test_assert(ctx.cache->fields[cache_fields[TEST_FIELD_TEMP].idx].field.decision ==
			    MAIL_CACHE_DECISION_NO);
		test_assert(ctx.cache->fields[cache_fields[TEST_FIELD_YES].idx].field.decision ==
			    MAIL_CACHE_DECISION_NO);
	} else {
		test_assert(ctx.cache->fields[cache_fields[TEST_FIELD_TEMP].idx].field.decision ==
			    MAIL_CACHE_DECISION_TEMP);
		test_assert(ctx.cache->fields[cache_fields[TEST_FIELD_YES].idx].field.decision ==
			    MAIL_CACHE_DECISION_TEMP);
	}

	/* verify that cache fields exist as expected after purging */
	test_assert(cache_equals(cache_view, 1, cache_fields[TEST_FIELD_NO].idx, NULL));
	test_assert(cache_equals(cache_view, 2, cache_fields[TEST_FIELD_NO].idx, NULL));
	test_assert(cache_equals(cache_view, 1, cache_fields[TEST_FIELD_NO_FORCED].idx, NULL));
	test_assert(cache_equals(cache_view, 2, cache_fields[TEST_FIELD_NO_FORCED].idx, NULL));
	test_assert(cache_equals(cache_view, 1, cache_fields[TEST_FIELD_TEMP].idx, NULL));
	if (drop_fields)
		test_assert(cache_equals(cache_view, 2, cache_fields[TEST_FIELD_TEMP].idx, NULL));
	else
		test_assert(cache_equals(cache_view, 2, cache_fields[TEST_FIELD_TEMP].idx, "temp-value"));
	test_assert(cache_equals(cache_view, 1, cache_fields[TEST_FIELD_TEMP_FORCED].idx, NULL));
	test_assert(cache_equals(cache_view, 2, cache_fields[TEST_FIELD_TEMP_FORCED].idx, "temp-forced-value"));
	if (drop_fields)
		test_assert(cache_equals(cache_view, 1, cache_fields[TEST_FIELD_YES].idx, NULL));
	else
		test_assert(cache_equals(cache_view, 1, cache_fields[TEST_FIELD_YES].idx, "yes-value"));
	test_assert(cache_equals(cache_view, 2, cache_fields[TEST_FIELD_YES_FORCED].idx, "yes-forced-value"));

	test_assert(test_mail_cache_get_purge_count(&ctx) == 1);
	mail_cache_view_close(&cache_view);
	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
}

static void test_mail_cache_purge_field_changes(void)
{
	test_begin("mail cache purge field changes");
	test_mail_cache_purge_field_changes_int(FALSE);
	test_end();
}

static void test_mail_cache_purge_field_changes2(void)
{
	test_begin("mail cache purge field changes");
	test_mail_cache_purge_field_changes_int(TRUE);
	test_end();
}

static void test_mail_cache_purge_already_done(void)
{
	struct test_mail_cache_ctx ctx;

	test_begin("mail cache purge already done");
	test_mail_cache_init(test_mail_index_init(), &ctx);
	test_mail_cache_add_mail(&ctx, ctx.cache_field.idx, "foo1");

	test_mail_cache_purge();
	test_assert(mail_cache_purge(ctx.cache, 1, "test") == 0);
	test_assert(test_mail_cache_get_purge_count(&ctx) == 1);

	test_assert(mail_cache_purge(ctx.cache, 2, "test") == 0);
	test_assert(test_mail_cache_get_purge_count(&ctx) == 2);

	test_assert(mail_cache_purge(ctx.cache, 2, "test") == 0);
	test_assert(test_mail_cache_get_purge_count(&ctx) == 2);

	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
	test_end();
}

static void test_mail_cache_purge_bitmask(void)
{
	struct mail_index_optimization_settings optimization_set = {
		.cache = {
			.unaccessed_field_drop_secs = 60,
		},
	};
	struct mail_cache_field bitmask_field = {
		.name = "bitmask",
		.type = MAIL_CACHE_FIELD_BITMASK,
		.field_size = 1,
		.decision = MAIL_CACHE_DECISION_TEMP,
	};
	struct test_mail_cache_ctx ctx;
	struct mail_cache_view *cache_view;

	test_begin("mail cache purge bitmask");
	test_mail_cache_init(test_mail_index_init(), &ctx);
	mail_index_set_optimization_settings(ctx.index, &optimization_set);
	ioloop_time = 1000000;
	test_mail_cache_add_mail(&ctx, UINT_MAX, NULL);
	test_mail_cache_add_mail(&ctx, UINT_MAX, NULL);
	test_assert(mail_cache_purge(ctx.cache, (uint32_t)-1, "test") == 0);
	mail_cache_register_fields(ctx.cache, &bitmask_field, 1);

	test_mail_cache_update_day_first_uid7(&ctx, 3);

	test_mail_cache_add_field(&ctx, 1, bitmask_field.idx, "\x01");
	test_mail_cache_add_field(&ctx, 1, bitmask_field.idx, "\x02");
	test_mail_cache_add_field(&ctx, 1, bitmask_field.idx, "\x04");
	test_mail_cache_add_field(&ctx, 2, bitmask_field.idx, "\x01");
	test_mail_cache_add_field(&ctx, 2, bitmask_field.idx, "\x02");
	test_mail_cache_add_field(&ctx, 2, bitmask_field.idx, "\x04");

	/* avoid dropping the field */
	ctx.cache->fields[bitmask_field.idx].field.last_used = ioloop_time;

	/* purge with TEMP decision, which causes the bitmask to be dropped */
	test_assert(mail_cache_purge(ctx.cache, (uint32_t)-1, "test") == 0);

	cache_view = mail_cache_view_open(ctx.cache, ctx.view);
	test_assert(cache_equals(cache_view, 1, bitmask_field.idx, NULL));
	test_assert(cache_equals(cache_view, 2, bitmask_field.idx, NULL));
	mail_cache_view_close(&cache_view);

	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
	test_end();
}


static void
test_mail_cache_update_need_purge_continued_records_int(bool big_min_size)
{
	struct mail_index_optimization_settings optimization_set = {
		.cache = {
			.purge_min_size = big_min_size ? 1024*1024 : 1,
			.purge_continued_percentage = 30,
		},
	};
	char value[30];
	struct test_mail_cache_ctx ctx;
	uint32_t seq;

	test_mail_cache_init(test_mail_index_init(), &ctx);
	mail_index_set_optimization_settings(ctx.index, &optimization_set);

	for (seq = 1; seq <= 100; seq++) {
		i_snprintf(value, sizeof(value), "foo%d", seq);
		test_mail_cache_add_mail(&ctx, ctx.cache_field.idx, value);
	}

	/* up to 29% no need to purge */
	for (seq = 1; seq <= 29; seq++) {
		i_snprintf(value, sizeof(value), "bar%d", seq);
		test_mail_cache_add_field(&ctx, seq, ctx.cache_field2.idx, value);
	}
	test_assert(ctx.cache->need_purge_file_seq == 0);

	/* at 30% need to purge */
	test_mail_cache_add_field(&ctx, 30, ctx.cache_field2.idx, "bar30");
	if (big_min_size)
		test_assert(ctx.cache->need_purge_file_seq == 0);
	else
		test_assert(ctx.cache->need_purge_file_seq == ctx.cache->hdr->file_seq);

	test_assert(test_mail_cache_get_purge_count(&ctx) == 0);
	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
}

static void test_mail_cache_update_need_purge_continued_records(void)
{
	test_begin("mail cache update need purge continued records");
	test_mail_cache_update_need_purge_continued_records_int(FALSE);
	test_end();
}

static void test_mail_cache_update_need_purge_continued_records2(void)
{
	test_begin("mail cache update need purge continued records (2)");
	test_mail_cache_update_need_purge_continued_records_int(TRUE);
	test_end();
}

static void
test_mail_cache_update_need_purge_deleted_records_int(bool big_min_size)
{
	struct mail_index_optimization_settings optimization_set = {
		.cache = {
			.purge_min_size = big_min_size ? 1024*1024 : 1,
			.purge_delete_percentage = 30,
		},
	};
	char value[30];
	struct mail_index_transaction *trans;
	struct test_mail_cache_ctx ctx;
	uint32_t seq;

	test_mail_cache_init(test_mail_index_init(), &ctx);
	mail_index_set_optimization_settings(ctx.index, &optimization_set);

	for (seq = 1; seq <= 100; seq++) {
		i_snprintf(value, sizeof(value), "foo%d", seq);
		test_mail_cache_add_mail(&ctx, ctx.cache_field.idx, value);
	}

	/* up to 29% no need to purge */
	trans = mail_index_transaction_begin(ctx.view, 0);
	for (seq = 1; seq <= 29; seq++) {
		i_snprintf(value, sizeof(value), "bar%d", seq);
		mail_index_expunge(trans, seq);
	}
	test_assert(mail_index_transaction_commit(&trans) == 0);
	test_mail_cache_index_sync(&ctx);

	test_assert(ctx.cache->need_purge_file_seq == 0);
	test_assert(mail_cache_reopen(ctx.cache) == 1);
	test_assert(ctx.cache->need_purge_file_seq == 0);
	test_assert(test_mail_cache_get_purge_count(&ctx) == 0);

	/* at 30% need to purge */
	trans = mail_index_transaction_begin(ctx.view, 0);
	mail_index_expunge(trans, 1);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	/* syncing will internally purge if !big_min_size */
	test_mail_cache_index_sync(&ctx);

	test_assert(ctx.cache->need_purge_file_seq == 0);
	test_assert(mail_cache_reopen(ctx.cache) == 1);
	test_assert(ctx.cache->need_purge_file_seq == 0);
	if (big_min_size)
		test_assert(test_mail_cache_get_purge_count(&ctx) == 0);
	else
		test_assert(test_mail_cache_get_purge_count(&ctx) == 1);

	test_mail_cache_deinit(&ctx);
	test_mail_index_delete();
}

static void test_mail_cache_update_need_purge_deleted_records(void)
{
	test_begin("mail cache update need purge deleted records");
	test_mail_cache_update_need_purge_deleted_records_int(FALSE);
	test_end();
}

static void test_mail_cache_update_need_purge_deleted_records2(void)
{
	test_begin("mail cache update need purge deleted records (2)");
	test_mail_cache_update_need_purge_deleted_records_int(TRUE);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_cache_read_during_purge,
		test_mail_cache_write_during_purge,
		test_mail_cache_purge_while_cache_locked,
		test_mail_cache_write_lost_during_purge,
		test_mail_cache_write_lost_during_purge2,
		test_mail_cache_delete_too_large,
		test_mail_cache_delete_too_large2,
		test_mail_cache_purge_too_large,
		test_mail_cache_purge_too_large2,
		test_mail_cache_unexpectedly_lost,
		test_mail_cache_unexpectedly_lost2,
		test_mail_cache_resetid_mismatch,
		test_mail_cache_resetid_mismatch2,
		test_mail_cache_purge_field_changes,
		test_mail_cache_purge_field_changes2,
		test_mail_cache_purge_already_done,
		test_mail_cache_purge_bitmask,
		test_mail_cache_update_need_purge_continued_records,
		test_mail_cache_update_need_purge_continued_records2,
		test_mail_cache_update_need_purge_deleted_records,
		test_mail_cache_update_need_purge_deleted_records2,
		NULL
	};
	return test_run(test_functions);
}
