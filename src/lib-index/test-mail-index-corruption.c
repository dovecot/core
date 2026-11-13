/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "test-common.h"
#include "test-corruption.h"
#include "test-mail-index.h"
#include "test-mail-index-corruption-common.h"
#include "mail-transaction-log.h"

static failure_callback_t *orig_error_callback;

static void
test_ignore_errors_handler(const struct failure_context *ctx,
			   const char *format, va_list args)
{
	/* Corruption is expected to be logged as errors and warnings */
	if (ctx->type == LOG_TYPE_ERROR || ctx->type == LOG_TYPE_WARNING)
		return;
	orig_error_callback(ctx, format, args);
}

struct test_index_corruption_ctx {
	const struct test_index_file *file;
	enum mail_index_open_flags open_flags;
};

static void
test_index_corruption_callback(const unsigned char *data, size_t size,
			       struct test_index_corruption_ctx *ctx)
{
	bool success;

	test_index_corrupted_open(ctx->file, data, size, ctx->open_flags,
				  &success);
}

static void
test_index_file_corruption(const struct test_index_file *file,
			   enum mail_index_open_flags open_flags)
{
	struct test_index_corruption_ctx ctx = {
		.file = file,
		.open_flags = open_flags,
	};
	const struct test_corruption_settings set = {
		.name = t_strdup_printf("%s open_flags=0x%x",
					file->name, open_flags),
	};
	test_corruption_run(&set, file->data, file->size,
			    test_index_corruption_callback, &ctx);
}

static void
test_mail_index_corruption_flags(const char *name,
				 enum mail_index_open_flags open_flags)
{
	const struct test_index_file *file;
	failure_callback_t *fatal_callback, *info_callback, *debug_callback;
	bool success;

	test_begin(name);
	test_index_create(test_mail_index_get_dir());
	test_index_files_read();
	/* Make sure that all the expected files were created:
	   .index, .index.log, .index.log.2 and .index.cache */
	test_assert(array_count(&test_index_files) == 4);

	/* The original must be readable */
	test_index_corrupted_open(NULL, NULL, 0, open_flags, &success);
	test_assert(success);

	i_get_failure_handlers(&fatal_callback, &orig_error_callback,
			       &info_callback, &debug_callback);
	i_set_error_handler(test_ignore_errors_handler);
	array_foreach(&test_index_files, file)
		test_index_file_corruption(file, open_flags);
	i_set_error_handler(orig_error_callback);

	test_index_files_free();
	test_mail_index_delete();
	test_end();
}

static void test_mail_index_corruption(void)
{
	test_mail_index_corruption_flags("mail index corruption", 0);
}

static void test_mail_index_corruption_mmap_disable(void)
{
	test_mail_index_corruption_flags(
		"mail index corruption (mmap disabled)",
		MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE);
}

static void test_mail_index_corruption_saveonly(void)
{
	/* the cache file is read with pread() instead of mmap() */
	test_mail_index_corruption_flags("mail index corruption (save-only)",
					 MAIL_INDEX_OPEN_FLAG_SAVEONLY);
}

static const struct test_index_file *test_index_file_find(const char *name)
{
	const struct test_index_file *file;

	array_foreach(&test_index_files, file) {
		if (strcmp(file->name, name) == 0)
			return file;
	}
	i_unreached();
}

static void test_mail_index_corruption_log_prev_file_seq(void)
{
	static const enum mail_index_open_flags open_flags[] = {
		0,
		MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE,
		MAIL_INDEX_OPEN_FLAG_SAVEONLY,
	};
	const struct test_index_file *file;
	struct mail_transaction_log_header hdr;
	failure_callback_t *fatal_callback, *info_callback, *debug_callback;
	bool success;

	test_begin("mail index corruption: log prev_file_seq >= file_seq");
	test_index_create(test_mail_index_get_dir());
	test_index_files_read();

	/* Replace .log with only a v1.1 header (without compat_flags) that
	   has the same file_seq as .log.2, but prev_file_seq pointing to the
	   original .log's file_seq. Opening rotates it to .log.2 and creates
	   a new .log with the original file_seq. The old file then claims to
	   be the next file after the new .log, which links the files into a
	   loop. This used to lower the log view's max_file_seq below
	   min_file_seq and crash. */
	file = test_index_file_find(TEST_INDEX_PREFIX".log");
	i_assert(file->size >= sizeof(hdr));
	memcpy(&hdr, file->data, sizeof(hdr));
	test_assert(hdr.hdr_size == sizeof(hdr));
	test_assert(hdr.prev_file_seq + 1 == hdr.file_seq);
	hdr.minor_version = 1;
	hdr.hdr_size = offsetof(struct mail_transaction_log_header,
				compat_flags);
	hdr.file_seq = hdr.prev_file_seq;
	hdr.prev_file_seq = hdr.file_seq + 1;
	/* the new .log's header size */
	hdr.prev_file_offset = sizeof(hdr);

	i_get_failure_handlers(&fatal_callback, &orig_error_callback,
			       &info_callback, &debug_callback);
	i_set_error_handler(test_ignore_errors_handler);
	for (unsigned int i = 0; i < N_ELEMENTS(open_flags); i++) {
		test_index_corrupted_open(file, (const void *)&hdr,
					  hdr.hdr_size, open_flags[i],
					  &success);
		test_assert_idx(success, i);
	}
	i_set_error_handler(orig_error_callback);

	test_index_files_free();
	test_mail_index_delete();
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_index_corruption,
		test_mail_index_corruption_mmap_disable,
		test_mail_index_corruption_saveonly,
		test_mail_index_corruption_log_prev_file_seq,
		NULL
	};
	test_dir_init("mail-index-corruption");
	return test_run(test_functions);
}
