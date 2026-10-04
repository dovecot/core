/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "test-common.h"
#include "test-corruption.h"
#include "test-mail-index.h"
#include "test-mail-index-corruption-common.h"

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

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_index_corruption,
		test_mail_index_corruption_mmap_disable,
		test_mail_index_corruption_saveonly,
		NULL
	};
	test_dir_init("mail-index-corruption");
	return test_run(test_functions);
}
