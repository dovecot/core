/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "str.h"
#include "read-full.h"
#include "write-full.h"
#include "test-common.h"
#include "unlink-directory.h"
#include "ioloop.h"
#include "mail-index-private.h"
#include "test-mail-index-corruption-common.h"
#include "mail-index-modseq.h"
#include "mail-transaction-log-private.h"
#include "mail-cache.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST_MESSAGES_COUNT 6

static const struct mail_cache_field test_cache_fields[] = {
	{ .name = "fixed", .type = MAIL_CACHE_FIELD_FIXED_SIZE,
	  .field_size = sizeof(uint32_t),
	  .decision = MAIL_CACHE_DECISION_YES },
	{ .name = "str", .type = MAIL_CACHE_FIELD_STRING,
	  .decision = MAIL_CACHE_DECISION_YES },
	{ .name = "bits", .type = MAIL_CACHE_FIELD_BITMASK,
	  .field_size = sizeof(uint32_t),
	  .decision = MAIL_CACHE_DECISION_YES },
	{ .name = "hdr.subject", .type = MAIL_CACHE_FIELD_HEADER,
	  .decision = MAIL_CACHE_DECISION_YES },
};

struct test_index_ctx {
	struct mail_index *index;
	bool opened;
	uint32_t hdr_ext_id, rec_ext_id, rec64_ext_id;
	unsigned int cache_fields[N_ELEMENTS(test_cache_fields)];
};

ARRAY_TYPE(test_index_file) test_index_files;
static char *test_index_dir;

static bool
test_index_ctx_open(struct test_index_ctx *ctx_r,
		    enum mail_index_open_flags open_flags)
{
	struct mail_cache_field fields[N_ELEMENTS(test_cache_fields)];

	i_zero(ctx_r);
	ctx_r->index = mail_index_alloc(NULL, test_index_dir,
					TEST_INDEX_PREFIX);
	mail_index_set_fsync_mode(ctx_r->index, FSYNC_MODE_NEVER, 0);
	ctx_r->hdr_ext_id = mail_index_ext_register(ctx_r->index, "test-hdr",
						    sizeof(uint64_t), 0, 0);
	ctx_r->rec_ext_id = mail_index_ext_register(ctx_r->index, "test-rec",
						    0, sizeof(uint32_t),
						    sizeof(uint32_t));
	ctx_r->rec64_ext_id = mail_index_ext_register(ctx_r->index,
						      "test-rec64", 0,
						      sizeof(uint64_t),
						      sizeof(uint64_t));
	if (mail_index_open(ctx_r->index,
			    MAIL_INDEX_OPEN_FLAG_CREATE | open_flags) <= 0)
		return FALSE;
	ctx_r->opened = TRUE;
	mail_index_modseq_enable(ctx_r->index);

	memcpy(fields, test_cache_fields, sizeof(fields));
	mail_cache_register_fields(ctx_r->index->cache, fields,
				   N_ELEMENTS(fields),
				   MAIL_CACHE_TRUNCATE_NAME_FAIL);
	for (unsigned int i = 0; i < N_ELEMENTS(fields); i++)
		ctx_r->cache_fields[i] = fields[i].idx;
	return TRUE;
}

static void test_index_ctx_close(struct test_index_ctx *ctx)
{
	if (ctx->opened)
		mail_index_close(ctx->index);
	mail_index_free(&ctx->index);
}

static void
test_index_cache_add(struct test_index_ctx *ctx,
		     struct mail_index_transaction *trans,
		     struct mail_cache_view *cache_view, uint32_t seq,
		     unsigned int field_num, const char *value)
{
	struct mail_cache_transaction_ctx *cache_trans =
		mail_cache_get_transaction(cache_view, trans);
	uint32_t num = seq * 0x01010101;

	switch (test_cache_fields[field_num].type) {
	case MAIL_CACHE_FIELD_FIXED_SIZE:
	case MAIL_CACHE_FIELD_BITMASK:
		mail_cache_add(cache_trans, seq, ctx->cache_fields[field_num],
			       &num, sizeof(num));
		break;
	case MAIL_CACHE_FIELD_HEADER: {
		/* { line_nums[], 0, "headers" } */
		buffer_t *buf = t_buffer_create(64);
		uint32_t line_num = 1;
		buffer_append(buf, &line_num, sizeof(line_num));
		line_num = 0;
		buffer_append(buf, &line_num, sizeof(line_num));
		str_printfa(buf, "Subject: %s\n", value);
		mail_cache_add(cache_trans, seq, ctx->cache_fields[field_num],
			       buf->data, buf->used);
		break;
	}
	default:
		mail_cache_add(cache_trans, seq, ctx->cache_fields[field_num],
			       value, strlen(value) + 1);
		break;
	}
}

/* Write all the different kinds of changes to the index, log and cache. */
static void test_index_write_changes(struct test_index_ctx *ctx, bool first)
{
	static const char *const keywords_list[] = { "foo", "bar", NULL };
	static const char *const keywords2_list[] = { "baz", NULL };
	struct mail_index_view *view, *updated_view;
	struct mail_index_transaction *trans;
	struct mail_cache_view *cache_view;
	struct mail_keywords *keywords;
	uint32_t seq, value32;
	uint64_t value64;

	view = mail_index_view_open(ctx->index);
	trans = mail_index_transaction_begin(view,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	updated_view = mail_index_transaction_open_updated_view(trans);
	cache_view = mail_cache_view_open(ctx->index->cache, updated_view);

	uint32_t next_uid = mail_index_get_header(view)->next_uid;
	if (first) {
		uint32_t uid_validity = 1234;
		mail_index_update_header(trans,
			offsetof(struct mail_index_header, uid_validity),
			&uid_validity, sizeof(uid_validity), TRUE);
	}
	keywords = mail_index_keywords_create(ctx->index,
			first ? keywords_list : keywords2_list);
	for (unsigned int i = 0; i < TEST_MESSAGES_COUNT / 2; i++) {
		mail_index_append(trans, next_uid + i * 2, &seq);
		mail_index_update_flags(trans, seq, MODIFY_REPLACE,
					MAIL_SEEN | (i % 2 == 0 ? 0 :
						     MAIL_FLAGGED));
		if (i % 2 == 0) {
			mail_index_update_keywords(trans, seq, MODIFY_ADD,
						   keywords);
		}
		value32 = 0x10000 + seq;
		mail_index_update_ext(trans, seq, ctx->rec_ext_id,
				      &value32, NULL);
		value64 = 0x100000000ULL + seq;
		mail_index_update_ext(trans, seq, ctx->rec64_ext_id,
				      &value64, NULL);
		for (unsigned int j = 0; j < N_ELEMENTS(test_cache_fields); j++) {
			test_index_cache_add(ctx, trans, cache_view, seq, j,
				t_strdup_printf("value %u-%u", seq, j));
		}
	}
	mail_index_keywords_unref(&keywords);
	value64 = first ? 0x123456789abcdefULL : 0xfedcba987654321ULL;
	mail_index_update_header_ext(trans, ctx->hdr_ext_id, 0,
				     &value64, sizeof(value64));
	if (!first) {
		/* Changes to the previously existing mails */
		mail_index_update_flags(trans, 1, MODIFY_ADD, MAIL_ANSWERED);
		mail_index_update_flags(trans, 2, MODIFY_REMOVE, MAIL_SEEN);
		keywords = mail_index_keywords_create(ctx->index, NULL);
		mail_index_update_keywords(trans, 1, MODIFY_REPLACE, keywords);
		mail_index_keywords_unref(&keywords);
		(void)mail_index_atomic_inc_ext(trans, 2, ctx->rec_ext_id, 5);
		mail_index_update_modseq(trans, 3, 1000);
		mail_index_attribute_set(trans, FALSE, "test-attr", 1, 10);
		/* Add more cache fields to an existing mail, so it
		   gets multiple cache records. */
		test_index_cache_add(ctx, trans, cache_view, 2, 1,
				     "second record");
		mail_index_expunge(trans, 3);
	}
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_cache_view_close(&cache_view);
	mail_index_view_close(&updated_view);
	mail_index_view_close(&view);
}

static void test_index_sync(struct mail_index *index, bool write_index)
{
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	struct mail_index_sync_rec sync_rec;
	uint32_t seq1, seq2;

	if (mail_index_sync_begin(index, &sync_ctx, &view, &trans, 0) <= 0)
		return;
	while (mail_index_sync_next(sync_ctx, &sync_rec)) {
		if (sync_rec.type != MAIL_INDEX_SYNC_TYPE_EXPUNGE)
			continue;
		if (mail_index_lookup_seq_range(view, sync_rec.uid1,
						sync_rec.uid2,
						&seq1, &seq2)) {
			for (; seq1 <= seq2; seq1++)
				mail_index_expunge(trans, seq1);
		}
	}
	if (write_index)
		mail_index_write(index, FALSE, "test");
	(void)mail_index_sync_commit(&sync_ctx);
}

static void test_index_rotate(struct mail_index *index)
{
	uint32_t file_seq;
	uoff_t file_offset;

	test_assert(mail_transaction_log_sync_lock(index->log, "test",
						   &file_seq, &file_offset) == 0);
	mail_index_write(index, TRUE, "test");
	mail_transaction_log_sync_unlock(index->log, "test");
}

static int
test_index_file_cmp(const struct test_index_file *f1,
		    const struct test_index_file *f2)
{
	return strcmp(f1->name, f2->name);
}

void test_index_files_read(void)
{
	const char *dir = test_index_dir;
	struct test_index_file *file;
	struct dirent *d;
	struct stat st;
	DIR *dirp;

	i_array_init(&test_index_files, 8);
	dirp = opendir(dir);
	if (dirp == NULL)
		i_fatal("opendir(%s) failed: %m", dir);
	while ((d = readdir(dirp)) != NULL) {
		if (d->d_name[0] == '.')
			continue;
		const char *path = t_strdup_printf("%s/%s", dir, d->d_name);
		int fd = open(path, O_RDONLY);
		if (fd == -1)
			i_fatal("open(%s) failed: %m", path);
		if (fstat(fd, &st) < 0)
			i_fatal("fstat(%s) failed: %m", path);
		file = array_append_space(&test_index_files);
		file->name = i_strdup(d->d_name);
		file->size = st.st_size;
		file->data = i_malloc(file->size + 1);
		if (file->size > 0 &&
		    pread_full(fd, file->data, file->size, 0) <= 0)
			i_fatal("pread(%s) failed: %m", path);
		i_close_fd(&fd);
	}
	if (closedir(dirp) < 0)
		i_fatal("closedir(%s) failed: %m", dir);
	/* keep the order stable */
	array_sort(&test_index_files, test_index_file_cmp);
}

void test_index_files_free(void)
{
	struct test_index_file *file;

	array_foreach_modifiable(&test_index_files, file) {
		i_free(file->name);
		i_free(file->data);
	}
	array_free(&test_index_files);
	i_free(test_index_dir);
}

void test_index_create(const char *dir)
{
	struct test_index_ctx ctx;
	const char *error;

	i_free(test_index_dir);
	test_index_dir = i_strdup(dir);
	(void)unlink_directory(test_index_dir, UNLINK_DIRECTORY_FLAG_RMDIR,
			       &error);
	if (mkdir(test_index_dir, 0700) < 0)
		i_fatal("mkdir(%s) failed: %m", test_index_dir);

	ioloop_time = 1;
	test_assert(test_index_ctx_open(&ctx, 0));
	test_index_write_changes(&ctx, TRUE);
	/* Write dovecot.index and rotate the log */
	test_index_sync(ctx.index, TRUE);
	test_index_rotate(ctx.index);
	/* The rest of the changes go only to the log and cache */
	test_index_write_changes(&ctx, FALSE);
	test_index_ctx_close(&ctx);
}

/* Write the files, with the given file replaced by data. */
static void
test_index_files_write(const struct test_index_file *corrupted_file,
		       const unsigned char *data, size_t size)
{
	const char *dir = test_index_dir;
	const struct test_index_file *file;
	const char *error;

	(void)unlink_directory(dir, UNLINK_DIRECTORY_FLAG_RMDIR, &error);
	if (mkdir(dir, 0700) < 0)
		i_fatal("mkdir(%s) failed: %m", dir);

	array_foreach(&test_index_files, file) {
		const char *path = t_strdup_printf("%s/%s", dir, file->name);
		int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd == -1)
			i_fatal("open(%s) failed: %m", path);
		if (file == corrupted_file) {
			if (write_full(fd, data, size) < 0)
				i_fatal("write(%s) failed: %m", path);
		} else {
			if (write_full(fd, file->data, file->size) < 0)
				i_fatal("write(%s) failed: %m", path);
		}
		i_close_fd(&fd);
	}
}

static void test_index_lookups(struct test_index_ctx *ctx)
{
	struct mail_index_view *view;
	struct mail_cache_view *cache_view;
	ARRAY_TYPE(keyword_indexes) keywords;
	const void *data;
	size_t data_size;
	enum mail_flags flags;
	uint32_t seq, seq1, seq2, uid, count;
	bool expunged;

	view = mail_index_view_open(ctx->index);
	cache_view = mail_cache_view_open(ctx->index->cache, view);
	buffer_t *buf = t_buffer_create(64);
	string_t *str = t_str_new(64);
	t_array_init(&keywords, 8);

	mail_index_get_header_ext(view, ctx->hdr_ext_id, &data, &data_size);
	(void)mail_index_lookup_seq_range(view, 1, UINT32_MAX, &seq1, &seq2);
	(void)mail_index_lookup_first(view, MAIL_SEEN, MAIL_SEEN, &seq);
	count = mail_index_view_get_messages_count(view);
	for (seq = 1; seq <= count; seq++) {
		(void)mail_index_lookup(view, seq);
		mail_index_lookup_uid(view, seq, &uid);
		/* Record UIDs aren't verified until fsck, so uid=0 is
		   possible. */
		if (uid != 0)
			(void)mail_index_lookup_seq(view, uid, &seq1);
		array_clear(&keywords);
		mail_index_lookup_keywords(view, seq, &keywords);
		array_clear(&keywords);
		mail_index_lookup_view_flags(view, seq, &flags, &keywords);
		mail_index_lookup_ext(view, seq, ctx->rec_ext_id,
				      &data, &expunged);
		mail_index_lookup_ext(view, seq, ctx->rec64_ext_id,
				      &data, &expunged);
		(void)mail_index_modseq_lookup(view, seq);
		for (unsigned int i = 0; i < N_ELEMENTS(ctx->cache_fields); i++) {
			buffer_set_used_size(buf, 0);
			(void)mail_cache_lookup_field(cache_view, buf, seq,
						      ctx->cache_fields[i]);
		}
		str_truncate(str, 0);
		/* hdr.subject */
		(void)mail_cache_lookup_headers(cache_view, str, seq,
						&ctx->cache_fields[3], 1);
		(void)mail_cache_field_exists_any(cache_view, seq);
	}
	mail_cache_view_close(&cache_view);
	mail_index_view_close(&view);
}

static void test_index_updates(struct test_index_ctx *ctx)
{
	struct mail_index_view *view, *updated_view;
	struct mail_index_transaction *trans;
	struct mail_cache_view *cache_view;
	uint32_t seq, count, value32 = 0x12345678;

	view = mail_index_view_open(ctx->index);
	trans = mail_index_transaction_begin(view,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	updated_view = mail_index_transaction_open_updated_view(trans);
	cache_view = mail_cache_view_open(ctx->index->cache, updated_view);

	count = mail_index_view_get_messages_count(view);
	if (count > 0) {
		mail_index_update_flags(trans, 1, MODIFY_ADD, MAIL_DELETED);
		mail_index_update_ext(trans, count, ctx->rec_ext_id,
				      &value32, NULL);
		test_index_cache_add(ctx, trans, cache_view, count, 1,
				     "updated");
	}
	uint32_t next_uid = mail_index_get_header(view)->next_uid;
	if (next_uid != 0 && next_uid != UINT32_MAX) {
		mail_index_append(trans, next_uid, &seq);
		for (unsigned int i = 0; i < N_ELEMENTS(test_cache_fields); i++) {
			test_index_cache_add(ctx, trans, cache_view, seq, i,
					     "new");
		}
	}
	(void)mail_index_transaction_commit(&trans);
	mail_cache_view_close(&cache_view);
	mail_index_view_close(&updated_view);
	mail_index_view_close(&view);
}

void
test_index_corrupted_open(const struct test_index_file *corrupted_file,
			  const unsigned char *data, size_t size,
			  enum mail_index_open_flags open_flags,
			  bool *success_r)
{
	struct test_index_ctx ctx;

	test_index_files_write(corrupted_file, data, size);

	*success_r = test_index_ctx_open(&ctx, open_flags);
	if (*success_r) T_BEGIN {
		/* Lookups before and after syncing. Syncing runs fsck and
		   may rebuild the index. */
		test_index_lookups(&ctx);
		(void)mail_index_verify_records(ctx.index);
		test_index_lookups(&ctx);
		test_index_sync(ctx.index, FALSE);
		test_index_lookups(&ctx);
		test_index_updates(&ctx);
		test_index_sync(ctx.index, FALSE);
		test_index_lookups(&ctx);
		(void)mail_cache_purge(ctx.index->cache, UINT32_MAX, "test");
		test_index_lookups(&ctx);
	} T_END;
	test_index_ctx_close(&ctx);
}
