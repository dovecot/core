/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "test-common.h"
#include "test-mail-index.h"
#include "mail-transaction-log-private.h"

static void test_mail_index_rotate(void)
{
	struct mail_index *index, *index2;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	struct mail_transaction_log_file *file;
	const char *reason;

	test_begin("mail index rotate");
	index = test_mail_index_init(TRUE);
	index2 = test_mail_index_open(FALSE);
	view = mail_index_view_open(index);

	/* First rotation of the index. The view will point to the old index. */
	trans = mail_index_transaction_begin(view, 0);
	mail_index_reset(trans);
	test_assert(mail_index_transaction_commit(&trans) == 0);

	/* Second rotation of the index. The log head doesn't have any extra
	   references. */
	trans = mail_index_transaction_begin(view, 0);
	mail_index_reset(trans);
	test_assert(mail_index_transaction_commit(&trans) == 0);

	/* The 2nd index's log head also doesn't have any extra references.
	   Check that it doesn't crash. */
	test_assert(mail_transaction_log_find_file(index2->log, 3, FALSE, &file, &reason) == 0);

	mail_index_view_close(&view);
	test_mail_index_deinit(&index);
	test_mail_index_deinit(&index2);
	test_end();
}

static void
test_mail_index_new_extension_rotate_write(struct mail_index *index2,
					   uint32_t uid)
{
	struct mail_index_view *view2;
	struct mail_index_transaction *trans;
	uint32_t hdr_ext_id, rec_ext_id, file_seq, seq, rec_ext = 0x12345678;
	uoff_t file_offset;

	/* Rotate the index in the index */
	test_assert(mail_transaction_log_sync_lock(index2->log, "test",
						   &file_seq, &file_offset) == 0);
	mail_index_write(index2, TRUE, "test");
	mail_transaction_log_sync_unlock(index2->log, "test");

	/* Write a new extension header to the 2nd index. */
	hdr_ext_id = mail_index_ext_register(index2, "test",
					     sizeof(hdr_ext_id), 0, 0);
	rec_ext_id = mail_index_ext_register(index2, "test-rec", 0,
					     sizeof(uint32_t), sizeof(uint32_t));
	view2 = mail_index_view_open(index2);
	trans = mail_index_transaction_begin(view2,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mail_index_update_header_ext(trans, hdr_ext_id, 0,
				     &hdr_ext_id, sizeof(hdr_ext_id));
	mail_index_append(trans, uid, &seq);
	mail_index_update_ext(trans, seq, rec_ext_id, &rec_ext, NULL);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(&view2);
}

static void test_mail_index_new_extension_sync(struct mail_index_view *view)
{
	struct mail_index_view_sync_ctx *sync_ctx;
	struct mail_index_view_sync_rec sync_rec;
	bool delayed_expunges;

	test_assert(mail_index_refresh(view->index) == 0);
	sync_ctx = mail_index_view_sync_begin(view,
		MAIL_INDEX_VIEW_SYNC_FLAG_NOEXPUNGES);
	test_assert(!mail_index_view_sync_next(sync_ctx, &sync_rec));
	test_assert(mail_index_view_sync_commit(&sync_ctx, &delayed_expunges) == 0);
}

static void test_mail_index_new_extension(void)
{
	struct mail_index *index, *index2;
	struct mail_index_view *view, *view2;
	struct mail_index_transaction *trans;
	uint32_t seq, rec_ext_id, rec_ext = 0x12345678;

	test_begin("mail index new extension");
	index = test_mail_index_init(TRUE);
	index2 = test_mail_index_open(FALSE);
	view = mail_index_view_open(index);

	rec_ext_id = mail_index_ext_register(index, "test-rec", 0,
					     sizeof(uint32_t), sizeof(uint32_t));

	/* Save two mails */
	uint32_t uid_validity = 123456;
	trans = mail_index_transaction_begin(view,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);
	mail_index_append(trans, 1, &seq);
	mail_index_update_ext(trans, seq, rec_ext_id, &rec_ext, NULL);
	mail_index_append(trans, 2, &seq);
	mail_index_update_ext(trans, seq, rec_ext_id, &rec_ext, NULL);
	test_assert(mail_index_transaction_commit(&trans) == 0);

	/* refresh indexes and view */
	test_assert(mail_index_refresh(index2) == 0);
	mail_index_view_close(&view);
	view = mail_index_view_open(index);

	/* Expunge the mail in the 2nd index */
	view2 = mail_index_view_open(index2);
	trans = mail_index_transaction_begin(view2,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mail_index_expunge(trans, 1);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(&view2);

	/* Sync the first view without expunges */
	test_mail_index_new_extension_sync(view);

	for (unsigned int i = 0; i < 3; i++)
		test_mail_index_new_extension_rotate_write(index2, 3 + i);

	/* Sync the first view. It needs to generate the missing view. */
	test_expect_error_string("generating missing logs");
	test_mail_index_new_extension_sync(view);
	test_expect_no_more_errors();
	test_assert(mail_index_get_header(view)->messages_count == 5);

	/* Make sure the extensions records are still there.
	   Note that this works, because the extensions are looked up from the
	   newly refreshed index, not the old index. */
	for (seq = 1; seq <= 5; seq++) {
		const void *data;
		bool expunged;
		mail_index_lookup_ext(view, seq, rec_ext_id, &data, &expunged);
		test_assert_idx(memcmp(data, &rec_ext, sizeof(rec_ext)) == 0, seq);
	}

	/* Once more rotate and write using the new extension */
	test_mail_index_new_extension_rotate_write(index2, 6);
	/* Make sure the first view understands the new extension by ID */
	test_mail_index_new_extension_sync(view);

	mail_index_view_close(&view);
	test_mail_index_deinit(&index);
	test_mail_index_deinit(&index2);
	test_end();
}

static void test_mail_index_corruption_message_count(void)
{
	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;

	test_begin("mail index corruption: message count");
	index = test_mail_index_init(TRUE);

	/* make dovecot.index at least MAIL_INDEX_MMAP_MIN_SIZE bytes */
	view = mail_index_view_open(index);
	trans = mail_index_transaction_begin(view,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);

	uint32_t uid_validity = 1234;
	mail_index_update_header(trans,
				 offsetof(struct mail_index_header, uid_validity),
				 &uid_validity, sizeof(uid_validity), TRUE);

	uint32_t seq;
	for (uint32_t uid = 1; uid <= 10000; uid++)
		mail_index_append(trans, uid, &seq);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(&view);

	/* write dovecot.index */
	struct mail_index_sync_ctx *sync_ctx;
	test_assert(mail_index_sync_begin(index, &sync_ctx, &view, &trans, 0) > 0);
	mail_index_write(index, FALSE, "test");
	test_assert(mail_index_sync_commit(&sync_ctx) == 0);

	test_mail_index_close(&index);

	/* write a corrupted messages_count */
	const char *path = t_strconcat(test_mail_index_get_dir(),
				       "/test.dovecot.index", NULL);
	int fd = open(path, O_RDWR);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);

	uint32_t messages_count = 0x80000000;
	test_assert(pwrite(fd, &messages_count, sizeof(messages_count),
			   offsetof(struct mail_index_header, messages_count)) ==
		    sizeof(messages_count));
	i_close_fd(&fd);

	test_expect_error_string_n_times("test.dovecot.index", 3);
	index = test_mail_index_open(FALSE);
	test_expect_no_more_errors();
	test_mail_index_deinit(&index);

	test_end();
}

static void test_mail_index_map_fsck_fail_restores_map(void)
{
	struct mail_index *index;
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *sync_trans;
	const char *idx_path;
	uint32_t seen_count;
	int fd;

	test_begin("mail index map: fsck fail restores old map");

	/* Create a valid index and force the .index file to be written. */
	index = test_mail_index_init(TRUE);
	int ret = mail_index_sync_begin(index, &sync_ctx, &sync_view,
					&sync_trans, 0);
	test_assert_cmp(ret, >, 0);
	mail_index_write(index, FALSE, "test");
	ret = mail_index_sync_commit(&sync_ctx);
	test_assert_cmp(ret, ==, 0);
	test_mail_index_close(&index);

	/* Corrupt seen_messages_count > messages_count (0 messages, so 1 > 0).
	 * mail_index_map_check_header() returns 0 (soft error) for this,
	 * which triggers mail_index_fsck() inside mail_index_map_latest_file(). */
	idx_path = t_strconcat(test_mail_index_get_dir(),
			       "/test.dovecot.index", NULL);
	fd = open(idx_path, O_RDWR);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", idx_path);
	seen_count = 1;
	ssize_t len = pwrite(fd, &seen_count, sizeof(seen_count),
			     offsetof(struct mail_index_header,
				    seen_messages_count));
	test_assert_cmp(len, ==, (ssize_t)sizeof(seen_count));
	i_close_fd(&fd);

	/* Opening readonly causes fsck to fail immediately (can't write-lock a
	 * readonly index). Without the fix in mail_index_map_latest_file(),
	 * index->map is left pointing to the freed new_map, and the subsequent
	 * mail_index_unmap() in mail_index_close_nonopened() is a use-after-free
	 * caught by ASAN/valgrind. */
	test_expect_errors(2);
	index = mail_index_alloc(NULL, test_mail_index_get_dir(),
				 "test.dovecot.index");
	ret = mail_index_open(index, MAIL_INDEX_OPEN_FLAG_READONLY);
	test_assert_cmp(ret, ==, -1);
	mail_index_free(&index);
	test_expect_no_more_errors();

	test_mail_index_delete();
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_index_rotate,
		test_mail_index_new_extension,
		test_mail_index_corruption_message_count,
		test_mail_index_map_fsck_fail_restores_map,
		NULL
	};
	test_dir_init("mail-index");
	return test_run(test_functions);
}
