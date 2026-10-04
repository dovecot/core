/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "write-full.h"
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

static void test_mail_index_log_refresh_rotation_race(void)
{
	struct mail_index *index, *index2;
	struct mail_index_view *view, *view2;
	struct mail_index_transaction *trans;
	struct mail_transaction_log_file *file;
	const char *reason, *log_path, *log2_path;
	uint32_t file_seq, seq;
	uoff_t file_offset;
	unsigned int i;

	test_begin("mail index log refresh rotation race");
	index = test_mail_index_init(TRUE);
	log_path = t_strconcat(test_mail_index_get_dir(),
			       "/test.dovecot.index.log", NULL);
	log2_path = t_strconcat(log_path, ".2", NULL);

	view = mail_index_view_open(index);
	trans = mail_index_transaction_begin(view,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	uint32_t uid_validity = 1234;
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);
	mail_index_append(trans, 1, &seq);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(&view);

	/* Rotate twice, so .log.2 also exists */
	for (i = 0; i < 2; i++) {
		test_assert(mail_transaction_log_sync_lock(index->log, "test",
			&file_seq, &file_offset) == 0);
		mail_index_write(index, TRUE, "test");
		mail_transaction_log_sync_unlock(index->log, "test");
	}

	/* Second "process" opens the index and sees the latest log head */
	index2 = test_mail_index_open(FALSE);
	uint32_t base_seq = index2->log->head->hdr.file_seq;

	/* First index rotates again: .log=base+1, .log.2=base */
	test_assert(mail_transaction_log_sync_lock(index->log, "test",
		&file_seq, &file_offset) == 0);
	mail_index_write(index, TRUE, "test");
	mail_transaction_log_sync_unlock(index->log, "test");

	/* Simulate the middle of the next rotation: the new log file has
	   been hard-linked to .log.2, but the newer .log hasn't been
	   created yet, so both .log and .log.2 point to the base+1 file. */
	test_assert(i_unlink(log2_path) == 0);
	test_assert(link(log_path, log2_path) == 0);

	/* index2 (head=base) tries to find an already deleted file seq,
	   e.g. for syncing a view. It opens .log.2 and finds base+1 in it,
	   which gets added to its file list, while its head still points
	   to base. */
	test_assert(mail_transaction_log_find_file(index2->log, base_seq - 2,
						   FALSE, &file, &reason) == 0);

	/* index2 appends to the log. Refreshing the log sees that the .log
	   inode differs from its head (base), but reopening .log finds the
	   same base+1 file that is already opened via the .log.2 path.
	   This must not fail the append. */
	view2 = mail_index_view_open(index2);
	trans = mail_index_transaction_begin(view2,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mail_index_append(trans, 2, &seq);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(&view2);
	test_assert(index2->log->head->hdr.file_seq == base_seq + 1);

	test_mail_index_close(&index2);
	test_mail_index_deinit(&index);
	test_end();
}

static void test_mail_index_log_rotate_max_file_seq(void)
{
	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	const char *path;
	uint32_t file_seq, seq;
	uoff_t file_offset;
	int fd;

	test_begin("mail index log rotate max file_seq");
	index = test_mail_index_init(TRUE);
	view = mail_index_view_open(index);
	trans = mail_index_transaction_begin(view,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	uint32_t uid_validity = 1234;
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);
	mail_index_append(trans, 1, &seq);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(&view);

	/* write dovecot.index without rotating */
	test_assert(mail_transaction_log_sync_lock(index->log, "test",
		&file_seq, &file_offset) == 0);
	mail_index_write(index, FALSE, "test");
	mail_transaction_log_sync_unlock(index->log, "test");
	test_mail_index_close(&index);

	/* set the highest allowed file_seq to both the log and the index */
	file_seq = MAIL_TRANSACTION_LOG_MAX_FILE_SEQ;
	path = t_strconcat(test_mail_index_get_dir(),
			   "/test.dovecot.index.log", NULL);
	fd = open(path, O_RDWR);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);
	test_assert(pwrite(fd, &file_seq, sizeof(file_seq),
		offsetof(struct mail_transaction_log_header, file_seq)) ==
		sizeof(file_seq));
	i_close_fd(&fd);
	path = t_strconcat(test_mail_index_get_dir(),
			   "/test.dovecot.index", NULL);
	fd = open(path, O_RDWR);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);
	test_assert(pwrite(fd, &file_seq, sizeof(file_seq),
		offsetof(struct mail_index_header, log_file_seq)) ==
		sizeof(file_seq));
	i_close_fd(&fd);

	index = test_mail_index_open(FALSE);
	test_assert(index->log->head->hdr.file_seq ==
		    MAIL_TRANSACTION_LOG_MAX_FILE_SEQ);

	/* rotating must not create a log file older than the head */
	test_assert(mail_transaction_log_sync_lock(index->log, "test",
		&file_seq, &file_offset) == 0);
	mail_index_write(index, TRUE, "test");
	mail_transaction_log_sync_unlock(index->log, "test");
	test_assert(index->log->head->hdr.file_seq >
		    MAIL_TRANSACTION_LOG_MAX_FILE_SEQ);

	/* changes written to the new log file are seen */
	view = mail_index_view_open(index);
	trans = mail_index_transaction_begin(view,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mail_index_append(trans, 2, &seq);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(&view);
	test_assert(mail_index_refresh(index) == 0);
	view = mail_index_view_open(index);
	test_assert(mail_index_view_get_messages_count(view) == 2);
	mail_index_view_close(&view);

	test_mail_index_deinit(&index);
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

static void test_mail_index_corruption_record_size_zero(void)
{
	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;

	test_begin("mail index corruption: record_size zero");
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

	/* write a corrupted record_size */
	const char *path = t_strconcat(test_mail_index_get_dir(),
				       "/test.dovecot.index", NULL);
	int fd = open(path, O_RDWR);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);

	uint32_t record_size = 0;
	test_assert(pwrite(fd, &record_size, sizeof(record_size),
			   offsetof(struct mail_index_header, record_size)) ==
		    sizeof(record_size));
	i_close_fd(&fd);

	test_expect_error_string("record_size too small");
	index = test_mail_index_open(FALSE);
	test_expect_no_more_errors();
	test_mail_index_deinit(&index);

	test_end();
}

static void test_mail_index_log_garbage_at_eof(void)
{
	static const unsigned char garbage[8] = { 0 };
	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	struct mail_index_sync_ctx *sync_ctx = NULL;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *sync_trans;
	struct mail_transaction_log_file *file;
	const char *path;
	struct stat st;
	uoff_t old_sync_offset;
	uint32_t seq, old_file_seq;
	int fd;

	test_begin("mail index log garbage at EOF");
	index = test_mail_index_init(TRUE);

	/* Write something to the log */
	uint32_t uid_validity = 123456;
	view = mail_index_view_open(index);
	trans = mail_index_transaction_begin(view,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);
	mail_index_append(trans, 1, &seq);
	test_assert_cmp(mail_index_transaction_commit(&trans), ==, 0);
	mail_index_view_close(&view);

	file = index->log->head;
	old_file_seq = file->hdr.file_seq;
	old_sync_offset = file->sync_offset;

	/* Simulate a transaction that another process couldn't write fully */
	path = t_strconcat(test_mail_index_get_dir(),
			   "/test.dovecot.index.log", NULL);
	fd = open(path, O_RDWR | O_APPEND);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);
	test_assert_cmp(write_full(fd, garbage, sizeof(garbage)), ==, 0);
	i_close_fd(&fd);

	/* Syncing must rotate the log instead of truncating the garbage
	   away. */
	test_assert_cmp(mail_index_sync_begin(index, &sync_ctx, &sync_view,
					      &sync_trans, 0), >=, 0);
	if (sync_ctx != NULL)
		test_assert_cmp(mail_index_sync_commit(&sync_ctx), ==, 0);

	file = index->log->head;
	test_assert_ucmp(file->hdr.file_seq, ==, old_file_seq + 1);
	test_assert_ucmp(file->hdr.prev_file_seq, ==, old_file_seq);
	test_assert_ucmp(file->hdr.prev_file_offset, ==, old_sync_offset);
	test_assert(!file->garbage_at_eof);

	/* The old log still has the partially written transaction */
	path = t_strconcat(test_mail_index_get_dir(),
			   "/test.dovecot.index.log.2", NULL);
	if (stat(path, &st) < 0)
		i_fatal("stat(%s) failed: %m", path);
	test_assert_ucmp((uoff_t)st.st_size, ==,
			 old_sync_offset + sizeof(garbage));

	/* Appending works again */
	view = mail_index_view_open(index);
	trans = mail_index_transaction_begin(view,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mail_index_append(trans, 2, &seq);
	test_assert_cmp(mail_index_transaction_commit(&trans), ==, 0);
	mail_index_view_close(&view);
	test_assert_ucmp(index->log->head->hdr.file_seq, ==, old_file_seq + 1);

	test_mail_index_deinit(&index);
	test_end();
}

static void test_mail_index_log_rotate_at_close(void)
{
	static const unsigned char garbage[8] = { 0 };
	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	struct mail_transaction_log_file *file;
	const char *path;
	uoff_t old_sync_offset;
	uint32_t seq, old_file_seq;
	int fd;

	test_begin("mail index log rotate at close");
	index = test_mail_index_init(TRUE);

	uint32_t uid_validity = 123456;
	view = mail_index_view_open(index);
	trans = mail_index_transaction_begin(view,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);
	mail_index_append(trans, 1, &seq);
	test_assert_cmp(mail_index_transaction_commit(&trans), ==, 0);
	mail_index_view_close(&view);

	file = index->log->head;
	old_file_seq = file->hdr.file_seq;
	old_sync_offset = file->sync_offset;

	path = t_strconcat(test_mail_index_get_dir(),
			   "/test.dovecot.index.log", NULL);
	fd = open(path, O_RDWR | O_APPEND);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);
	test_assert_cmp(write_full(fd, garbage, sizeof(garbage)), ==, 0);
	i_close_fd(&fd);

	/* Simulate this process having failed to fully write the transaction.
	   The rotation must not be left for the next process, which couldn't
	   append to the log either. */
	mail_transaction_log_file_set_garbage_at_eof(file, "test");
	test_mail_index_close(&index);

	index = test_mail_index_open(FALSE);
	test_assert_ucmp(index->log->head->hdr.file_seq, ==, old_file_seq + 1);
	test_assert_ucmp(index->log->head->hdr.prev_file_seq, ==, old_file_seq);
	test_assert_ucmp(index->log->head->hdr.prev_file_offset, ==,
			 old_sync_offset);

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

static void
test_mail_index_sync_add_flag(struct mail_index *index, uint32_t seq,
			      enum mail_flags flag)
{
	struct mail_index_view *view;
	struct mail_index_transaction *trans;

	view = mail_index_view_open(index);
	trans = mail_index_transaction_begin(view, 0);
	mail_index_update_flags(trans, seq, MODIFY_ADD, flag);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(&view);
}

/* Read all the sync records. Returns the number of records. If there was
   exactly one record, its first UID is returned in uid_r. */
static unsigned int
test_mail_index_sync_read(struct mail_index_sync_ctx *sync_ctx, uint32_t *uid_r)
{
	struct mail_index_sync_rec sync_rec;
	unsigned int count = 0;

	*uid_r = 0;
	while (mail_index_sync_next(sync_ctx, &sync_rec)) {
		test_assert(sync_rec.type == MAIL_INDEX_SYNC_TYPE_FLAGS);
		*uid_r = sync_rec.uid1;
		count++;
	}
	return count;
}

static void
test_mail_index_sync_full(struct mail_index *index,
			  unsigned int expected_count, uint32_t expected_uid)
{
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	uint32_t uid;

	test_assert(mail_index_sync_begin(index, &sync_ctx, &view, &trans,
					  0) == 1);
	test_assert(test_mail_index_sync_read(sync_ctx, &uid) == expected_count);
	if (expected_count == 1)
		test_assert(uid == expected_uid);
	test_assert(mail_index_sync_commit(&sync_ctx) == 0);
}

static struct mail_index *test_mail_index_sync_init(void)
{
	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	uint32_t seq, uid_validity = 1;

	index = test_mail_index_init(TRUE);
	view = mail_index_view_open(index);
	trans = mail_index_transaction_begin(view, 0);
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);
	mail_index_append(trans, 1, &seq);
	mail_index_append(trans, 2, &seq);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(&view);

	test_mail_index_sync_full(index, 0, 0);
	return index;
}

static void test_mail_index_sync_read_only(void)
{
	struct mail_index *index;
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	uint32_t uid, log_seq, seq1, seq2;
	uoff_t log_offset, offset1, offset2;

	test_begin("mail index sync read-only");
	index = test_mail_index_sync_init();
	test_mail_index_sync_add_flag(index, 1, MAIL_SEEN);
	mail_transaction_log_get_head(index->log, &log_seq, &log_offset);

	test_assert(mail_index_sync_begin(index, &sync_ctx, &view, &trans,
					  MAIL_INDEX_SYNC_FLAG_READ_ONLY) == 1);
	test_assert(!mail_index_is_locked(index));
	/* the transaction log can be written to during the sync, but the
	   sync doesn't see the change */
	test_mail_index_sync_add_flag(index, 2, MAIL_FLAGGED);
	test_assert(test_mail_index_sync_read(sync_ctx, &uid) == 1);
	test_assert(uid == 1);
	mail_index_sync_get_offsets(sync_ctx, &seq1, &offset1, &seq2, &offset2);
	test_assert(seq2 == log_seq && offset2 == log_offset);
	mail_index_sync_rollback(&sync_ctx);

	/* the changes are still waiting to be synced */
	test_mail_index_sync_full(index, 2, 0);
	test_mail_index_sync_full(index, 0, 0);

	test_mail_index_deinit(&index);
	test_end();
}

/* Write the index with a tail offset beyond the head offset and close it */
static void test_mail_index_sync_break_tail_offset(struct mail_index **index)
{
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	const char *idx_path;
	uint32_t tail_offset;
	int fd;

	test_assert(mail_index_sync_begin(*index, &sync_ctx, &view, &trans,
					  0) == 1);
	mail_index_write(*index, FALSE, "test");
	test_assert(mail_index_sync_commit(&sync_ctx) == 0);
	tail_offset = (*index)->map->hdr.log_file_head_offset + 100;
	test_mail_index_close(index);

	idx_path = t_strconcat(test_mail_index_get_dir(),
			       "/test.dovecot.index", NULL);
	fd = open(idx_path, O_RDWR);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", idx_path);
	if (pwrite(fd, &tail_offset, sizeof(tail_offset),
		   offsetof(struct mail_index_header,
			    log_file_tail_offset)) != (ssize_t)sizeof(tail_offset))
		i_fatal("pwrite(%s) failed: %m", idx_path);
	i_close_fd(&fd);
}

static void test_mail_index_sync_read_only_fsck(void)
{
	struct mail_index *index;
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	const struct mail_index_header *hdr;
	uint32_t uid;

	test_begin("mail index sync read-only fsck");
	index = test_mail_index_sync_init();
	test_mail_index_sync_add_flag(index, 1, MAIL_SEEN);
	test_mail_index_sync_break_tail_offset(&index);

	/* the broken sync positions are fixed even though the sync doesn't
	   otherwise lock the transaction log */
	index = test_mail_index_open(FALSE);
	test_expect_errors(3);
	test_assert(mail_index_sync_begin(index, &sync_ctx, &view, &trans,
					  MAIL_INDEX_SYNC_FLAG_READ_ONLY) == 1);
	test_expect_no_more_errors();
	test_assert(!mail_index_is_locked(index));
	hdr = &index->map->hdr;
	test_assert(hdr->log_file_tail_offset <= hdr->log_file_head_offset);
	test_assert(test_mail_index_sync_read(sync_ctx, &uid) == 0);
	mail_index_sync_rollback(&sync_ctx);
	test_mail_index_close(&index);

	/* the fsck fails if the transaction log can't be locked */
	index = test_mail_index_sync_init();
	test_mail_index_sync_add_flag(index, 1, MAIL_SEEN);
	test_mail_index_sync_break_tail_offset(&index);
	index = mail_index_alloc(NULL, test_mail_index_get_dir(),
				 "test.dovecot.index");
	test_assert(mail_index_open(index, MAIL_INDEX_OPEN_FLAG_READONLY) == 1);
	test_expect_errors(3);
	test_assert(mail_index_sync_begin(index, &sync_ctx, &view, &trans,
					  MAIL_INDEX_SYNC_FLAG_READ_ONLY) < 0);
	test_expect_no_more_errors();
	test_assert(!mail_index_is_locked(index));

	test_mail_index_deinit(&index);
	test_end();
}

static void test_mail_index_sync_stop_at_offset(void)
{
	struct mail_index *index;
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	const struct mail_index_header *hdr;
	uint32_t log_seq, uid, seq1, seq2;
	uoff_t log_offset, offset1, offset2;

	test_begin("mail index sync stop at offset");
	index = test_mail_index_sync_init();

	/* nothing to sync - the sync is still started */
	mail_transaction_log_get_head(index->log, &log_seq, &log_offset);
	test_assert(mail_index_sync_begin_to(index, &sync_ctx, &view, &trans,
			log_seq, log_offset,
			MAIL_INDEX_SYNC_FLAG_STOP_AT_OFFSET) == 1);
	test_assert(test_mail_index_sync_read(sync_ctx, &uid) == 0);
	test_assert(mail_index_sync_commit(&sync_ctx) == 0);

	test_mail_index_sync_add_flag(index, 1, MAIL_SEEN);
	mail_transaction_log_get_head(index->log, &log_seq, &log_offset);
	test_mail_index_sync_add_flag(index, 2, MAIL_FLAGGED);

	/* only the change before the offset is synced */
	test_assert(mail_index_sync_begin_to(index, &sync_ctx, &view, &trans,
			log_seq, log_offset,
			MAIL_INDEX_SYNC_FLAG_STOP_AT_OFFSET) == 1);
	mail_index_sync_get_offsets(sync_ctx, &seq1, &offset1, &seq2, &offset2);
	test_assert(seq2 == log_seq && offset2 == log_offset);
	test_assert(test_mail_index_sync_read(sync_ctx, &uid) == 1);
	test_assert(uid == 1);
	test_assert(mail_index_sync_commit(&sync_ctx) == 0);

	hdr = &index->map->hdr;
	test_assert(hdr->log_file_seq == log_seq);
	test_assert(hdr->log_file_tail_offset == log_offset);

	/* the change after the offset is synced by the next sync */
	test_mail_index_sync_full(index, 1, 2);

	/* the offset is already synced */
	test_assert(mail_index_sync_begin_to(index, &sync_ctx, &view, &trans,
			log_seq, log_offset,
			MAIL_INDEX_SYNC_FLAG_STOP_AT_OFFSET) == 1);
	test_assert(test_mail_index_sync_read(sync_ctx, &uid) == 0);
	test_assert(mail_index_sync_commit(&sync_ctx) == 0);

	test_mail_index_deinit(&index);
	test_end();
}

static void test_mail_index_sync_stop_at_offset_write(bool rotate)
{
	struct mail_index *index, *index2;
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	uint32_t log_seq, uid;
	uoff_t log_offset;

	test_begin(rotate ? "mail index sync stop at offset rotate" :
		   "mail index sync stop at offset write");
	index = test_mail_index_sync_init();
	/* make the sync want to rewrite the index or rotate the log */
	if (rotate)
		index->optimization_set.log.max_size = 0;
	else
		index->optimization_set.index.rewrite_max_log_bytes = 0;

	test_mail_index_sync_add_flag(index, 1, MAIL_SEEN);
	mail_transaction_log_get_head(index->log, &log_seq, &log_offset);
	test_mail_index_sync_add_flag(index, 2, MAIL_FLAGGED);

	test_assert(mail_index_sync_begin_to(index, &sync_ctx, &view, &trans,
			log_seq, log_offset,
			MAIL_INDEX_SYNC_FLAG_STOP_AT_OFFSET) == 1);
	test_assert(test_mail_index_sync_read(sync_ctx, &uid) == 1);
	test_assert(uid == 1);
	test_assert(mail_index_sync_commit(&sync_ctx) == 0);

	/* another process still sees the change after the offset */
	index2 = test_mail_index_open(FALSE);
	test_mail_index_sync_full(index2, 1, 2);
	test_mail_index_deinit(&index2);

	test_mail_index_deinit(&index);
	test_end();
}

static void test_mail_index_sync_stop_at_offset_index_write(void)
{
	test_mail_index_sync_stop_at_offset_write(FALSE);
}

static void test_mail_index_sync_stop_at_offset_rotate(void)
{
	test_mail_index_sync_stop_at_offset_write(TRUE);
}

static void test_mail_index_sync_stop_at_offset_log_garbage(void)
{
	static const unsigned char garbage[8] = { 0 };
	struct mail_index *index;
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	const char *path;
	uint32_t log_seq, old_file_seq, uid;
	uoff_t log_offset;
	int fd;

	test_begin("mail index sync stop at offset log garbage");
	index = test_mail_index_sync_init();
	old_file_seq = index->log->head->hdr.file_seq;

	test_mail_index_sync_add_flag(index, 1, MAIL_SEEN);
	mail_transaction_log_get_head(index->log, &log_seq, &log_offset);
	test_mail_index_sync_add_flag(index, 2, MAIL_FLAGGED);

	/* Simulate a transaction that another process couldn't write fully */
	path = t_strconcat(test_mail_index_get_dir(),
			   "/test.dovecot.index.log", NULL);
	fd = open(path, O_RDWR | O_APPEND);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);
	test_assert(write_full(fd, garbage, sizeof(garbage)) == 0);
	i_close_fd(&fd);

	/* The log needs to be rotated, but the sync would stop in the old
	   log file. */
	test_assert(mail_index_sync_begin_to(index, &sync_ctx, &view, &trans,
			log_seq, log_offset,
			MAIL_INDEX_SYNC_FLAG_STOP_AT_OFFSET) == 0);
	test_assert(index->log->head->hdr.file_seq == old_file_seq);
	test_assert(!mail_index_is_locked(index));

	/* Syncing up to the head rotates the log */
	mail_transaction_log_get_head(index->log, &log_seq, &log_offset);
	test_assert(mail_index_sync_begin_to(index, &sync_ctx, &view, &trans,
			log_seq, log_offset,
			MAIL_INDEX_SYNC_FLAG_STOP_AT_OFFSET) == 1);
	test_assert(index->log->head->hdr.file_seq == old_file_seq + 1);
	test_assert(test_mail_index_sync_read(sync_ctx, &uid) == 2);
	test_assert(mail_index_sync_commit(&sync_ctx) == 0);

	/* nothing is left to sync */
	test_mail_index_sync_full(index, 0, 0);

	test_mail_index_deinit(&index);
	test_end();
}

static bool
test_mail_index_has_keyword(struct mail_index *index, uint32_t seq,
			    unsigned int idx)
{
	struct mail_index_view *view;
	ARRAY_TYPE(keyword_indexes) keywords;
	const unsigned int *kw_idx;
	bool found = FALSE;

	t_array_init(&keywords, 4);
	test_assert(mail_index_refresh(index) == 0);
	view = mail_index_view_open(index);
	mail_index_lookup_keywords(view, seq, &keywords);
	array_foreach(&keywords, kw_idx) {
		if (*kw_idx == idx)
			found = TRUE;
	}
	mail_index_view_close(&view);
	return found;
}

static void test_mail_index_keyword_update_avoid_after_replace(void)
{
	static const char *const kw_names[] = { "foo", NULL };
	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	struct mail_keywords *keywords, *no_keywords;

	test_begin("mail index keyword update after replace with AVOID_FLAG_UPDATES");
	index = test_mail_index_sync_init();
	keywords = mail_index_keywords_create(index, kw_names);
	no_keywords = mail_index_keywords_create(index, NULL);

	view = mail_index_view_open(index);
	trans = mail_index_transaction_begin(view, 0);
	mail_index_update_keywords(trans, 1, MODIFY_ADD, keywords);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(&view);
	test_assert(test_mail_index_has_keyword(index, 1, keywords->idx[0]));

	/* Replacing the keywords removes "foo", but adding it back within
	   the same transaction must cancel the removal, even though the index
	   already has it. */
	view = mail_index_view_open(index);
	trans = mail_index_transaction_begin(view,
		MAIL_INDEX_TRANSACTION_FLAG_AVOID_FLAG_UPDATES);
	mail_index_update_keywords(trans, 1, MODIFY_REPLACE, no_keywords);
	mail_index_update_keywords(trans, 1, MODIFY_ADD, keywords);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(&view);
	test_assert(test_mail_index_has_keyword(index, 1, keywords->idx[0]));

	/* The same with removing a keyword that the index doesn't have
	   after adding it within the same transaction. */
	view = mail_index_view_open(index);
	trans = mail_index_transaction_begin(view,
		MAIL_INDEX_TRANSACTION_FLAG_AVOID_FLAG_UPDATES);
	mail_index_update_keywords(trans, 2, MODIFY_REPLACE, keywords);
	mail_index_update_keywords(trans, 2, MODIFY_REMOVE, keywords);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(&view);
	test_assert(!test_mail_index_has_keyword(index, 2, keywords->idx[0]));

	mail_index_keywords_unref(&keywords);
	mail_index_keywords_unref(&no_keywords);
	test_mail_index_deinit(&index);
	test_end();
}

static void
test_mail_index_verify_records_corrupt(uint32_t seq, uint32_t uid,
				       uint32_t expected_messages_count)
{
	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	struct mail_index_sync_ctx *sync_ctx;
	uint32_t seq2;

	index = test_mail_index_init(TRUE);
	view = mail_index_view_open(index);
	trans = mail_index_transaction_begin(view,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	uint32_t uid_validity = 1234;
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);
	for (uint32_t i = 1; i <= 3; i++)
		mail_index_append(trans, i * 10, &seq2);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(&view);

	/* write dovecot.index */
	test_assert(mail_index_sync_begin(index, &sync_ctx, &view, &trans, 0) > 0);
	mail_index_write(index, FALSE, "test");
	test_assert(mail_index_sync_commit(&sync_ctx) == 0);
	uoff_t rec_offset = index->map->hdr.header_size +
		(seq - 1) * index->map->hdr.record_size;
	test_mail_index_close(&index);

	/* corrupt the record's UID */
	const char *path = t_strconcat(test_mail_index_get_dir(),
				       "/test.dovecot.index", NULL);
	int fd = open(path, O_RDWR);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);
	test_assert(pwrite(fd, &uid, sizeof(uid), rec_offset +
			   offsetof(struct mail_index_record, uid)) ==
		    sizeof(uid));
	i_close_fd(&fd);

	/* opening doesn't notice the corruption */
	index = test_mail_index_open(FALSE);
	test_assert(index->map->hdr.messages_count == 3);

	/* the corruption error, fscking warning and 2 fsck errors */
	test_expect_errors(4);
	test_assert(mail_index_verify_records(index) == 0);
	test_expect_no_more_errors();
	test_assert(mail_index_reset_fscked(index));
	test_assert_ucmp(index->map->hdr.messages_count, ==,
			 expected_messages_count);

	/* verifying again finds no errors */
	test_assert(mail_index_verify_records(index) == 1);
	test_assert(!mail_index_reset_fscked(index));
	test_mail_index_deinit(&index);
}

static void test_mail_index_verify_records(void)
{
	test_begin("mail index verify records");
	/* valid index */
	struct mail_index *index = test_mail_index_init(TRUE);
	test_assert(mail_index_verify_records(index) == 1);
	test_assert(!mail_index_reset_fscked(index));
	test_mail_index_deinit(&index);

	/* UID=0 */
	test_mail_index_verify_records_corrupt(1, 0, 2);
	/* UIDs 10, 5, 30 */
	test_mail_index_verify_records_corrupt(2, 5, 2);
	/* UIDs 10, 30, 30 */
	test_mail_index_verify_records_corrupt(2, 30, 2);
	test_end();
}

static struct mail_index *test_mail_index_open_zero_uids(void)
{
	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	struct mail_index_sync_ctx *sync_ctx;
	uint32_t seq;

	index = test_mail_index_init(TRUE);
	view = mail_index_view_open(index);
	trans = mail_index_transaction_begin(view,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	uint32_t uid_validity = 1234;
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);
	for (uint32_t uid = 1; uid <= 4; uid++)
		mail_index_append(trans, uid, &seq);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(&view);

	/* write dovecot.index */
	test_assert(mail_index_sync_begin(index, &sync_ctx, &view,
					  &trans, 0) > 0);
	mail_index_write(index, FALSE, "test");
	test_assert(mail_index_sync_commit(&sync_ctx) == 0);
	uoff_t hdr_size = index->map->hdr.header_size;
	uoff_t record_size = index->map->hdr.record_size;
	test_mail_index_close(&index);

	/* set the UIDs of seqs 1 and 3 to 0 */
	const char *path = t_strconcat(test_mail_index_get_dir(),
				       "/test.dovecot.index", NULL);
	int fd = open(path, O_RDWR);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);
	uint32_t uid = 0;
	for (seq = 1; seq <= 3; seq += 2) {
		uoff_t offset = hdr_size + (seq - 1) * record_size +
			offsetof(struct mail_index_record, uid);
		test_assert(pwrite(fd, &uid, sizeof(uid), offset) ==
			    sizeof(uid));
	}
	i_close_fd(&fd);

	/* opening doesn't notice the corruption */
	return test_mail_index_open(FALSE);
}

static void test_mail_index_commit_zero_uids(void)
{
	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;

	test_begin("mail index commit updates to uid=0 records");
	/* flag update range covering uid=0 records and a valid record */
	index = test_mail_index_open_zero_uids();
	view = mail_index_view_open(index);
	trans = mail_index_transaction_begin(view, 0);
	mail_index_update_flags_range(trans, 1, 3, MODIFY_ADD, MAIL_SEEN);
	/* the corruption error, fscking warning and 2 fsck errors */
	test_expect_errors(4);
	test_assert(mail_index_transaction_commit(&trans) < 0);
	test_expect_no_more_errors();
	test_assert(mail_index_reset_fscked(index));
	mail_index_view_close(&view);

	/* fsck dropped the uid=0 records */
	view = mail_index_view_open(index);
	test_assert(mail_index_view_get_messages_count(view) == 2);
	trans = mail_index_transaction_begin(view, 0);
	mail_index_update_flags_range(trans, 1, 2, MODIFY_ADD, MAIL_SEEN);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	mail_index_view_close(&view);
	test_mail_index_deinit(&index);

	/* separate flag updates to two uid=0 records */
	index = test_mail_index_open_zero_uids();
	view = mail_index_view_open(index);
	trans = mail_index_transaction_begin(view, 0);
	mail_index_update_flags(trans, 1, MODIFY_ADD, MAIL_SEEN);
	mail_index_update_flags(trans, 3, MODIFY_ADD, MAIL_SEEN);
	test_expect_errors(4);
	test_assert(mail_index_transaction_commit(&trans) < 0);
	test_expect_no_more_errors();
	mail_index_view_close(&view);
	test_mail_index_deinit(&index);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_index_rotate,
		test_mail_index_log_refresh_rotation_race,
		test_mail_index_log_rotate_max_file_seq,
		test_mail_index_new_extension,
		test_mail_index_corruption_message_count,
		test_mail_index_corruption_record_size_zero,
		test_mail_index_log_garbage_at_eof,
		test_mail_index_log_rotate_at_close,
		test_mail_index_map_fsck_fail_restores_map,
		test_mail_index_sync_read_only,
		test_mail_index_sync_read_only_fsck,
		test_mail_index_sync_stop_at_offset,
		test_mail_index_sync_stop_at_offset_index_write,
		test_mail_index_sync_stop_at_offset_rotate,
		test_mail_index_sync_stop_at_offset_log_garbage,
		test_mail_index_keyword_update_avoid_after_replace,
		test_mail_index_verify_records,
		test_mail_index_commit_zero_uids,
		NULL
	};
	test_dir_init("mail-index");
	return test_run(test_functions);
}
