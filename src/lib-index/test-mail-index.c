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
	index = test_mail_index_init();
	index2 = test_mail_index_open();
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
	index = test_mail_index_init();
	index2 = test_mail_index_open();
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

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_index_rotate,
		test_mail_index_new_extension,
		NULL
	};
	return test_run(test_functions);
}
