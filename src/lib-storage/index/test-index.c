/* Copyright Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "test-common.h"
#include "test-dir.h"
#include "master-service.h"
#include "test-mail-storage-common.h"
#include "mail-storage-private.h"
#include "index/index-storage.h"
#include "index/index-mailbox-size.h"

static void test_mail_save(struct mailbox *box, const char *mail_input)
{
	struct mailbox_transaction_context *trans;
	struct mail_save_context *save_ctx;
	struct istream *input;
	int ret;

	input = i_stream_create_from_data(mail_input, strlen(mail_input));
	trans = mailbox_transaction_begin(box,
			MAILBOX_TRANSACTION_FLAG_EXTERNAL, __func__);
	save_ctx = mailbox_save_alloc(trans);
	test_assert(mailbox_save_begin(&save_ctx, input) == 0);
	while ((ret = i_stream_read(input)) > 0) ;
	test_assert(ret == -1);
	test_assert(mailbox_save_finish(&save_ctx) == 0);
	i_stream_unref(&input);
	test_assert(mailbox_transaction_commit(&trans) == 0);
	test_assert(mailbox_sync(box, 0) == 0);
}

static void test_vsize_hdr_corruption_fix(void)
{
	struct test_mail_storage_ctx *ctx;
	const struct mail_namespace *ns;
	struct mailbox *box;
	struct mail_index_view *view;
	const void *data;
	size_t size;

	test_begin("vsize header corruption fix");

	ctx = test_mail_storage_init();
	const struct test_mail_storage_settings set = {
		.driver = "maildir",
		.hierarchy_sep = "/",
	};
	test_mail_storage_init_user(ctx, &set);

	ns = mail_namespace_find_inbox(ctx->user->namespaces);
	box = mailbox_alloc(ns->list, "vsize-test", 0);
	test_assert(mailbox_create(box, NULL, FALSE) == 0);
	test_assert(mailbox_open(box) == 0);
	test_assert(mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) == 0);

	/* write corrupted header */
	struct mail_index_transaction *trans =
		mail_index_transaction_begin(box->view,
					     MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	char corrupted_hdr[44];
	i_zero(&corrupted_hdr);
	memcpy(corrupted_hdr, "corrupted", 9);
	mail_index_update_header_ext(trans, box->vsize_hdr_ext_id, 0,
				     corrupted_hdr, sizeof(corrupted_hdr));
	test_assert(mail_index_transaction_commit(&trans) == 0);

	/* close and reopen the box to trigger the fix */
	test_expect_errors(2);
	mailbox_free(&box);
	box = mailbox_alloc(ns->list, "vsize-test", 0);
	test_assert(mailbox_open(box) == 0);
	index_mailbox_vsize_update_appends(box);
	mailbox_free(&box);

	/* reopen one last time to verify fix on disk */
	box = mailbox_alloc(ns->list, "vsize-test", 0);
	test_assert(mailbox_open(box) == 0);

	/* verify the fix */
	(void)mail_index_refresh(box->index);
	view = mail_index_view_open(box->index);
	mail_index_get_header_ext(view, box->vsize_hdr_ext_id, &data, &size);

	test_assert(size == sizeof(struct mailbox_index_vsize));
	struct mailbox_index_vsize empty_hdr;
	i_zero(&empty_hdr);
	test_assert(memcmp(data, &empty_hdr, sizeof(empty_hdr)) == 0);

	mail_index_view_close(&view);
	mailbox_free(&box);
	test_mail_storage_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);

	test_end();
}

static void test_vsize_hdr_msg_count_corruption_fix(void)
{
	struct test_mail_storage_ctx *ctx;
	const struct mail_namespace *ns;
	struct mailbox *box;
	struct mail_index_view *view;
	const void *data;
	size_t size;
	uint32_t uid2;

	test_begin("vsize header message count corruption fix");

	ctx = test_mail_storage_init();
	const struct test_mail_storage_settings set = {
		.driver = "maildir",
		.hierarchy_sep = "/",
	};
	test_mail_storage_init_user(ctx, &set);

	ns = mail_namespace_find_inbox(ctx->user->namespaces);
	box = mailbox_alloc(ns->list, "vsize-msg-count-test", 0);
	test_assert(mailbox_create(box, NULL, FALSE) == 0);
	test_assert(mailbox_open(box) == 0);
	test_assert(mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) == 0);

	test_mail_save(box, "From: foo\n\nbar\n");
	test_mail_save(box, "From: bar\n\nbaz\n");

	struct mailbox_status status;
	mailbox_get_open_status(box, STATUS_UIDNEXT, &status);
	uid2 = status.uidnext - 1;

	/* Create a valid vsize header with message_count == 2 */
	{
		struct mail_index_transaction *trans;
		struct mailbox_index_vsize valid_hdr;
		i_zero(&valid_hdr);
		valid_hdr.vsize = 100;
		valid_hdr.highest_uid = uid2;
		valid_hdr.message_count = 2;
		trans = mail_index_transaction_begin(box->view,
					     MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
		mail_index_update_header_ext(trans, box->vsize_hdr_ext_id, 0,
					     &valid_hdr, sizeof(valid_hdr));
		test_assert(mail_index_transaction_commit(&trans) == 0);
	}

	/* Verify we have 2 messages in vsize header */
	(void)mail_index_refresh(box->index);
	view = mail_index_view_open(box->index);
	mail_index_get_header_ext(view, box->vsize_hdr_ext_id, &data, &size);
	test_assert(size == sizeof(struct mailbox_index_vsize));
	const struct mailbox_index_vsize *vsize_hdr = data;
	test_assert(vsize_hdr->message_count == 2);
	test_assert(vsize_hdr->highest_uid == uid2);
	mail_index_view_close(&view);

	/* Write corrupted header: message_count = 1, but highest_uid is still uid2 */
	struct mail_index_transaction *trans =
		mail_index_transaction_begin(box->view,
					     MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	struct mailbox_index_vsize corrupted_vsize;
	corrupted_vsize.vsize = 100; /* dummy */
	corrupted_vsize.highest_uid = uid2;
	corrupted_vsize.message_count = 1;
	mail_index_update_header_ext(trans, box->vsize_hdr_ext_id, 0,
				     &corrupted_vsize, sizeof(corrupted_vsize));
	test_assert(mail_index_transaction_commit(&trans) == 0);

	/* Close and reopen to trigger the fix in index_mailbox_vsize_check_rebuild */
	test_expect_errors(2); /* vsize-hdr has invalid message-count (1 < 2) twice */
	mailbox_free(&box);
	box = mailbox_alloc(ns->list, "vsize-msg-count-test", 0);
	test_assert(mailbox_open(box) == 0);
	index_mailbox_vsize_update_appends(box);
	mailbox_free(&box);

	/* Reopen one last time to verify fix on disk */
	box = mailbox_alloc(ns->list, "vsize-msg-count-test", 0);
	test_assert(mailbox_open(box) == 0);

	/* verify the fix */
	(void)mail_index_refresh(box->index);
	view = mail_index_view_open(box->index);
	mail_index_get_header_ext(view, box->vsize_hdr_ext_id, &data, &size);

	test_assert(size == sizeof(struct mailbox_index_vsize));
	vsize_hdr = data;
	test_assert(vsize_hdr->message_count == 2);
	test_assert(vsize_hdr->highest_uid == uid2);

	mail_index_view_close(&view);
	mailbox_free(&box);
	test_mail_storage_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);

	test_end();
}

int main(int argc, char *argv[])
{
	static void (* const test_functions[])(void) = {
		test_vsize_hdr_corruption_fix,
		test_vsize_hdr_msg_count_corruption_fix,
		NULL
	};

	master_service = master_service_init("test-index",
					     MASTER_SERVICE_FLAG_STANDALONE |
					     MASTER_SERVICE_FLAG_DONT_SEND_STATS |
					     MASTER_SERVICE_FLAG_CONFIG_BUILTIN |
					     MASTER_SERVICE_FLAG_NO_SSL_INIT |
					     MASTER_SERVICE_FLAG_NO_INIT_DATASTACK_FRAME,
					     &argc, &argv, "");
	test_dir_init("test-index");
	int ret = test_run(test_functions);

	master_service_deinit(&master_service);

	return ret;
}
