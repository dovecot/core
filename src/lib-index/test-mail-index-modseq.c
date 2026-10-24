/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "test-common.h"
#include "test-mail-index.h"
#include "mail-index-modseq.h"
#include "mail-transaction-log-private.h"

static void test_mail_index_modseq_get_next_log_offset(void)
{
	static const struct {
		uint32_t log_seq;
		uoff_t log_offset;
	} tests[] = {
		{ 0, 0 },
		{ 2, 40 },
		{ 2, 148 },
		{ 2, 164 },
		{ 3, 40 },
		{ 3, 56 },
		{ 3, 72 },
		{ 3, 88 },
	};
	struct mail_index *index;
	struct mail_index_view *view, *view2;
	struct mail_index_transaction *trans;
	uint32_t seq, uid;

	test_begin("mail_transaction_log_file_get_modseq_next_offset()");
	index = test_mail_index_init(TRUE);
	view = mail_index_view_open(index);
	mail_index_modseq_enable(index);

	trans = mail_index_transaction_begin(view, 0);
	uid = 1234;
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid, sizeof(uid), TRUE);
	test_assert(mail_index_transaction_commit(&trans) == 0);

	for (uid = 1; uid <= 3; uid++) {
		trans = mail_index_transaction_begin(view, 0);
		mail_index_append(trans, uid, &seq);
		test_assert(mail_index_transaction_commit(&trans) == 0);
	}
	test_assert(mail_transaction_log_file_lock(index->log->head) == 0);
	test_assert(mail_transaction_log_rotate(index->log, FALSE) == 0);
	mail_transaction_log_file_unlock(index->log->head, "rotating");
	for (uid = 4; uid <= 6; uid++) {
		trans = mail_index_transaction_begin(view, 0);
		mail_index_append(trans, uid, &seq);
		test_assert(mail_index_transaction_commit(&trans) == 0);
	}

	view2 = mail_index_view_open(index);
	for (uint64_t modseq = 1; modseq <= 7; modseq++) {
		uint32_t log_seq = 0;
		uoff_t log_offset;

		test_assert_idx(mail_index_modseq_get_next_log_offset(view2, modseq, &log_seq, &log_offset) == (tests[modseq].log_seq != 0), modseq);
		test_assert_idx(tests[modseq].log_seq == log_seq && tests[modseq].log_offset == log_offset, modseq);
	}

	mail_index_view_close(&view);
	mail_index_view_close(&view2);
	test_mail_index_deinit(&index);
	test_end();
}

static void test_mail_index_modseq_enable_broken_hdr_size(void)
{
	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	const struct mail_index_modseq_header *modseq_hdr;
	uint32_t seq, uid;

	test_begin("mail_index_modseq_enable() with broken header size");
	index = test_mail_index_init(TRUE);
	view = mail_index_view_open(index);
	mail_index_modseq_enable(index);
	test_assert(mail_index_have_modseq_tracking(index));

	trans = mail_index_transaction_begin(view, 0);
	uid = 1234;
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid, sizeof(uid), TRUE);
	mail_index_append(trans, 1, &seq);
	test_assert(mail_index_transaction_commit(&trans) == 0);

	/* corrupt the modseq header size */
	trans = mail_index_transaction_begin(view, 0);
	mail_index_ext_resize_hdr(trans, index->modseq_ext_id, 8);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	test_assert(!mail_index_have_modseq_tracking(index));

	/* enabling modseqs fixes the header size */
	mail_index_modseq_enable(index);
	test_assert(mail_index_have_modseq_tracking(index));
	modseq_hdr = mail_index_map_get_modseq_header(index->map);
	uint64_t highest_modseq = modseq_hdr->highest_modseq;
	test_assert(highest_modseq > 0);

	/* the header is updated again */
	trans = mail_index_transaction_begin(view, 0);
	mail_index_append(trans, 2, &seq);
	test_assert(mail_index_transaction_commit(&trans) == 0);
	modseq_hdr = mail_index_map_get_modseq_header(index->map);
	test_assert(modseq_hdr->highest_modseq > highest_modseq);

	mail_index_view_close(&view);
	test_mail_index_deinit(&index);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_index_modseq_get_next_log_offset,
		test_mail_index_modseq_enable_broken_hdr_size,
		NULL
	};
	test_dir_init("mail-index-modseq");
	return test_run(test_functions);
}
