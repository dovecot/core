/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "test-common.h"
#include "mail-index-modseq.h"
#include "index-storage.h"

static uint32_t expunge_uids[] = { 25, 15, 7, 3, 11, 1, 53, 33 };
static uint8_t mail_guids[N_ELEMENTS(expunge_uids)][MAIL_GUID_128_SIZE];
static unsigned int expunge_idx;
static unsigned int nonexternal_idx;

void mail_index_lookup_uid(struct mail_index_view *view ATTR_UNUSED,
			   uint32_t seq, uint32_t *uid_r)
{
	*uid_r = seq;
}

bool mail_index_lookup_seq_range(struct mail_index_view *view ATTR_UNUSED,
				 uint32_t first_uid, uint32_t last_uid,
				 uint32_t *first_seq_r, uint32_t *last_seq_r)
{
	*first_seq_r = first_uid;
	*last_seq_r = last_uid;
	return TRUE;
}

bool mail_index_modseq_get_next_log_offset(struct mail_index_view *view ATTR_UNUSED,
					   uint64_t modseq, uint32_t *log_seq_r,
					   uoff_t *log_offset_r)
{
	*log_seq_r = modseq >> 32;
	*log_offset_r = modseq & 0xfffffff;
	return TRUE;
}

struct mail_transaction_log_view *
mail_transaction_log_view_open(struct mail_transaction_log *log ATTR_UNUSED) { return NULL; }
int mail_transaction_log_view_set(struct mail_transaction_log_view *view ATTR_UNUSED,
				  uint32_t min_file_seq ATTR_UNUSED, uoff_t min_file_offset ATTR_UNUSED,
				  uint32_t max_file_seq ATTR_UNUSED, uoff_t max_file_offset ATTR_UNUSED,
				  bool *reset_r ATTR_UNUSED) {
	if (min_file_seq < 99)
		return 0;
	return 1;
}

void mail_transaction_log_view_close(struct mail_transaction_log_view **view ATTR_UNUSED) { }

void mail_transaction_log_get_tail(struct mail_transaction_log *log ATTR_UNUSED,
				   uint32_t *file_seq_r)
{
	*file_seq_r = 100;
}

int mail_transaction_log_view_next(struct mail_transaction_log_view *view ATTR_UNUSED,
				   const struct mail_transaction_header **hdr_r,
				   const void **data_r)
{
	static struct mail_transaction_header hdr;
	static struct mail_transaction_expunge_guid exp;
	static struct mail_transaction_expunge old_exp;

	if (expunge_idx == N_ELEMENTS(expunge_uids))
		return 0;

	if (mail_guids[expunge_idx][0] == 0) {
		old_exp.uid1 = old_exp.uid2 = expunge_uids[expunge_idx];
		hdr.type = MAIL_TRANSACTION_EXPUNGE;
		hdr.size = sizeof(old_exp);
		*data_r = &old_exp;
	} else {
		exp.uid = expunge_uids[expunge_idx];
		memcpy(exp.guid_128, mail_guids[expunge_idx], sizeof(exp.guid_128));
		hdr.type = MAIL_TRANSACTION_EXPUNGE_GUID;
		hdr.size = sizeof(exp);
		*data_r = &exp;
	}
	if (expunge_idx != nonexternal_idx)
		hdr.type |= MAIL_TRANSACTION_EXTERNAL;

	*hdr_r = &hdr;
	expunge_idx++;
	return 1;
}

void mail_transaction_log_view_mark(struct mail_transaction_log_view *view ATTR_UNUSED)
{
}

void mail_transaction_log_view_rewind(struct mail_transaction_log_view *view ATTR_UNUSED)
{
	expunge_idx = 0;
}

static void test_index_storage_get_expunges(void)
{
	struct mailbox *box;
	ARRAY_TYPE(seq_range) uids_filter;
	ARRAY_TYPE(mailbox_expunge_rec) expunges;
	const struct mailbox_expunge_rec *exp;
	unsigned int count;
	uint64_t modseq;

	box = t_new(struct mailbox, 1);
	box->index = t_new(struct mail_index, 1);
	box->view = t_new(struct mail_index_view, 1);

	box->view->log_file_head_seq = 101;
	box->view->log_file_head_offset = 1024;

	test_begin("index storage get expunges");

	nonexternal_idx = 1;
	memset(mail_guids + 2, 0, MAIL_GUID_128_SIZE);
	memset(mail_guids + 4, 0, MAIL_GUID_128_SIZE);

	t_array_init(&uids_filter, 32);
	seq_range_array_add_range(&uids_filter, 1, 20);
	seq_range_array_add_range(&uids_filter, 53, 53);

	t_array_init(&expunges, 32);
	modseq = 98ULL << 32;
	test_assert(index_storage_get_expunges(box, modseq, &uids_filter,
					       NULL, &expunges) == 0);

	exp = array_get(&expunges, &count);
	test_assert(count == 5);
	test_assert(exp[0].uid == 3);
	test_assert(memcmp(exp[0].guid_128, mail_guids[3], MAIL_GUID_128_SIZE) == 0);
	test_assert(exp[1].uid == 1);
	test_assert(memcmp(exp[1].guid_128, mail_guids[5], MAIL_GUID_128_SIZE) == 0);
	test_assert(exp[2].uid == 53);
	test_assert(memcmp(exp[2].guid_128, mail_guids[6], MAIL_GUID_128_SIZE) == 0);
	test_assert(exp[3].uid == 7);
	test_assert(memcmp(exp[3].guid_128, mail_guids[2], MAIL_GUID_128_SIZE) == 0);
	test_assert(exp[4].uid == 11);
	test_assert(memcmp(exp[4].guid_128, mail_guids[4], MAIL_GUID_128_SIZE) == 0);

	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_index_storage_get_expunges,
		NULL
	};
	unsigned int i, j;

	for (i = 0; i < N_ELEMENTS(mail_guids); i++) {
		for (j = 0; j < MAIL_GUID_128_SIZE; j++)
			mail_guids[i][j] = j + i + 1;
	}
	return test_run(test_functions);
}
