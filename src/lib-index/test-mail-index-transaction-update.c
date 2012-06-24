/* Copyright (c) 2009-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "test-common.h"
#include "mail-index-private.h"
#include "mail-index-transaction-private.h"

#include <stdlib.h>

static struct mail_index_header hdr;
static struct mail_index_record rec;

const struct mail_index_header *
mail_index_get_header(struct mail_index_view *view ATTR_UNUSED)
{
	return &hdr;
}

const struct mail_index_record *
mail_index_lookup(struct mail_index_view *view ATTR_UNUSED,
		  uint32_t seq ATTR_UNUSED)
{
	return &rec;
}

void mail_index_lookup_keywords(struct mail_index_view *view ATTR_UNUSED,
				uint32_t seq ATTR_UNUSED,
				ARRAY_TYPE(keyword_indexes) *keyword_idx ATTR_UNUSED)
{
	array_clear(keyword_idx);
}

bool mail_index_map_get_ext_idx(struct mail_index_map *map ATTR_UNUSED,
				uint32_t ext_id ATTR_UNUSED,
				uint32_t *idx_r ATTR_UNUSED)
{
	return FALSE;
}

uint32_t mail_index_view_get_messages_count(struct mail_index_view *view ATTR_UNUSED)
{
	return hdr.messages_count;
}

void mail_index_transaction_lookup_latest_keywords(struct mail_index_transaction *t ATTR_UNUSED,
						   uint32_t seq ATTR_UNUSED,
						   ARRAY_TYPE(keyword_indexes) *keywords ATTR_UNUSED)
{
}

struct mail_keywords *
mail_index_keywords_create_from_indexes(struct mail_index *index ATTR_UNUSED,
					const ARRAY_TYPE(keyword_indexes)
						*keyword_indexes ATTR_UNUSED)
{
	return NULL;
}

static struct mail_index_transaction *
mail_index_transaction_new(void)
{
	struct mail_index_transaction *t;

	t = t_new(struct mail_index_transaction, 1);
	t->first_new_seq = hdr.messages_count + 1;
	return t;
}

static void test_mail_index_append(void)
{
	struct mail_index_transaction *t;
	const struct mail_index_record *appends;
	ARRAY_TYPE(seq_range) saved_uids_arr;
	const struct seq_range *saved_uids;
	unsigned int count;
	uint32_t seq;

	hdr.messages_count = 4;
	t = mail_index_transaction_new();

	test_begin("mail index append");
	mail_index_append(t, 0, &seq);
	test_assert(t->log_updates);
	test_assert(seq == 5);
	mail_index_append(t, 0, &seq);
	test_assert(seq == 6);
	test_assert(!t->appends_nonsorted);

	t_array_init(&saved_uids_arr, 128);
	mail_index_append_finish_uids(t, 123, &saved_uids_arr);
	saved_uids = array_get(&saved_uids_arr, &count);
	test_assert(count == 1);
	test_assert(saved_uids[0].seq1 == 123 && saved_uids[0].seq2 == 124);

	appends = array_get(&t->appends, &count);
	test_assert(appends[0].uid == 123);
	test_assert(appends[0].flags == 0);
	test_assert(appends[1].uid == 124);
	test_assert(appends[1].flags == 0);
	test_end();

	/* test with some uids */
	t = mail_index_transaction_new();

	test_begin("mail index append with uids");
	mail_index_append(t, 0, &seq);
	test_assert(seq == 5);
	mail_index_append(t, 126, &seq);
	test_assert(seq == 6);
	test_assert(!t->appends_nonsorted);
	mail_index_append(t, 124, &seq);
	test_assert(seq == 7);
	test_assert(t->appends_nonsorted);
	mail_index_append(t, 0, &seq);
	test_assert(seq == 8);
	mail_index_append(t, 128, &seq);
	test_assert(seq == 9);
	test_assert(t->highest_append_uid == 128);

	mail_index_append_finish_uids(t, 125, &saved_uids_arr);
	saved_uids = array_get(&saved_uids_arr, &count);
	test_assert(count == 4);
	test_assert(saved_uids[0].seq1 == 129 && saved_uids[0].seq2 == 129);
	test_assert(saved_uids[1].seq1 == 126 && saved_uids[1].seq2 == 126);
	test_assert(saved_uids[2].seq1 == 130 && saved_uids[2].seq2 == 131);
	test_assert(saved_uids[3].seq1 == 128 && saved_uids[3].seq2 == 128);

	appends = array_get(&t->appends, &count);
	test_assert(count == 5);
	test_assert(appends[0].uid == 129);
	test_assert(appends[1].uid == 126);
	test_assert(appends[2].uid == 130);
	test_assert(appends[3].uid == 131);
	test_assert(appends[4].uid == 128);
	test_end();
}

static void test_mail_index_flag_update_fastpath(void)
{
	struct mail_index_transaction *t;
	const struct mail_index_flag_update *updates;
	unsigned int count;

	hdr.messages_count = 20;
	t = mail_index_transaction_new();

	test_begin("mail index flag update fast paths");

	mail_index_update_flags_range(t, 13, 14, MODIFY_REPLACE,
				      MAIL_DELETED);
	test_assert(t->last_update_idx == 0);
	test_assert(array_count(&t->updates) == 1);

	mail_index_update_flags_range(t, 15, 15, MODIFY_REPLACE,
				      MAIL_DELETED);
	test_assert(t->last_update_idx == 0);
	test_assert(array_count(&t->updates) == 1);

	mail_index_update_flags_range(t, 16, 16, MODIFY_ADD,
				      MAIL_DELETED);
	test_assert(t->last_update_idx == 1);
	test_assert(array_count(&t->updates) == 2);

	updates = array_get(&t->updates, &count);
	test_assert(updates[0].uid1 == 13);
	test_assert(updates[0].uid2 == 15);
	test_assert(updates[0].add_flags == MAIL_DELETED);
	test_assert(updates[0].remove_flags ==
		    (MAIL_ANSWERED | MAIL_FLAGGED | MAIL_SEEN | MAIL_DRAFT));
	test_assert(updates[1].uid1 == 16);
	test_assert(updates[1].uid2 == 16);
	test_assert(updates[1].add_flags == MAIL_DELETED);
	test_assert(updates[1].remove_flags == 0);
	test_assert(!t->log_updates);
	test_end();
}

static void test_mail_index_flag_update_simple_merges(void)
{
	struct mail_index_transaction *t;
	const struct mail_index_flag_update *updates;
	unsigned int count;

	hdr.messages_count = 20;
	t = mail_index_transaction_new();

	test_begin("mail index flag update simple merges");

	mail_index_update_flags_range(t, 6, 8, MODIFY_ADD,
				      MAIL_FLAGGED);
	test_assert(t->last_update_idx == 0);
	mail_index_update_flags_range(t, 5, 6, MODIFY_ADD,
				      MAIL_FLAGGED);
	test_assert(t->last_update_idx == 0);
	mail_index_update_flags_range(t, 4, 4, MODIFY_ADD,
				      MAIL_FLAGGED);
	test_assert(t->last_update_idx == 0);
	mail_index_update_flags_range(t, 7, 9, MODIFY_ADD,
				      MAIL_FLAGGED);
	test_assert(t->last_update_idx == 0);
	mail_index_update_flags_range(t, 10, 10, MODIFY_ADD,
				      MAIL_FLAGGED);
	updates = array_get(&t->updates, &count);
	test_assert(count == 1);
	test_assert(updates[0].uid1 == 4);
	test_assert(updates[0].uid2 == 10);
	test_assert(updates[0].add_flags == MAIL_FLAGGED);
	test_assert(updates[0].remove_flags == 0);

	mail_index_update_flags_range(t, 12, 12, MODIFY_ADD,
				      MAIL_FLAGGED);
	mail_index_update_flags_range(t, 11, 11, MODIFY_ADD,
				      MAIL_FLAGGED);
	updates = array_get(&t->updates, &count);
	test_assert(count == 1);
	test_assert(updates[0].uid1 == 4);
	test_assert(updates[0].uid2 == 12);
	test_end();
}

static void test_mail_index_flag_update_complex_merges(void)
{
	struct mail_index_transaction *t;
	const struct mail_index_flag_update *updates;
	unsigned int count;

	hdr.messages_count = 20;
	t = mail_index_transaction_new();

	test_begin("mail index flag update complex merges");

	mail_index_update_flags_range(t, 6, 8, MODIFY_REPLACE,
				      MAIL_SEEN);
	mail_index_update_flags_range(t, 3, 6, MODIFY_ADD,
				      MAIL_FLAGGED);
	mail_index_update_flags_range(t, 5, 7, MODIFY_ADD,
				      MAIL_DRAFT);
	mail_index_update_flags_range(t, 6, 6, MODIFY_REPLACE,
				      MAIL_SEEN | MAIL_ANSWERED);
	mail_index_update_flags_range(t, 5, 10, MODIFY_REMOVE,
				      MAIL_ANSWERED);
	mail_index_update_flags_range(t, 7, 12, MODIFY_ADD,
				      MAIL_DELETED);

	updates = array_get(&t->updates, &count);
	test_assert(count == 7);
	test_assert(updates[0].uid1 == 3);
	test_assert(updates[0].uid2 == 4);
	test_assert(updates[0].add_flags == MAIL_FLAGGED);
	test_assert(updates[0].remove_flags == 0);
	test_assert(updates[1].uid1 == 5);
	test_assert(updates[1].uid2 == 5);
	test_assert(updates[1].add_flags == (MAIL_DRAFT | MAIL_FLAGGED));
	test_assert(updates[1].remove_flags == MAIL_ANSWERED);
	test_assert(updates[2].uid1 == 6);
	test_assert(updates[2].uid2 == 6);
	test_assert(updates[2].add_flags == MAIL_SEEN);
	test_assert(updates[2].remove_flags == (MAIL_ANSWERED | MAIL_FLAGGED | MAIL_DELETED | MAIL_DRAFT));
	test_assert(updates[3].uid1 == 7);
	test_assert(updates[3].uid2 == 7);
	test_assert(updates[3].add_flags == (MAIL_SEEN | MAIL_DRAFT | MAIL_DELETED));
	test_assert(updates[3].remove_flags == (MAIL_ANSWERED | MAIL_FLAGGED));
	test_assert(updates[4].uid1 == 8);
	test_assert(updates[4].uid2 == 8);
	test_assert(updates[4].add_flags == (MAIL_SEEN | MAIL_DELETED));
	test_assert(updates[4].remove_flags == (MAIL_ANSWERED | MAIL_FLAGGED | MAIL_DRAFT));
	test_assert(updates[5].uid1 == 9);
	test_assert(updates[5].uid2 == 10);
	test_assert(updates[5].add_flags == MAIL_DELETED);
	test_assert(updates[5].remove_flags == MAIL_ANSWERED);
	test_assert(updates[6].uid1 == 11);
	test_assert(updates[6].uid2 == 12);
	test_assert(updates[6].add_flags == MAIL_DELETED);
	test_assert(updates[6].remove_flags == 0);

	test_end();
}

static void
flags_array_check(struct mail_index_transaction *t,
		  const enum mail_flags *flags, unsigned int msg_count)
{
	const struct mail_index_flag_update *updates;
	unsigned int i, count, seq;

	if (array_is_created(&t->updates))
		updates = array_get(&t->updates, &count);
	else {
		updates = NULL;
		count = 0;
	}
	for (seq = 1, i = 0; i < count; i++) {
		if (i > 0) {
			test_assert(updates[i-1].uid2 < updates[i].uid1);
			test_assert(updates[i-1].uid2 + 1 != updates[i].uid1 ||
				    updates[i-1].add_flags != updates[i].add_flags ||
				    updates[i-1].remove_flags != updates[i].remove_flags);
		}
		for (; seq != updates[i].uid1; seq++)
			test_assert(flags[seq] == 0);
		for (; seq <= updates[i].uid2; seq++)
			test_assert(flags[seq] == updates[i].add_flags);
	}
	for (; seq <= msg_count; seq++)
		test_assert(flags[seq] == 0);
}

static void test_mail_index_flag_update_random(void)
{
	struct mail_index_transaction *t;
	unsigned int r, seq1, seq2, seq;
	enum mail_flags *flags, change;
	enum modify_type modify_type;

	hdr.messages_count = 20;
	t = mail_index_transaction_new();

	test_begin("mail index flag update random");

	flags = t_new(enum mail_flags, hdr.messages_count + 1);
	for (r = 0; r < 1000; r++) {
		change = rand() % (MAIL_FLAGS_NONRECENT+1);
		seq1 = (rand() % hdr.messages_count) + 1;
		seq2 = seq1 == hdr.messages_count ? seq1 :
			(rand() % (hdr.messages_count - seq1)) + seq1;

		switch (rand() % 3) {
		case 0:
			modify_type = MODIFY_ADD;
			for (seq = seq1; seq <= seq2; seq++)
				flags[seq] |= change;
			break;
		case 1:
			modify_type = MODIFY_REMOVE;
			for (seq = seq1; seq <= seq2; seq++)
				flags[seq] &= ~change;
			break;
		case 2:
			modify_type = MODIFY_REPLACE;
			for (seq = seq1; seq <= seq2; seq++)
				flags[seq] = change;
			break;
		default:
			i_unreached();
		}
		mail_index_update_flags_range(t, seq1, seq2, modify_type,
					      change);
		flags_array_check(t, flags, hdr.messages_count);
	}
	test_end();
}

static void test_mail_index_cancel_flag_updates(void)
{
	struct mail_index_transaction *t;
	const struct mail_index_flag_update *updates;
	unsigned int count;

	hdr.messages_count = 20;
	t = mail_index_transaction_new();

	test_begin("mail index cancel flag updates");

	mail_index_update_flags_range(t, 5, 7, MODIFY_REPLACE, 0);
	updates = array_get(&t->updates, &count);
	test_assert(count == 1);
	test_assert(updates[0].uid1 == 5 && updates[0].uid2 == 7);
	test_assert(mail_index_cancel_flag_updates(t, 5));
	test_assert(updates[0].uid1 == 6 && updates[0].uid2 == 7);
	test_assert(mail_index_cancel_flag_updates(t, 7));
	test_assert(updates[0].uid1 == 6 && updates[0].uid2 == 6);
	test_assert(mail_index_cancel_flag_updates(t, 6));
	test_assert(!array_is_created(&t->updates));

	mail_index_update_flags_range(t, 5, 7, MODIFY_REPLACE, 0);
	test_assert(mail_index_cancel_flag_updates(t, 6));
	updates = array_get(&t->updates, &count);
	test_assert(count == 2);
	test_assert(updates[0].uid1 == 5 && updates[0].uid2 == 5);
	test_assert(updates[1].uid1 == 7 && updates[1].uid2 == 7);

	test_end();
}

static void test_mail_index_flag_update_appends(void)
{
	struct mail_index_transaction *t;
	const struct mail_index_record *appends;
	const struct mail_index_flag_update *updates;
	unsigned int count;
	uint32_t seq;

	hdr.messages_count = 4;
	t = mail_index_transaction_new();

	test_begin("mail index flag update appends");
	mail_index_append(t, 0, &seq);
	test_assert(seq == 5);
	mail_index_append(t, 0, &seq);
	test_assert(seq == 6);
	mail_index_append(t, 0, &seq);
	test_assert(seq == 7);

	mail_index_update_flags_range(t, 5, 6, MODIFY_REPLACE,
				      MAIL_SEEN | MAIL_FLAGGED);
	mail_index_update_flags_range(t, 6, 7, MODIFY_ADD,
				      MAIL_DRAFT | MAIL_FLAGGED);
	mail_index_update_flags_range(t, 5, 7, MODIFY_REMOVE,
				      MAIL_FLAGGED);

	appends = array_get(&t->appends, &count);
	test_assert(count == 3);
	test_assert(appends[0].flags == MAIL_SEEN);
	test_assert(appends[1].flags == (MAIL_SEEN | MAIL_DRAFT));
	test_assert(appends[2].flags == MAIL_DRAFT);

	/* mixed existing/appends */
	mail_index_update_flags_range(t, 4, 5, MODIFY_ADD,
				      MAIL_ANSWERED);
	test_assert(appends[0].flags == (MAIL_SEEN | MAIL_ANSWERED));

	updates = array_get(&t->updates, &count);
	test_assert(count == 1);
	test_assert(updates[0].uid1 == 4);
	test_assert(updates[0].uid2 == 4);
	test_assert(updates[0].add_flags == MAIL_ANSWERED);
	test_end();
}

static bool test_flag_update_pos(struct mail_index_transaction *t,
				 uint32_t seq, unsigned int idx)
{
	unsigned int i, j, count;

	count = array_count(&t->updates);
	for (i = 0; i < idx; i++) {
		for (j = idx + 1; j <= count; j++) {
			if (!mail_index_transaction_get_flag_update_pos(t, i, j, seq) == idx) {
				test_assert(FALSE);
				return FALSE;
			}
		}
	}
	return TRUE;
}

static void test_mail_index_transaction_get_flag_update_pos(void)
{
	struct mail_index_transaction *t;

	test_begin("mail index transaction get flag update pos");

	hdr.messages_count = 10;
	t = mail_index_transaction_new();
	mail_index_update_flags_range(t, 1, 1, MODIFY_REPLACE, 0);
	mail_index_update_flags_range(t, 3, 4, MODIFY_REPLACE, 0);
	mail_index_update_flags_range(t, 6, 7, MODIFY_REPLACE, 0);
	mail_index_update_flags_range(t, 9, 10, MODIFY_REPLACE, 0);

	test_assert(test_flag_update_pos(t, 1, 0));
	test_assert(test_flag_update_pos(t, 2, 1));
	test_assert(test_flag_update_pos(t, 3, 1));
	test_assert(test_flag_update_pos(t, 4, 1));
	test_assert(test_flag_update_pos(t, 5, 2));
	test_assert(test_flag_update_pos(t, 6, 2));
	test_assert(test_flag_update_pos(t, 7, 2));
	test_assert(test_flag_update_pos(t, 8, 3));
	test_assert(test_flag_update_pos(t, 9, 3));
	test_assert(test_flag_update_pos(t, 10, 3));
	test_assert(test_flag_update_pos(t, 11, 4));
	test_assert(test_flag_update_pos(t, 12, 4));
	test_end();
}

static void test_mail_index_modseq_update(void)
{
	struct mail_index_transaction *t;
	const struct mail_transaction_modseq_update *ups;
	unsigned int count;

	test_begin("mail index modseq update");

	hdr.messages_count = 10;
	t = mail_index_transaction_new();

	mail_index_update_modseq(t, 4, 0x8234fefa02747429ULL);
	mail_index_update_modseq(t, 6, 0x1234567890abcdefULL);
	mail_index_update_modseq(t, 2, 0xfeed);
	mail_index_update_modseq(t, 4, 2);
	/* modseq=1 updates are ignored: */
	mail_index_update_modseq(t, 5, 1);
	mail_index_update_modseq(t, 6, 1);

	ups = array_get(&t->modseq_updates, &count);
	test_assert(count == 4);
	test_assert(ups[0].uid == 4 &&
		    ups[0].modseq_high32 == 0x8234fefa &&
		    ups[0].modseq_low32 == 0x02747429);
	test_assert(ups[1].uid == 6 &&
		    ups[1].modseq_high32 == 0x12345678 &&
		    ups[1].modseq_low32 == 0x90abcdef);
	test_assert(ups[2].uid == 2 &&
		    ups[2].modseq_high32 == 0 &&
		    ups[2].modseq_low32 == 0xfeed);
	test_assert(ups[3].uid == 4 &&
		    ups[3].modseq_high32 == 0 &&
		    ups[3].modseq_low32 == 2);
	test_end();
}

static void test_mail_index_expunge(void)
{
	static guid_128_t empty_guid = { 0, };
	struct mail_index_transaction *t;
	const struct mail_transaction_expunge_guid *expunges;
	guid_128_t guid2, guid3, guid4;
	unsigned int i, count;

	test_begin("mail index expunge");

	hdr.messages_count = 10;
	t = mail_index_transaction_new();
	for (i = 0; i < sizeof(guid2); i++) {
		guid2[i] = i + 1;
		guid3[i] = i ^ 0xff;
		guid4[i] = i + 0x80;
	}

	mail_index_expunge_guid(t, 4, guid4);
	test_assert(!t->expunges_nonsorted);
	mail_index_expunge_guid(t, 2, guid2);
	test_assert(t->expunges_nonsorted);
	mail_index_expunge_guid(t, 3, guid3);
	mail_index_expunge(t, 1);
	mail_index_expunge(t, 5);

	expunges = array_get(&t->expunges, &count);
	test_assert(count == 5);
	test_assert(expunges[0].uid == 4);
	test_assert(memcmp(expunges[0].guid_128, guid4, sizeof(guid4)) == 0);
	test_assert(expunges[1].uid == 2);
	test_assert(memcmp(expunges[1].guid_128, guid2, sizeof(guid2)) == 0);
	test_assert(expunges[2].uid == 3);
	test_assert(memcmp(expunges[2].guid_128, guid3, sizeof(guid3)) == 0);
	test_assert(expunges[3].uid == 1);
	test_assert(memcmp(expunges[3].guid_128, empty_guid, sizeof(empty_guid)) == 0);
	test_assert(expunges[4].uid == 5);
	test_assert(memcmp(expunges[4].guid_128, empty_guid, sizeof(empty_guid)) == 0);

	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_mail_index_append,
		test_mail_index_flag_update_fastpath,
		test_mail_index_flag_update_simple_merges,
		test_mail_index_flag_update_complex_merges,
		test_mail_index_flag_update_random,
		test_mail_index_flag_update_appends,
		test_mail_index_cancel_flag_updates,
		test_mail_index_transaction_get_flag_update_pos,
		test_mail_index_modseq_update,
		test_mail_index_expunge,
		NULL
	};
	return test_run(test_functions);
}
