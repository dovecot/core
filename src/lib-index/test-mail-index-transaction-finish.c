/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "test-common.h"
#include "mail-index-private.h"
#include "mail-index-modseq.h"
#include "mail-index-transaction-private.h"

#include <stdlib.h>

static struct mail_index_record recs[20];
static uint64_t modseqs[N_ELEMENTS(recs)];

bool mail_index_map_get_ext_idx(struct mail_index_map *map ATTR_UNUSED,
				uint32_t ext_id ATTR_UNUSED,
				uint32_t *idx_r ATTR_UNUSED) { return FALSE; }
void mail_index_ext_set_reset_id(struct mail_index_transaction *t ATTR_UNUSED,
				 uint32_t ext_id ATTR_UNUSED,
				 uint32_t reset_id ATTR_UNUSED) { }
void mail_index_transaction_set_log_updates(struct mail_index_transaction *t ATTR_UNUSED) { }
void mail_index_update_day_headers(struct mail_index_transaction *t ATTR_UNUSED) {}
bool mail_index_cancel_flag_updates(struct mail_index_transaction *t ATTR_UNUSED,
				    uint32_t seq ATTR_UNUSED) { return TRUE; }
bool mail_index_cancel_keyword_updates(struct mail_index_transaction *t ATTR_UNUSED,
				       uint32_t seq ATTR_UNUSED) { return TRUE; }
void mail_index_transaction_sort_appends(struct mail_index_transaction *t ATTR_UNUSED) {}
int mail_index_map(struct mail_index *index ATTR_UNUSED,
		   enum mail_index_sync_handler_type type ATTR_UNUSED) { return 1; }
void mail_index_update_modseq(struct mail_index_transaction *t ATTR_UNUSED, uint32_t seq ATTR_UNUSED,
			      uint64_t min_modseq ATTR_UNUSED) {}

const struct mail_index_record *
mail_index_lookup(struct mail_index_view *view ATTR_UNUSED, uint32_t seq)
{
	i_assert(seq < N_ELEMENTS(recs));
	return &recs[seq];
}

struct mail_index_record *
mail_index_transaction_lookup(struct mail_index_transaction *t ATTR_UNUSED,
			      uint32_t seq)
{
	i_assert(seq < N_ELEMENTS(recs));
	return &recs[seq];
}

uint64_t mail_index_modseq_lookup(struct mail_index_view *view ATTR_UNUSED,
				  uint32_t seq)
{
	i_assert(seq < N_ELEMENTS(modseqs));
	return modseqs[seq];
}

uint64_t mail_index_modseq_get_highest(struct mail_index_view *view ATTR_UNUSED)
{
	return modseqs[0];
}

static void test_mail_index_transaction_finish_flag_updates(void)
{
	struct mail_index_transaction *t;
	const struct mail_transaction_flag_update *updates;
	struct mail_transaction_flag_update u;
	unsigned int count;

	t = t_new(struct mail_index_transaction, 1);
	t->drop_unnecessary_flag_updates = TRUE;

	memset(&u, 0, sizeof(u));
	u.add_flags = MAIL_SEEN; u.remove_flags = MAIL_DRAFT;

	test_begin("mail index transaction finish flag updates");

	/* test fast path: all changed */
	t_array_init(&t->updates, 10);
	u.uid1 = 1; u.uid2 = 2;
	array_append(&t->updates, &u, 1);
	u.uid1 = 4; u.uid2 = 5;
	array_append(&t->updates, &u, 1);
	mail_index_transaction_finish(t);

	updates = array_get(&t->updates, &count);
	test_assert(count == 4);
	test_assert(updates[0].uid1 == 1*2 && updates[0].uid2 == 1*2);
	test_assert(updates[1].uid1 == 2*2 && updates[1].uid2 == 2*2);
	test_assert(updates[2].uid1 == 4*2 && updates[2].uid2 == 4*2);
	test_assert(updates[3].uid1 == 5*2 && updates[3].uid2 == 5*2);

	/* nothing changed */
	t_array_init(&t->updates, 10);
	u.uid1 = 1; u.uid2 = 2;
	array_append(&t->updates, &u, 1);
	u.uid1 = 4; u.uid2 = 5;
	array_append(&t->updates, &u, 1);
	recs[1].flags = MAIL_SEEN;
	recs[2].flags = MAIL_SEEN;
	recs[4].flags = MAIL_SEEN;
	recs[5].flags = MAIL_SEEN;
	mail_index_transaction_finish(t);
	test_assert(!array_is_created(&t->updates));

	/* some changes */
	t_array_init(&t->updates, 10);
	u.uid1 = 2; u.uid2 = 3;
	array_append(&t->updates, &u, 1);
	u.uid1 = 5; u.uid2 = 6;
	array_append(&t->updates, &u, 1);
	mail_index_transaction_finish(t);

	updates = array_get(&t->updates, &count);
	test_assert(count == 2);
	test_assert(updates[0].uid1 == 3*2 && updates[0].uid2 == 3*2);
	test_assert(updates[1].uid1 == 6*2 && updates[1].uid2 == 6*2);

	test_end();
}

static void test_mail_index_transaction_finish_check_conflicts(void)
{
	struct mail_index_transaction *t;
	const struct seq_range *conflicts;
	ARRAY_TYPE(seq_range) conflict_seqs = ARRAY_INIT;
	unsigned int count;

	t = t_new(struct mail_index_transaction, 1);
	t->view = t_new(struct mail_index_view, 1);
	t->min_flagupdate_seq = 5;
	t->max_flagupdate_seq = 8;
	t->conflict_seqs = &conflict_seqs;

	modseqs[0] = 1234;
	modseqs[5] = 5;
	modseqs[6] = 8;
	modseqs[7] = 6;
	modseqs[8] = 7;

	test_begin("mail index transaction finish check conflicts");

	/* fast path: no conflicts */
	t->max_modseq = 1234;
	mail_index_transaction_finish(t);
	test_assert(!array_is_created(&conflict_seqs));

	/* try some conflicts */
	t->max_modseq = 6;
	mail_index_transaction_finish(t);

	conflicts = array_get(&conflict_seqs, &count);
	test_assert(count == 2);
	test_assert(conflicts[0].seq1 == 6 && conflicts[0].seq2 == 6);
	test_assert(conflicts[1].seq1 == 8 && conflicts[1].seq2 == 8);

	test_end();
}

static void test_mail_index_transaction_finish_modseq_updates(void)
{
	struct mail_index_transaction *t;
	const struct mail_transaction_modseq_update *ups;
	struct mail_transaction_modseq_update u;
	unsigned int count;

	t = t_new(struct mail_index_transaction, 1);

	test_begin("mail index transaction finish modseq updates");

	t_array_init(&t->modseq_updates, 10);
	u.modseq_low32 = 1234567890;
	u.modseq_high32 = 987654321;
	u.uid = 1; array_append(&t->modseq_updates, &u, 1);
	u.modseq_low32++;
	u.modseq_high32++;
	u.uid = 2; array_append(&t->modseq_updates, &u, 1);
	u.modseq_low32++;
	u.modseq_high32++;
	u.uid = 5; array_append(&t->modseq_updates, &u, 1);
	u.modseq_low32 = 1234;
	u.modseq_high32 = 0;
	u.uid = 2; array_append(&t->modseq_updates, &u, 1);

	mail_index_transaction_finish(t);

	ups = array_get(&t->modseq_updates, &count);
	test_assert(count == 4);

	test_assert(ups[0].uid == 1*2);
	test_assert(ups[0].modseq_low32 == 1234567890 &&
		    ups[0].modseq_high32 == 987654321);
	test_assert(ups[1].uid == 2*2);
	test_assert(ups[1].modseq_low32 == 1234567891 &&
		    ups[1].modseq_high32 == 987654322);
	test_assert(ups[2].uid == 5*2);
	test_assert(ups[2].modseq_low32 == 1234567892 &&
		    ups[2].modseq_high32 == 987654323);
	test_assert(ups[3].uid == 2*2);
	test_assert(ups[3].modseq_low32 == 1234 &&
		    ups[3].modseq_high32 == 0);
	test_end();
}

static void test_mail_index_transaction_finish_expunges(void)
{
	struct mail_index_transaction *t;
	uint8_t guid1[MAIL_GUID_128_SIZE];
	uint8_t guid2[MAIL_GUID_128_SIZE];
	uint8_t guid3[MAIL_GUID_128_SIZE];
	const struct mail_transaction_expunge_guid *expunges;
	struct mail_transaction_expunge_guid expunge;
	unsigned int i, count;

	for (i = 0; i < sizeof(guid2); i++) {
		guid1[i] = i + 1;
		guid2[i] = i ^ 0xff;
		guid3[i] = i + 0x80;
	}

	recs[1].uid = 12;
	recs[2].uid = 15;
	recs[3].uid = 18;

	t = t_new(struct mail_index_transaction, 1);
	t->expunges_nonsorted = TRUE;

	test_begin("mail index transaction finish expunges");

	t_array_init(&t->expunges, 3);
	expunge.uid = 2;
	memcpy(expunge.guid_128, guid2, sizeof(expunge.guid_128));
	array_append(&t->expunges, &expunge, 1);
	array_append(&t->expunges, &expunge, 1);
	expunge.uid = 1;
	memcpy(expunge.guid_128, guid1, sizeof(expunge.guid_128));
	array_append(&t->expunges, &expunge, 1);
	array_append(&t->expunges, &expunge, 1);
	expunge.uid = 3;
	memcpy(expunge.guid_128, guid3, sizeof(expunge.guid_128));
	array_append(&t->expunges, &expunge, 1);
	array_append(&t->expunges, &expunge, 1);

	mail_index_transaction_finish(t);

	expunges = array_get(&t->expunges, &count);
	test_assert(count == 3);
	test_assert(expunges[0].uid == 12);
	test_assert(memcmp(expunges[0].guid_128, guid1, sizeof(guid1)) == 0);
	test_assert(expunges[1].uid == 15);
	test_assert(memcmp(expunges[1].guid_128, guid2, sizeof(guid2)) == 0);
	test_assert(expunges[2].uid == 18);
	test_assert(memcmp(expunges[2].guid_128, guid3, sizeof(guid3)) == 0);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_mail_index_transaction_finish_flag_updates,
		test_mail_index_transaction_finish_check_conflicts,
		test_mail_index_transaction_finish_modseq_updates,
		test_mail_index_transaction_finish_expunges,
		NULL
	};
	unsigned int i;

	for (i = 1; i < N_ELEMENTS(recs); i++)
		recs[i].uid = i*2;
	return test_run(test_functions);
}
