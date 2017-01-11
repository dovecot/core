/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "test-common.h"
#include "mail-index-private.h"
#include "mail-index-modseq.h"
#include "mail-index-transaction-private.h"

static void test_mail_index_map_lookup_seq_range_count(unsigned int messages_count)
{
	struct mail_index_record_map rec_map;
	struct mail_index_map map;
	uint32_t seq, first_uid, last_uid, first_seq, last_seq, max_uid;

	i_zero(&map);
	i_zero(&rec_map);
	map.rec_map = &rec_map;
	map.hdr.messages_count = messages_count;
	map.hdr.record_size = sizeof(struct mail_index_record);
	rec_map.records_count = map.hdr.messages_count;
	rec_map.records = i_new(struct mail_index_record, map.hdr.messages_count);

	for (seq = 1; seq <= map.hdr.messages_count; seq++)
		MAIL_INDEX_REC_AT_SEQ(&map, seq)->uid = seq*2;
	max_uid = (seq-1)*2;
	map.hdr.next_uid = max_uid + 1;

	for (first_uid = 2; first_uid <= max_uid; first_uid++) {
		for (last_uid = first_uid; last_uid <= max_uid; last_uid++) {
			if (first_uid == last_uid && first_uid%2 != 0)
				continue;
			mail_index_map_lookup_seq_range(&map, first_uid, last_uid, &first_seq, &last_seq);
			test_assert((first_uid+1)/2 == first_seq && last_uid/2 == last_seq);
		}
	}
	i_free(rec_map.records);
}

static void test_mail_index_map_lookup_seq_range(void)
{
	unsigned int i;

	test_begin("mail index map lookup seq range");
	for (i = 1; i < 20; i++)
		test_mail_index_map_lookup_seq_range_count(i);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_mail_index_map_lookup_seq_range,
		NULL
	};
	return test_run(test_functions);
}
