/* Copyright (c) Dovecot authors, see top-level COPYING file */

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

static void test_mail_index_map_parse_keywords_empty_name_area(void)
{
	/* A keywords extension whose hdr_size equals just the
	   mail_index_keyword_header (keywords_count==0) has an empty name area,
	   so name_area_end_offset is 0. mail_index_map_parse_keywords() must
	   handle this without evaluating name[name_area_end_offset-1], which
	   would underflow to name[(unsigned)-1] and read ~4 GB out of bounds.
	   This is a valid (empty) keyword set, so parsing succeeds. */
	struct mail_index_map map;
	struct mail_index_keyword_header kw_hdr;
	struct mail_index_ext ext;

	test_begin("mail index map parse keywords empty name area");

	i_zero(&map);
	map.hdr.header_size = sizeof(kw_hdr) + 1;

	map.hdr_copy_buf = buffer_create_dynamic(default_pool, 64);
	i_zero(&kw_hdr);
	kw_hdr.keywords_count = 0;
	buffer_append(map.hdr_copy_buf, &kw_hdr, sizeof(kw_hdr));

	i_array_init(&map.extensions, 1);
	i_zero(&ext);
	ext.name = MAIL_INDEX_EXT_KEYWORDS;
	ext.hdr_offset = 0;
	ext.hdr_size = sizeof(struct mail_index_keyword_header);
	array_append(&map.extensions, &ext, 1);

	test_assert(mail_index_map_parse_keywords(&map) == 0);

	if (array_is_created(&map.keyword_idx_map))
		array_free(&map.keyword_idx_map);
	array_free(&map.extensions);
	buffer_free(&map.hdr_copy_buf);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_index_map_lookup_seq_range,
		test_mail_index_map_parse_keywords_empty_name_area,
		NULL
	};
	return test_run(test_functions);
}
