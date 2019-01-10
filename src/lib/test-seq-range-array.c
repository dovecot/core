/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "array.h"
#include "seq-range-array.h"


static void
boundaries_permute(uint32_t *input, unsigned int i, unsigned int count)
{
	ARRAY_TYPE(seq_range) range;
	const struct seq_range *seqs;
	unsigned int seqs_count;
	uint32_t tmp;
	unsigned int j;

	if (i+1 < count) {
		for (j = i; j < count; j++) {
			tmp = input[i]; input[i] = input[j]; input[j] = tmp;
			boundaries_permute(input, i+1, count);
			tmp = input[i]; input[i] = input[j]; input[j] = tmp;
		}
		return;
	}
	t_array_init(&range, 4);
	for (i = 0; i < count; i++)
		seq_range_array_add(&range, input[i]);
	seqs = array_get(&range, &seqs_count);
	test_assert(seqs_count == 2);
	test_assert(seqs[0].seq1 == 0);
	test_assert(seqs[0].seq2 == 1);
	test_assert(seqs[1].seq1 == (uint32_t)-2);
	test_assert(seqs[1].seq2 == (uint32_t)-1);
}

static void test_seq_range_array_add_boundaries(void)
{
	static uint32_t input[] = { 0, 1, (uint32_t)-2, (uint32_t)-1 };

	boundaries_permute(input, 0, N_ELEMENTS(input));
}

static void test_seq_range_array_add_merge(void)
{
	ARRAY_TYPE(seq_range) range;

	test_begin("seq_range_array_add() merging");
	t_array_init(&range, 8);
	seq_range_array_add(&range, 4);
	seq_range_array_add(&range, 1);
	seq_range_array_add(&range, 2);
	test_assert(array_count(&range) == 2);

	seq_range_array_add_range(&range, 1, (uint32_t)-1);
	test_assert(array_count(&range) == 1);
	seq_range_array_add_range(&range, 1, (uint32_t)-1);
	test_assert(array_count(&range) == 1);
	test_end();
}

static void test_seq_range_array_remove_nth(void)
{
	ARRAY_TYPE(seq_range) range;
	const struct seq_range *r;

	test_begin("seq_range_array_remove_nth()");
	t_array_init(&range, 8);
	seq_range_array_add_range(&range, 1, 5);
	seq_range_array_add(&range, 7);
	seq_range_array_add_range(&range, 10,20);
	test_assert(array_count(&range) == 3);

	seq_range_array_remove_nth(&range, 0, 2);
	r = array_first(&range); test_assert(r->seq1 == 3 && r->seq2 == 5);

	seq_range_array_remove_nth(&range, 1, 4);
	r = array_first(&range); test_assert(r->seq1 == 3 && r->seq2 == 3);
	r = array_idx(&range, 1); test_assert(r->seq1 == 11 && r->seq2 == 20);

	seq_range_array_remove_nth(&range, 5, (uint32_t)-1);
	r = array_idx(&range, 1); test_assert(r->seq1 == 11 && r->seq2 == 14);

	test_assert(array_count(&range) == 2);
	test_end();
}

static void test_seq_range_array_random(void)
{
#define SEQ_RANGE_TEST_BUFSIZE 100
#define SEQ_RANGE_TEST_COUNT 20000
	unsigned char shadowbuf[SEQ_RANGE_TEST_BUFSIZE];
	ARRAY_TYPE(seq_range) range;
	const struct seq_range *seqs;
	uint32_t seq1, seq2;
	unsigned int i, j, ret, ret2, count;
	int test = -1;

	ret = ret2 = 0;
	i_array_init(&range, 1);
	memset(shadowbuf, 0, sizeof(shadowbuf));
	for (i = 0; i < SEQ_RANGE_TEST_COUNT; i++) {
		seq1 = i_rand() % SEQ_RANGE_TEST_BUFSIZE;
		seq2 = seq1 + i_rand() % (SEQ_RANGE_TEST_BUFSIZE - seq1);
		test = i_rand() % 4;
		switch (test) {
		case 0:
			ret = seq_range_array_add(&range, seq1) ? 0 : 1; /* FALSE == added */
			ret2 = shadowbuf[seq1] == 0 ? 1 : 0;
			shadowbuf[seq1] = 1;
			break;
		case 1:
			ret = seq_range_array_add_range_count(&range, seq1, seq2);
			for (ret2 = 0; seq1 <= seq2; seq1++) {
				if (shadowbuf[seq1] == 0) {
					ret2++;
					shadowbuf[seq1] = 1;
				}
			}
			break;
		case 2:
			ret = seq_range_array_remove(&range, seq1) ? 1 : 0;
			ret2 = shadowbuf[seq1] != 0 ? 1 : 0;
			shadowbuf[seq1] = 0;
			break;
		case 3:
			ret = seq_range_array_remove_range(&range, seq1, seq2);
			for (ret2 = 0; seq1 <= seq2; seq1++) {
				if (shadowbuf[seq1] != 0) {
					ret2++;
					shadowbuf[seq1] = 0;
				}
			}
			break;
		}
		if (ret != ret2)
			break;

		seqs = array_get(&range, &count);
		for (j = 0, seq1 = 0; j < count; j++) {
			if (j > 0 && seqs[j-1].seq2+1 >= seqs[j].seq1)
				goto fail;
			for (; seq1 < seqs[j].seq1; seq1++) {
				if (shadowbuf[seq1] != 0)
					goto fail;
			}
			for (; seq1 <= seqs[j].seq2; seq1++) {
				if (shadowbuf[seq1] == 0)
					goto fail;
			}
		}
		i_assert(seq1 <= SEQ_RANGE_TEST_BUFSIZE);
		for (; seq1 < SEQ_RANGE_TEST_BUFSIZE; seq1++) {
			if (shadowbuf[seq1] != 0)
				goto fail;
		}
	}
fail:
	if (i == SEQ_RANGE_TEST_COUNT)
		test_out("seq_range_array random", TRUE);
	else {
		test_out_reason("seq_range_array random", FALSE,
			t_strdup_printf("round %u test %d failed", i, test));
	}
	array_free(&range);
}

static void test_seq_range_array_invert_minmax(uint32_t min, uint32_t max)
{
	ARRAY_TYPE(seq_range) range = ARRAY_INIT;
	struct seq_range_iter iter;
	unsigned int n, inverse_mask, mask_inside, mask_size = max-min+1;
	uint32_t seq;

	i_assert(mask_size <= sizeof(unsigned int)*8);
	t_array_init(&range, 16);
	for (unsigned int mask = 0; mask < mask_size; mask++) {
		array_clear(&range);
		for (unsigned int i = 0; i < mask_size; i++) {
			if ((mask & (1 << i)) != 0)
				seq_range_array_add(&range, min+i);
		}
		seq_range_array_invert(&range, min, max);

		inverse_mask = 0;
		seq_range_array_iter_init(&iter, &range); n = 0;
		while (seq_range_array_iter_nth(&iter, n++, &seq)) {
			test_assert(seq >= min && seq <= max);
			inverse_mask |= 1 << (seq-min);
		}
		mask_inside = ((1 << mask_size)-1);
		test_assert_idx((inverse_mask & ~mask_inside) == 0, mask);
		test_assert_idx(inverse_mask == (mask ^ mask_inside), mask);
	}
}

static void test_seq_range_array_invert(void)
{
	test_begin("seq_range_array_invert()");
	/* first numbers */
	for (unsigned int min = 0; min <= 7; min++) {
		for (unsigned int max = min; max <= 7; max++) T_BEGIN {
			test_seq_range_array_invert_minmax(min, max);
		} T_END;
	}
	/* last numbers */
	for (uint64_t min = 0xffffffff-7; min <= 0xffffffff; min++) {
		for (uint64_t max = min; max <= 0xffffffff; max++) T_BEGIN {
			test_seq_range_array_invert_minmax(min, max);
		} T_END;
	}
	test_end();
}

static void test_seq_range_array_invert_edges(void)
{
	static const struct {
		int64_t a_seq1, a_seq2, b_seq1, b_seq2;
		int64_t resa_seq1, resa_seq2, resb_seq1, resb_seq2;
	} tests[] = {
		{ -1, -1, -1, -1,
		  0, 0xffffffff, -1, -1 },
		{ 0, 0xffffffff, -1, -1,
		  -1, -1, -1, -1 },
		{ 0, 0xfffffffe, -1, -1,
		  0xffffffff, 0xffffffff, -1, -1 },
		{ 1, 0xfffffffe, -1, -1,
		  0, 0, 0xffffffff, 0xffffffff },
		{ 1, 0xffffffff, -1, -1,
		  0, 0, -1, -1 },
		{ 0, 0, 0xffffffff, 0xffffffff,
		  1, 0xfffffffe, -1, -1 },
		{ 0xffffffff, 0xffffffff, -1, -1,
		  0, 0xfffffffe, -1, -1 },
	};
	ARRAY_TYPE(seq_range) range = ARRAY_INIT;
	const struct seq_range *result;
	unsigned int count;

	test_begin("seq_range_array_invert() edges");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) T_BEGIN {
		t_array_init(&range, 10);
		if (tests[i].a_seq1 != -1)
			seq_range_array_add_range(&range, tests[i].a_seq1, tests[i].a_seq2);
		if (tests[i].b_seq1 != -1)
			seq_range_array_add_range(&range, tests[i].b_seq1, tests[i].b_seq2);
		seq_range_array_invert(&range, 0, 0xffffffff);

		result = array_get(&range, &count);
		if (tests[i].resa_seq1 == -1)
			test_assert_idx(count == 0, i);
		else {
			test_assert(result[0].seq1 == tests[i].resa_seq1);
			test_assert(result[0].seq2 == tests[i].resa_seq2);
			if (tests[i].resb_seq1 == -1)
				test_assert_idx(count == 1, i);
			else {
				test_assert(result[1].seq1 == tests[i].resb_seq1);
				test_assert(result[1].seq2 == tests[i].resb_seq2);
			}
		}
	} T_END;
	test_end();
}

static void test_seq_range_create(ARRAY_TYPE(seq_range) *array, uint8_t byte)
{
	unsigned int i;

	array_clear(array);
	for (i = 0; i < 8; i++) {
		if ((byte & (1 << i)) != 0)
			seq_range_array_add(array, i + 1);
	}
}

static void test_seq_range_array_have_common(void)
{
	ARRAY_TYPE(seq_range) arr1, arr2;
	unsigned int i, j;
	bool ret1, ret2, success = TRUE;

	t_array_init(&arr1, 8);
	t_array_init(&arr2, 8);
	for (i = 0; i < 256; i++) {
		test_seq_range_create(&arr1, i);
		for (j = 0; j < 256; j++) {
			test_seq_range_create(&arr2, j);
			ret1 = seq_range_array_have_common(&arr1, &arr2);
			ret2 = (i & j) != 0;
			if (ret1 != ret2)
				success = FALSE;
		}
	}
	test_out("seq_range_array_have_common()", success);
}

void test_seq_range_array(void)
{
	test_seq_range_array_add_boundaries();
	test_seq_range_array_add_merge();
	test_seq_range_array_remove_nth();
	test_seq_range_array_invert();
	test_seq_range_array_invert_edges();
	test_seq_range_array_have_common();
	test_seq_range_array_random();
}
