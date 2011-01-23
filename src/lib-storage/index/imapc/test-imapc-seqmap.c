/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "imapc-seqmap.h"
#include "test-common.h"

#include <stdlib.h>

static void test_imapc_seqmap(void)
{
	struct imapc_seqmap *seqmap;

	test_begin("imapc seqmap");
	seqmap = imapc_seqmap_init();

	imapc_seqmap_expunge(seqmap, 4);
	imapc_seqmap_expunge(seqmap, 3);
	imapc_seqmap_expunge(seqmap, 2);

	test_assert(imapc_seqmap_rseq_to_lseq(seqmap, 1) == 1);
	test_assert(imapc_seqmap_rseq_to_lseq(seqmap, 2) == 5);

	test_assert(imapc_seqmap_lseq_to_rseq(seqmap, 1) == 1);
	test_assert(imapc_seqmap_lseq_to_rseq(seqmap, 2) == 0);
	test_assert(imapc_seqmap_lseq_to_rseq(seqmap, 3) == 0);
	test_assert(imapc_seqmap_lseq_to_rseq(seqmap, 4) == 0);
	test_assert(imapc_seqmap_lseq_to_rseq(seqmap, 5) == 2);

	imapc_seqmap_reset(seqmap);
	imapc_seqmap_expunge(seqmap, 3);
	imapc_seqmap_expunge(seqmap, 3);
	imapc_seqmap_expunge(seqmap, 3);

	test_assert(imapc_seqmap_rseq_to_lseq(seqmap, 1) == 1);
	test_assert(imapc_seqmap_rseq_to_lseq(seqmap, 2) == 2);
	test_assert(imapc_seqmap_rseq_to_lseq(seqmap, 3) == 6);

	test_assert(imapc_seqmap_lseq_to_rseq(seqmap, 1) == 1);
	test_assert(imapc_seqmap_lseq_to_rseq(seqmap, 2) == 2);
	test_assert(imapc_seqmap_lseq_to_rseq(seqmap, 3) == 0);
	test_assert(imapc_seqmap_lseq_to_rseq(seqmap, 4) == 0);
	test_assert(imapc_seqmap_lseq_to_rseq(seqmap, 5) == 0);
	test_assert(imapc_seqmap_lseq_to_rseq(seqmap, 6) == 3);

	imapc_seqmap_reset(seqmap);
	/* 9,8,5,4,2,1 */
	imapc_seqmap_expunge(seqmap, 4);
	imapc_seqmap_expunge(seqmap, 4);
	imapc_seqmap_expunge(seqmap, 1);
	imapc_seqmap_expunge(seqmap, 1);
	imapc_seqmap_expunge(seqmap, 4);
	imapc_seqmap_expunge(seqmap, 4);

	test_assert(imapc_seqmap_rseq_to_lseq(seqmap, 1) == 3);
	test_assert(imapc_seqmap_rseq_to_lseq(seqmap, 2) == 6);
	test_assert(imapc_seqmap_rseq_to_lseq(seqmap, 3) == 7);
	test_assert(imapc_seqmap_rseq_to_lseq(seqmap, 4) == 10);

	test_assert(imapc_seqmap_lseq_to_rseq(seqmap, 1) == 0);
	test_assert(imapc_seqmap_lseq_to_rseq(seqmap, 2) == 0);
	test_assert(imapc_seqmap_lseq_to_rseq(seqmap, 3) == 1);
	test_assert(imapc_seqmap_lseq_to_rseq(seqmap, 6) == 2);
	test_assert(imapc_seqmap_lseq_to_rseq(seqmap, 7) == 3);
	test_assert(imapc_seqmap_lseq_to_rseq(seqmap, 10) == 4);

	imapc_seqmap_deinit(&seqmap);
	test_end();
}

static void test_imapc_seqmap_random(void)
{
#define UIDMAP_SIZE 1000
	struct imapc_seqmap *seqmap;
	ARRAY_TYPE(uint32_t) uidmap;
	const uint32_t *uids;
	unsigned int i, count;
	uint32_t seq, uid;

	test_begin("imapc seqmap random");
	seqmap = imapc_seqmap_init();

	t_array_init(&uidmap, UIDMAP_SIZE);
	for (uid = 1; uid <= UIDMAP_SIZE; uid++)
		array_append(&uidmap, &uid, 1);

	for (i = 0; i < 100; i++) {
		seq = (rand() % array_count(&uidmap)) + 1;
		array_delete(&uidmap, seq-1, 1);
		imapc_seqmap_expunge(seqmap, seq);
	}

	uids = array_get(&uidmap, &count);
	for (i = 0; i < 100; i++) {
		seq = i + 1;
		test_assert(imapc_seqmap_rseq_to_lseq(seqmap, seq) == uids[i]);
		test_assert(imapc_seqmap_lseq_to_rseq(seqmap, uids[i]) == seq);
	}
	imapc_seqmap_deinit(&seqmap);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_imapc_seqmap,
		test_imapc_seqmap_random,
		NULL
	};
	return test_run(test_functions);
}
