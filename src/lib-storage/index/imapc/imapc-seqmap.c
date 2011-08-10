/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "imapc-seqmap.h"

struct imapc_seqmap {
	ARRAY_TYPE(uint32_t) queue;
	ARRAY_TYPE(uint32_t) expunges;
};

struct imapc_seqmap *imapc_seqmap_init(void)
{
	struct imapc_seqmap *seqmap;

	seqmap = i_new(struct imapc_seqmap, 1);
	i_array_init(&seqmap->queue, 64);
	i_array_init(&seqmap->expunges, 64);
	return seqmap;
}

void imapc_seqmap_deinit(struct imapc_seqmap **_seqmap)
{
	struct imapc_seqmap *seqmap = *_seqmap;

	*_seqmap = NULL;
	array_free(&seqmap->expunges);
	array_free(&seqmap->queue);
	i_free(seqmap);
}

void imapc_seqmap_reset(struct imapc_seqmap *seqmap)
{
	array_clear(&seqmap->queue);
	array_clear(&seqmap->expunges);
}

bool imapc_seqmap_is_reset(struct imapc_seqmap *seqmap)
{
	return array_count(&seqmap->queue) == 0 &&
		array_count(&seqmap->expunges) == 0;
}

void imapc_seqmap_expunge(struct imapc_seqmap *seqmap, uint32_t rseq)
{
	i_assert(rseq > 0);

	array_append(&seqmap->queue, &rseq, 1);
}

static int uint32_cmp_p(const uint32_t *p1, const uint32_t *p2)
{
	if (*p1 < *p2)
		return -1;
	else if (*p1 > *p2)
		return 1;
	else
		return 0;
}

static uint32_t
imapc_seqmap_rseq_idx_lookup(struct imapc_seqmap *seqmap, uint32_t rseq,
			     unsigned int *idx_r)
{
	const uint32_t *seqs;
	unsigned int idx, count;
	uint32_t lseq = rseq;

	seqs = array_get(&seqmap->expunges, &count);
	for (;;) {
		array_bsearch_insert_pos(&seqmap->expunges, &lseq, uint32_cmp_p, &idx);
		lseq = rseq + idx;
		if (idx == count || seqs[idx] > lseq) {
			*idx_r = idx;
			return lseq;
		}
		if (seqs[idx] == lseq)
			lseq++;
	}
}

static void
imapc_seqmap_dequeue_rseq(struct imapc_seqmap *seqmap, uint32_t rseq)
{
	unsigned int idx;
	uint32_t lseq;

	lseq = imapc_seqmap_rseq_idx_lookup(seqmap, rseq, &idx);
	array_insert(&seqmap->expunges, idx, &lseq, 1);
}

static void imapc_seqmap_dequeue(struct imapc_seqmap *seqmap)
{
	const uint32_t *seqp;

	array_foreach(&seqmap->queue, seqp)
		imapc_seqmap_dequeue_rseq(seqmap, *seqp);
	array_clear(&seqmap->queue);
}

uint32_t imapc_seqmap_rseq_to_lseq(struct imapc_seqmap *seqmap, uint32_t rseq)
{
	unsigned int idx;

	i_assert(rseq > 0);

	imapc_seqmap_dequeue(seqmap);
	return imapc_seqmap_rseq_idx_lookup(seqmap, rseq, &idx);
}

uint32_t imapc_seqmap_lseq_to_rseq(struct imapc_seqmap *seqmap, uint32_t lseq)
{
	unsigned int idx;

	i_assert(lseq > 0);

	imapc_seqmap_dequeue(seqmap);
	if (array_bsearch_insert_pos(&seqmap->expunges, &lseq,
				     uint32_cmp_p, &idx))
		return 0;

	return lseq - idx;
}
