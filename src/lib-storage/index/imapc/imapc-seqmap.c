/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "imapc-seqmap.h"

struct imapc_seqmap {
	ARRAY_TYPE(uint32_t) expunges;
};

struct imapc_seqmap *imapc_seqmap_init(void)
{
	struct imapc_seqmap *seqmap;

	seqmap = i_new(struct imapc_seqmap, 1);
	i_array_init(&seqmap->expunges, 64);
	return seqmap;
}

void imapc_seqmap_deinit(struct imapc_seqmap **_seqmap)
{
	struct imapc_seqmap *seqmap = *_seqmap;

	*_seqmap = NULL;
	array_free(&seqmap->expunges);
	i_free(seqmap);
}

void imapc_seqmap_reset(struct imapc_seqmap *seqmap)
{
	array_clear(&seqmap->expunges);
}

void imapc_seqmap_expunge(struct imapc_seqmap *seqmap, uint32_t rseq)
{
	i_assert(rseq > 0);

	array_append(&seqmap->expunges, &rseq, 1);
}

uint32_t imapc_seqmap_rseq_to_lseq(struct imapc_seqmap *seqmap, uint32_t rseq)
{
	i_assert(rseq > 0);
	return rseq; // FIXME
}

uint32_t imapc_seqmap_lseq_to_rseq(struct imapc_seqmap *seqmap, uint32_t lseq)
{
	i_assert(lseq > 0);
	return lseq; // FIXME
}
