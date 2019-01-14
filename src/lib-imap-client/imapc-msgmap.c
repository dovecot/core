/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "imapc-msgmap.h"
#include "sort.h"

struct imapc_msgmap {
	ARRAY_TYPE(uint32_t) uids;
	uint32_t uid_next;
};

struct imapc_msgmap *imapc_msgmap_init(void)
{
	struct imapc_msgmap *msgmap;

	msgmap = i_new(struct imapc_msgmap, 1);
	i_array_init(&msgmap->uids, 128);
	msgmap->uid_next = 1;
	return msgmap;
}

void imapc_msgmap_deinit(struct imapc_msgmap **_msgmap)
{
	struct imapc_msgmap *msgmap = *_msgmap;

	*_msgmap = NULL;

	array_free(&msgmap->uids);
	i_free(msgmap);
}

uint32_t imapc_msgmap_count(struct imapc_msgmap *msgmap)
{
	return array_count(&msgmap->uids);
}

uint32_t imapc_msgmap_uidnext(struct imapc_msgmap *msgmap)
{
	return msgmap->uid_next;
}

uint32_t imapc_msgmap_rseq_to_uid(struct imapc_msgmap *msgmap, uint32_t rseq)
{
	const uint32_t *uidp;

	uidp = array_idx(&msgmap->uids, rseq-1);
	return *uidp;
}

bool imapc_msgmap_uid_to_rseq(struct imapc_msgmap *msgmap,
			      uint32_t uid, uint32_t *rseq_r)
{
	const uint32_t *p, *first;

	p = array_bsearch(&msgmap->uids, &uid, uint32_cmp);
	if (p == NULL) {
		*rseq_r = 0;
		return FALSE;
	}

	first = array_front(&msgmap->uids);
	*rseq_r = (p - first) + 1;
	return TRUE;
}

void imapc_msgmap_append(struct imapc_msgmap *msgmap,
			 uint32_t rseq, uint32_t uid)
{
	i_assert(rseq == imapc_msgmap_count(msgmap) + 1);
	i_assert(uid >= msgmap->uid_next);

	msgmap->uid_next = uid + 1;
	array_push_back(&msgmap->uids, &uid);
}

void imapc_msgmap_expunge(struct imapc_msgmap *msgmap, uint32_t rseq)
{
	i_assert(rseq > 0);
	i_assert(rseq <= imapc_msgmap_count(msgmap));

	array_delete(&msgmap->uids, rseq-1, 1);
}

void imapc_msgmap_reset(struct imapc_msgmap *msgmap)
{
	array_clear(&msgmap->uids);
	msgmap->uid_next = 1;
}
