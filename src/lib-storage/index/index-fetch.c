/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"
#include "index-mail.h"

int index_storage_get_uids(struct mailbox *box,
			   uint32_t uid1, uint32_t uid2,
			   uint32_t *seq1_r, uint32_t *seq2_r)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;

	if (mail_index_lookup_uid_range(ibox->view, uid1, uid2,
					seq1_r, seq2_r) < 0) {
		mail_storage_set_index_error(ibox);
		return -1;
	}

	return 0;
}
