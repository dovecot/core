/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"
#include "index-mail.h"

struct mail *
index_storage_fetch(struct mailbox_transaction_context *_t, uint32_t seq,
		    enum mail_fetch_field wanted_fields)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;
        const struct mail_index_record *rec;

	if (mail_index_lookup(t->trans_view, seq, &rec) < 0) {
		mail_storage_set_index_error(t->ibox);
		return NULL;
	}

	if (rec == NULL)
		return NULL;

	if (t->fetch_mail.pool != NULL)
		index_mail_deinit(&t->fetch_mail);

	index_mail_init(t, &t->fetch_mail, wanted_fields, NULL);
	if (index_mail_next(&t->fetch_mail, rec, seq, FALSE) <= 0)
		return NULL;

	return &t->fetch_mail.mail;
}

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
