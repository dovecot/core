/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ostream.h"
#include "str.h"
#include "mail-index.h"
#include "mail-modifylog.h"
#include "mail-custom-flags.h"
#include "index-storage.h"
#include "index-messageset.h"
#include "index-mail.h"

static struct mail *
fetch_record(struct index_mailbox *ibox, struct mail_index_record *rec,
	     unsigned int idx_seq, enum mail_fetch_field wanted_fields)
{
	if (ibox->fetch_mail.pool != NULL)
		index_mail_deinit(&ibox->fetch_mail);

	index_mail_init(ibox, &ibox->fetch_mail, wanted_fields, NULL);
	if (index_mail_next(&ibox->fetch_mail, rec, idx_seq, FALSE) <= 0)
		return NULL;

	return &ibox->fetch_mail.mail;
}

struct mail *index_storage_fetch_uid(struct mailbox *box, unsigned int uid,
				     enum mail_fetch_field wanted_fields)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
	struct mail_index_record *rec;
	unsigned int seq;

	i_assert(ibox->index->lock_type != MAIL_LOCK_UNLOCK);

	rec = ibox->index->lookup_uid_range(ibox->index, uid, uid, &seq);
	if (rec == NULL)
		return NULL;

	return fetch_record(ibox, rec, seq, wanted_fields);
}

struct mail *index_storage_fetch_seq(struct mailbox *box, unsigned int seq,
				     enum mail_fetch_field wanted_fields)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
        struct mail_index_record *rec;
	unsigned int expunges_before;

	i_assert(ibox->index->lock_type != MAIL_LOCK_UNLOCK);

	if (mail_modifylog_seq_get_expunges(ibox->index->modifylog, seq, seq,
					    &expunges_before) == NULL)
		return NULL;

	seq -= expunges_before;
	rec = ibox->index->lookup(ibox->index, seq);
	if (rec == NULL)
		return NULL;

	return fetch_record(ibox, rec, seq, wanted_fields);
}
