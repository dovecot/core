#ifndef __INDEX_EXPUNGE_H
#define __INDEX_EXPUNGE_H

#include "mail-storage.h"
#include "index-mail.h"

struct mail_expunge_context {
        struct index_mailbox *ibox;
	struct index_mail mail;
	int expunge_all, fetch_next, failed;

	unsigned int seq;
	struct mail_index_record *rec;

	unsigned int first_seq, last_seq;
	struct mail_index_record *first_rec, *last_rec;
};

struct mail_expunge_context *
index_storage_expunge_init(struct mailbox *box,
			   enum mail_fetch_field wanted_fields,
			   int expunge_all);
int index_storage_expunge_deinit(struct mail_expunge_context *ctx);
struct mail *index_storage_expunge_fetch_next(struct mail_expunge_context *ctx);
int index_storage_expunge(struct mail *mail, struct mail_expunge_context *ctx,
			  unsigned int *seq_r, int notify);

#endif
