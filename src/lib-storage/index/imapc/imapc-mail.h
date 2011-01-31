#ifndef IMAPC_MAIL_H
#define IMAPC_MAIL_H

#include "index-mail.h"

struct imapc_mail {
	struct index_mail imail;
	unsigned int searching:1;
	unsigned int fetch_one:1;
};

extern struct mail_vfuncs imapc_mail_vfuncs;

struct mail *
imapc_mail_alloc(struct mailbox_transaction_context *t,
		 enum mail_fetch_field wanted_fields,
		 struct mailbox_header_lookup_ctx *wanted_headers);
int imapc_mail_fetch(struct mail *mail, enum mail_fetch_field fields);

#endif
