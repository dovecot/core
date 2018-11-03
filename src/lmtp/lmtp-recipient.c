/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "smtp-server.h"
#include "lmtp-recipient.h"

void lmtp_recipient_init(struct lmtp_recipient *lrcpt,
			 struct client *client,
			 enum lmtp_recipient_type type,
			 struct smtp_server_recipient *rcpt)
{
	lrcpt->client = client;
	lrcpt->type = type;
	lrcpt->rcpt = rcpt;
}

struct lmtp_recipient *
lmtp_recipient_find_duplicate(struct lmtp_recipient *lrcpt,
			      struct smtp_server_transaction *trans)
{
	struct smtp_server_recipient *drcpt;
	struct lmtp_recipient *dup_lrcpt;

	i_assert(lrcpt->rcpt != NULL);
	drcpt = smtp_server_transaction_find_rcpt_duplicate(trans, lrcpt->rcpt);
	if (drcpt == NULL)
		return NULL;

	dup_lrcpt = drcpt->context;
	i_assert(dup_lrcpt->rcpt == drcpt);
	i_assert(dup_lrcpt->type == lrcpt->type);

	return dup_lrcpt;
}

