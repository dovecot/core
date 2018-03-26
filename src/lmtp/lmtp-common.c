/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "smtp-server.h"
#include "lmtp-common.h"

void lmtp_recipient_init(struct lmtp_recipient *rcpt,
			 struct client *client,
			 enum lmtp_recipient_type type,
			 struct smtp_server_cmd_ctx *cmd,
			 struct smtp_server_cmd_rcpt *data)
{
	rcpt->client = client;
	rcpt->type = type;
	rcpt->rcpt_cmd = cmd;
	rcpt->path = data->path;
}

void lmtp_recipient_finish(struct lmtp_recipient *rcpt,
			   struct smtp_server_recipient *trcpt,
			   unsigned int index)
{
	trcpt->context = rcpt;

	rcpt->rcpt = trcpt;
	rcpt->index = index;
	rcpt->rcpt_cmd = NULL;
}

struct lmtp_recipient *
lmtp_recipient_find_duplicate(struct lmtp_recipient *rcpt,
			      struct smtp_server_transaction *trans)
{
	struct smtp_server_recipient *drcpt;
	struct lmtp_recipient *dup_rcpt;

	i_assert(rcpt->rcpt != NULL);
	drcpt = smtp_server_transaction_find_rcpt_duplicate(trans, rcpt->rcpt);
	if (drcpt == NULL)
		return NULL;

	dup_rcpt = drcpt->context;
	i_assert(dup_rcpt->rcpt == drcpt);
	i_assert(dup_rcpt->type == rcpt->type);

	return dup_rcpt;
}

