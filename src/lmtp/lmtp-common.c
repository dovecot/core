/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "smtp-server.h"
#include "lmtp-common.h"

void lmtp_recipient_init(struct lmtp_recipient *rcpt,
			 struct client *client,
			 struct smtp_server_cmd_ctx *cmd,
			 struct smtp_server_cmd_rcpt *data)
{
	rcpt->client = client;
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
