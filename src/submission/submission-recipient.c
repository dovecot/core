/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"

#include "submission-recipient.h"

struct submission_recipient *
submission_recipient_create(struct client *client, struct smtp_address *path)
{
	struct submission_recipient *rcpt;

	rcpt = i_new(struct submission_recipient, 1);
	rcpt->client = client;
	rcpt->path = path;

	return rcpt;
}

void submission_recipient_destroy(struct submission_recipient **_rcpt)
{
	struct submission_recipient *rcpt = *_rcpt;

	*_rcpt = NULL;

	i_free(rcpt);
}

void submission_recipient_finished(struct submission_recipient *rcpt,
				   struct smtp_server_recipient *trcpt,
				   unsigned int index)
{
	struct client *client = rcpt->client;

	rcpt->path = trcpt->path;
	rcpt->index = index;

	array_append(&client->rcpt_to, &rcpt, 1);
}
