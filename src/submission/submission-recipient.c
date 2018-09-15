/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"

#include "submission-backend.h"
#include "submission-recipient.h"

struct submission_recipient *
submission_recipient_create(struct client *client, struct smtp_address *path)
{
	struct submission_recipient *rcpt;

	rcpt = i_new(struct submission_recipient, 1);
	rcpt->backend = client->state.backend;
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
	struct submission_backend *backend = rcpt->backend;
	struct client *client = backend->client;
	struct submission_backend *const *bknd_idx;
	bool backend_found = FALSE;

	rcpt->path = trcpt->path;
	rcpt->index = index;

	array_append(&client->rcpt_to, &rcpt, 1);

	array_foreach(&client->rcpt_backends, bknd_idx) {
		if (*bknd_idx == backend) {
			backend_found = TRUE;
			break;
		}
	}
	if (!backend_found)
		array_append(&client->rcpt_backends, &backend, 1);
}
