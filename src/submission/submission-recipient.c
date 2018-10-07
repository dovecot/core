/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"

#include "submission-backend.h"
#include "submission-recipient.h"

struct submission_recipient_module_register
submission_recipient_module_register = { 0 };

struct submission_recipient *
submission_recipient_create(struct client *client, struct smtp_address *path)
{
	struct submission_recipient *srcpt;
	pool_t pool;

	pool = pool_alloconly_create("submission recipient", 512);
	srcpt = p_new(pool, struct submission_recipient, 1);
	srcpt->pool = pool;
	srcpt->backend = client->state.backend;
	srcpt->path = path;

	p_array_init(&srcpt->module_contexts, srcpt->pool, 5);

	return srcpt;
}

void submission_recipient_destroy(struct submission_recipient **_srcpt)
{
	struct submission_recipient *srcpt = *_srcpt;

	*_srcpt = NULL;

	pool_unref(&srcpt->pool);
}

void submission_recipient_finished(struct submission_recipient *srcpt,
				   struct smtp_server_recipient *trcpt,
				   unsigned int index)
{
	struct submission_backend *backend = srcpt->backend;
	struct client *client = backend->client;
	struct submission_backend *const *bknd_idx;
	bool backend_found = FALSE;

	srcpt->path = trcpt->path;
	srcpt->index = index;

	array_append(&client->rcpt_to, &srcpt, 1);

	array_foreach(&client->rcpt_backends, bknd_idx) {
		if (*bknd_idx == backend) {
			backend_found = TRUE;
			break;
		}
	}
	if (!backend_found)
		array_append(&client->rcpt_backends, &backend, 1);
}
