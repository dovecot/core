/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "smtp-address.h"

#include "smtp-server-private.h"

struct smtp_server_recipient *
smtp_server_recipient_create(struct smtp_server_connection *conn,
			     const struct smtp_address *rcpt_to)
{
	struct smtp_server_recipient *rcpt;
	pool_t pool;

	pool = pool_alloconly_create("smtp server recipient", 512);
	rcpt = p_new(pool, struct smtp_server_recipient, 1);
	rcpt->pool = pool;
	rcpt->conn = conn;
	rcpt->path = smtp_address_clone(pool, rcpt_to);

	return rcpt;
}

void smtp_server_recipient_destroy(struct smtp_server_recipient **_rcpt)
{
	struct smtp_server_recipient *rcpt = *_rcpt;

	*_rcpt = NULL;

	if (rcpt == NULL)
		return;

	pool_unref(&rcpt->pool);
}

void smtp_server_recipient_approved(struct smtp_server_recipient *rcpt)
{
	struct smtp_server_transaction *trans = rcpt->conn->state.trans;

	i_assert(trans != NULL);

	smtp_server_transaction_add_rcpt(trans, rcpt);
}
