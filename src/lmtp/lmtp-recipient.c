/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lmtp-common.h"
#include "array.h"
#include "smtp-address.h"
#include "smtp-server.h"
#include "lda-settings.h"
#include "lmtp-recipient.h"
#include "lmtp-client.h"

struct lmtp_recipient_module_register
lmtp_recipient_module_register = { 0 };

struct lmtp_recipient *
lmtp_recipient_create(struct client *client,
		      struct smtp_server_transaction *trans,
		      struct smtp_server_recipient *rcpt)
{
	struct lmtp_recipient *lrcpt;
	const char *username, *detail;
	char delim = '\0';

	lrcpt = p_new(rcpt->pool, struct lmtp_recipient, 1);
	lrcpt->rcpt = rcpt;	
	lrcpt->client = client;

	smtp_address_detail_parse_temp(
		client->unexpanded_lda_set->recipient_delimiter,
		rcpt->path, &username, &delim, &detail);
	i_assert(*username != '\0');

	lrcpt->username = p_strdup(rcpt->pool, username);
	lrcpt->detail = p_strdup(rcpt->pool, detail);
	lrcpt->delim = delim;

	/* Make user name and detail available in the recipient event. The
	   mail_user event (for local delivery) also adds the user field, but
	   adding it here makes it available to the recipient event in general.
	   Additionally, the auth lookups performed for local and proxy delivery
	   can further override the "user" recipient event when the auth service
	   returns a different user name. In any case, we provide the initial
	   value here.
	 */
	event_add_str(rcpt->event, "user", lrcpt->username);
	if (detail[0] != '\0')
		event_add_str(rcpt->event, "detail", lrcpt->detail);

	rcpt->context = lrcpt;

	p_array_init(&lrcpt->module_contexts, rcpt->pool, 5);

	/* Use a unique session_id for each mail delivery. This is especially
	   important for stats process to not see duplicate sessions. */
	if (client->state.session_id_seq++ == 0)
		lrcpt->session_id = trans->id;
	else {
		lrcpt->session_id = p_strdup_printf(rcpt->pool, "%s:R%u",
			trans->id, client->state.session_id_seq);
	}
	event_add_str(rcpt->event, "session", lrcpt->session_id);

	return lrcpt;
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

