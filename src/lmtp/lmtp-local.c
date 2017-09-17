/* Copyright (c) 2009-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hostpid.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "master-service.h"
#include "smtp-address.h"
#include "lda-settings.h"
#include "lmtp-settings.h"
#include "client.h"
#include "main.h"
#include "lmtp-local.h"

#define ERRSTR_TEMP_MAILBOX_FAIL "451 4.3.0 <%s> Temporary internal error"

void client_rcpt_anvil_disconnect(const struct mail_recipient *rcpt)
{
	const struct mail_storage_service_input *input;

	if (!rcpt->anvil_connect_sent)
		return;

	input = mail_storage_service_user_get_input(rcpt->service_user);
	master_service_anvil_send(master_service, t_strconcat(
		"DISCONNECT\t", my_pid, "\t", master_service_get_name(master_service),
		"/", input->username, "\n", NULL));
}

void client_send_line_overquota(struct client *client,
			   const struct mail_recipient *rcpt, const char *error)
{
	struct lda_settings *lda_set =
		mail_storage_service_user_get_set(rcpt->service_user)[2];

	client_send_line(client, "%s <%s> %s",
		lda_set->quota_full_tempfail ? "452 4.2.2" : "552 5.2.2",
		smtp_address_encode(rcpt->address), error);
}

static int
lmtp_rcpt_to_is_over_quota(struct client *client,
			   const struct mail_recipient *rcpt)
{
	struct mail_user *user;
	struct mail_namespace *ns;
	struct mailbox *box;
	struct mailbox_status status;
	const char *errstr;
	enum mail_error error;
	int ret;

	if (!client->lmtp_set->lmtp_rcpt_check_quota)
		return 0;

	/* mail user will be created second time when mail is saved,
	   so it's session_id needs to be different,
	   but second time session_id needs to be the same as rcpt session_id and
	   mail user session id for the first rcpt should not overlap with session id
	   of the second recipient, so add custom ":quota" suffix to the session_id without
	   session_id counter increment, so next time mail user will get
	   the same session id as rcpt */
	ret = mail_storage_service_next_with_session_suffix(storage_service,
							    rcpt->service_user,
							    "quota",
							    &user, &errstr);

	if (ret < 0) {
		i_error("Failed to initialize user %s: %s",
			smtp_address_encode(rcpt->address), errstr);
		return -1;
	}

	ns = mail_namespace_find_inbox(user->namespaces);
	box = mailbox_alloc(ns->list, "INBOX", 0);
	mailbox_set_reason(box, "over-quota check");
	ret = mailbox_get_status(box, STATUS_CHECK_OVER_QUOTA, &status);
	if (ret < 0) {
		errstr = mailbox_get_last_error(box, &error);
		if (error == MAIL_ERROR_NOQUOTA) {
			client_send_line_overquota(client, rcpt, errstr);
			ret = 1;
		} else {
			i_error("mailbox_get_status(%s, STATUS_CHECK_OVER_QUOTA) "
				"failed: %s",
				mailbox_get_vname(box),
				mailbox_get_last_internal_error(box, NULL));
		}
	}
	mailbox_free(&box);
	mail_user_unref(&user);
	return ret;
}

bool cmd_rcpt_finish(struct client *client, struct mail_recipient *rcpt)
{
	int ret;

	if ((ret = lmtp_rcpt_to_is_over_quota(client, rcpt)) != 0) {
		if (ret < 0) {
			client_send_line(client, ERRSTR_TEMP_MAILBOX_FAIL,
					 smtp_address_encode(rcpt->address));
		}
		mail_storage_service_user_unref(&rcpt->service_user);
		return FALSE;
	}
	array_append(&client->state.rcpt_to, &rcpt, 1);
	client_send_line(client, "250 2.1.5 OK");
	return TRUE;
}
