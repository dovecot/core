/* Copyright (c) 2009-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "master-service.h"
#include "client.h"
#include "lmtp-local.h"

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


