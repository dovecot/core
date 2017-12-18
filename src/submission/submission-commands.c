/* Copyright (c) 2013-2017 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "llist.h"
#include "istream.h"
#include "ostream.h"
#include "mail-storage.h"
#include "smtp-reply.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"

#include "submission-commands.h"

/* The command handling of the submission proxy service aims to follow the
   following rules:

   - Attempt to keep pipelined commands pipelined when proxying them to the
     actual relay service.
   - Don't forward commands if they're known to fail at the relay server. Errors
     can still occur if pipelined commands fail. Abort subsequent pending
     commands if such failures affect those commands.
   - Keep predictable errors consistent as much as possible; send our own reply
     if the error condition is clear (e.g. missing MAIL, RCPT).
*/

bool client_command_handle_proxy_reply(struct client *client,
	const struct smtp_reply *reply, struct smtp_reply *reply_r)
{
	*reply_r = *reply;

	switch (reply->status) {
	case SMTP_CLIENT_COMMAND_ERROR_ABORTED:
		return FALSE;
	case SMTP_CLIENT_COMMAND_ERROR_HOST_LOOKUP_FAILED:
	case SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED:
	case SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED:
		i_unreached();
		return FALSE;
	case SMTP_CLIENT_COMMAND_ERROR_CONNECTION_CLOSED:
	case SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST:
	case SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY:
	case SMTP_CLIENT_COMMAND_ERROR_TIMED_OUT:
		client_destroy(client,
			"4.4.0", "Lost connection to relay server");
		return FALSE;
	default:
		break;
	}

	if (!smtp_reply_has_enhanced_code(reply)) {
		reply_r->enhanced_code =
			SMTP_REPLY_ENH_CODE(reply->status / 100, 0, 0);
	}
	return TRUE;
}
