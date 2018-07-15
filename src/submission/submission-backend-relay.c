/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"
#include "smtp-client-command.h"

#include "submission-commands.h"

/*
 * Common
 */

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
	/* RFC 4954, Section 6: 530 5.7.0 Authentication required

	   This response SHOULD be returned by any command other than AUTH,
	   EHLO, HELO, NOOP, RSET, or QUIT when server policy requires
	   authentication in order to perform the requested action and
	   authentication is not currently in force. */
	case 530:
		i_error("Relay server requires authentication: %s",
			smtp_reply_log(reply));
		client_destroy(client, "4.3.5",
			"Internal error occurred. "
			"Refer to server log for more information.");
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
