/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "base64.h"
#include "buffer.h"
#include "hex-binary.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "safe-memset.h"
#include "str.h"
#include "str-sanitize.h"
#include "auth-client.h"
#include "master-service-ssl-settings.h"
#include "client.h"
#include "client-authenticate.h"
#include "submission-proxy.h"
#include "submission-login-settings.h"

static void cmd_helo_reply(struct submission_client *subm_client,
			   struct smtp_server_cmd_ctx *cmd,
			   struct smtp_server_cmd_helo *data)
{
	struct client *client = &subm_client->common;
	enum smtp_capability backend_caps = subm_client->backend_capabilities;
	struct smtp_server_reply *reply;

	reply = smtp_server_reply_create_ehlo(cmd->cmd);
	if (!data->helo.old_smtp) {
		if ((backend_caps & SMTP_CAPABILITY_8BITMIME) != 0)
			smtp_server_reply_ehlo_add(reply, "8BITMIME");

		if (client->secured ||
			strcmp(client->ssl_set->ssl, "required") != 0) {
			const struct auth_mech_desc *mechs;
			unsigned int count, i;
			string_t *param = t_str_new(128);

			mechs = sasl_server_get_advertised_mechs(client,
								 &count);
			for (i = 0; i < count; i++) {
				if (i > 0)
					str_append_c(param, ' ');
				str_append(param, mechs[i].name);
			}
			smtp_server_reply_ehlo_add_param(reply,
				"AUTH", "%s", str_c(param));
		}

		if ((backend_caps & SMTP_CAPABILITY_BINARYMIME) != 0 &&
		    (backend_caps & SMTP_CAPABILITY_CHUNKING) != 0)
			smtp_server_reply_ehlo_add(reply, "BINARYMIME");
		smtp_server_reply_ehlo_add_param(reply,
			"BURL", "imap");
		smtp_server_reply_ehlo_add(reply,
			"CHUNKING");
		if ((backend_caps & SMTP_CAPABILITY_DSN) != 0)
			smtp_server_reply_ehlo_add(reply, "DSN");
		smtp_server_reply_ehlo_add(reply,
			"ENHANCEDSTATUSCODES");

		if (subm_client->set->submission_max_mail_size > 0) {
			smtp_server_reply_ehlo_add_param(reply,
				"SIZE", "%zu",
				subm_client->set->submission_max_mail_size);
		} else {
			smtp_server_reply_ehlo_add(reply, "SIZE");
		}

		if (client_is_tls_enabled(client) && !client->tls)
			smtp_server_reply_ehlo_add(reply, "STARTTLS");
		smtp_server_reply_ehlo_add(reply, "PIPELINING");
		if ((backend_caps & SMTP_CAPABILITY_VRFY) != 0)
			smtp_server_reply_ehlo_add(reply, "VRFY");
		smtp_server_reply_ehlo_add_xclient(reply);
	}
	smtp_server_reply_submit(reply);
}

int cmd_helo(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_cmd_helo *data)
{
	struct submission_client *subm_client = conn_ctx;

	T_BEGIN {
		cmd_helo_reply(subm_client, cmd, data);
	} T_END;

	return 1;
}

void submission_client_auth_result(struct client *client,
	enum client_auth_result result,
	const struct client_auth_reply *reply ATTR_UNUSED,
	const char *text)
{
	struct submission_client *subm_client =
		container_of(client, struct submission_client, common);
	struct smtp_server_cmd_ctx *cmd = subm_client->pending_auth;

	if (subm_client->conn == NULL)
		return;

	subm_client->pending_auth = NULL;
	i_assert(cmd != NULL);

	switch (result) {
	case CLIENT_AUTH_RESULT_SUCCESS:
		/* nothing to be done for SMTP */
		if (client->login_proxy != NULL)
			subm_client->pending_auth = cmd;
		break;
	case CLIENT_AUTH_RESULT_TEMPFAIL:
		/* RFC4954, Section 6:

		   454 4.7.0 Temporary authentication failure

		   This response to the AUTH command indicates that the
		   authentication failed due to a temporary server failure.
		 */
		smtp_server_reply(cmd, 454, "4.7.0", "%s", text);
		break;
	case CLIENT_AUTH_RESULT_ABORTED:
		/* RFC4954, Section 4:

		   If the client wishes to cancel the authentication exchange,
		   it issues a line with a single "*". If the server receives
		   such a response, it MUST reject the AUTH command by sending
		   a 501 reply. */
		smtp_server_reply(cmd, 501, "5.5.2", "%s", text);
		break;
	case CLIENT_AUTH_RESULT_INVALID_BASE64:
		/* RFC4954, Section 4:

		   If the server cannot [BASE64] decode any client response, it
		   MUST reject the AUTH command with a 501 reply (and an
		   enhanced status code of 5.5.2). */
		smtp_server_reply(cmd, 501, "5.5.2", "%s", text);
		break;
	case CLIENT_AUTH_RESULT_SSL_REQUIRED:
		/* RFC3207, Section 4:

		   A SMTP server that is not publicly referenced may choose to
		   require that the client perform a TLS negotiation before
		   accepting any commands.  In this case, the server SHOULD
		   return the reply code:

		   530 Must issue a STARTTLS command first

		   to every command other than NOOP, EHLO, STARTTLS, or QUIT.
		   If the client and server are using the ENHANCEDSTATUSCODES
		   ESMTP extension [RFC2034], the status code to be returned
		   SHOULD be 5.7.0. */
		smtp_server_reply(cmd, 530, "5.7.0", "%s", text);
		break;
	case CLIENT_AUTH_RESULT_MECH_SSL_REQUIRED:
		/* RFC5248, Section 2.4:

		   523 X.7.10 Encryption Needed

		   This indicates that an external strong privacy layer is
		   needed in order to use the requested authentication
		   mechanism. This is primarily intended for use with clear text
		   authentication mechanisms. A client that receives this may
		   activate a security layer such as TLS prior to
		   authenticating, or attempt to use a stronger mechanism. */
		smtp_server_reply(cmd, 523, "5.7.10", "%s", text);
		break;
	case CLIENT_AUTH_RESULT_MECH_INVALID:
		/* RFC4954, Section 4:

		   If the requested authentication mechanism is invalid (e.g.,
		   is not supported or requires an encryption layer), the server
		   rejects the AUTH command with a 504 reply.  If the server
		   supports the [ESMTP-CODES] extension, it SHOULD return a
		   5.5.4 enhanced response code. */
		smtp_server_reply(cmd, 504, "5.5.4", "%s", text);
		break;
	case CLIENT_AUTH_RESULT_LOGIN_DISABLED:
	case CLIENT_AUTH_RESULT_ANONYMOUS_DENIED:
		/* RFC5248, Section 2.4:

		   525 X.7.13 User Account Disabled

		   Sometimes a system administrator will have to disable a
		   user's account (e.g., due to lack of payment, abuse, evidence
		   of a break-in attempt, etc.). This error code occurs after a
		   successful authentication to a disabled account. This informs
		   the client that the failure is permanent until the user
		   contacts their system administrator to get the account
		   re-enabled. */
		smtp_server_reply(cmd, 525, "5.7.13", "%s", text);
		break;
	case CLIENT_AUTH_RESULT_PASS_EXPIRED:
	default:
		/* FIXME: RFC4954, Section 4:

		   If the client uses an initial-response argument to the AUTH
		   command with a SASL mechanism in which the client does not
		   begin the authentication exchange, the server MUST reject the
		   AUTH command with a 501 reply.  Servers using the enhanced
		   status codes extension [ESMTP-CODES] SHOULD return an
		   enhanced status code of 5.7.0 in this case.

		   >> Currently, this is checked at the server side, but only a
		      generic error is ever produced.
		*/
		/* NOTE: RFC4954, Section 4:

		   If, during an authentication exchange, the server receives a
		   line that is longer than the server's authentication buffer,
		   the server fails the AUTH command with the 500 reply. Servers
		   using the enhanced status codes extension [ESMTP-CODES]
		   SHOULD return an enhanced status code of 5.5.6 in this case.

		   >> Currently, client is disconnected from login-common.
		*/
		/* RFC4954, Section 4:

		   If the server is unable to authenticate the client, it SHOULD
		   reject the AUTH command with a 535 reply unless a more
		   specific error code is appropriate.

		   RFC4954, Section 6:

		   535 5.7.8  Authentication credentials invalid

		   This response to the AUTH command indicates that the
		   authentication failed due to invalid or insufficient
		   authentication credentials.
		 */
		smtp_server_reply(cmd, 535, "5.7.8", "%s", text);
		break;
	}
}

int cmd_auth_continue(void *conn_ctx,
		      struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		      const char *response)
{
	struct submission_client *subm_client = conn_ctx;
	struct client *client = &subm_client->common;

	if (strcmp(response, "*") == 0) {
		client_auth_abort(client);
		return 0;
	}

	client_auth_respond(client, response);
	return 0;
}

void submission_client_auth_send_challenge(struct client *client,
					   const char *data)
{
	struct submission_client *subm_client =
		container_of(client, struct submission_client, common);
	struct smtp_server_cmd_ctx *cmd = subm_client->pending_auth;

	i_assert(cmd != NULL);

	smtp_server_cmd_auth_send_challenge(cmd, data);
}

int cmd_auth(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_cmd_auth *data)
{
	struct submission_client *subm_client = conn_ctx;
	struct client *client = &subm_client->common;
	struct smtp_server_helo_data *helo;
	const char *prefix = "";

	i_assert(subm_client->pending_auth == NULL);

	helo = smtp_server_connection_get_helo_data(subm_client->conn);
	if (helo->domain_valid) {
		i_assert(helo->domain != NULL);
		prefix = helo->domain;
	}

	/* pass ehlo parameter to post-login service upon successful login */
	i_free(client->master_data_prefix);
	client->master_data_prefix = (void *)i_strdup(prefix);
	client->master_data_prefix_len = strlen(prefix) + 1;

	subm_client->pending_auth = cmd;

	(void)client_auth_begin(client, data->sasl_mech, data->initial_response);
	return 0;
}
