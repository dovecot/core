/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "base64.h"
#include "safe-memset.h"
#include "str.h"
#include "str-sanitize.h"
#include "strescape.h"
#include "dsasl-client.h"
#include "client.h"
#include "smtp-syntax.h"
#include "submission-login-settings.h"
#include "submission-proxy.h"

#include <ctype.h>

static const char *submission_proxy_state_names[SUBMISSION_PROXY_STATE_COUNT] = {
	"banner", "ehlo", "starttls", "tls-ehlo", "xclient", "authenticate"
};

static void proxy_free_password(struct client *client)
{
	if (client->proxy_password == NULL)
		return;

	safe_memset(client->proxy_password, 0, strlen(client->proxy_password));
	i_free_and_null(client->proxy_password);
}

static buffer_t *
proxy_compose_xclient_forward(struct submission_client *client)
{
	const char *const *arg;
	string_t *str;

	if (*client->common.auth_passdb_args == NULL)
		return NULL;

	str = t_str_new(128);
	for (arg = client->common.auth_passdb_args; *arg != NULL; arg++) {
		if (strncasecmp(*arg, "forward_", 8) == 0) {
			if (str_len(str) > 0)
				str_append_c(str, '\t');
			str_append_tabescaped(str, (*arg)+8);
		}
	}

	return t_base64_encode(0, 0, str_data(str), str_len(str));
}

static void
proxy_send_xclient(struct submission_client *client, struct ostream *output)
{
	string_t *str;

	if ((client->proxy_capability & SMTP_CAPABILITY_XCLIENT) == 0 ||
	    client->common.proxy_not_trusted)
		return;

	/* remote supports XCLIENT, send it */
	str = t_str_new(128);
	str_append(str, "XCLIENT");
	if (str_array_icase_find(client->proxy_xclient, "ADDR")) {
		str_append(str, " ADDR=");
		str_append(str, net_ip2addr(&client->common.ip));
	}
	if (str_array_icase_find(client->proxy_xclient, "PORT"))
		str_printfa(str, " PORT=%u", client->common.remote_port);
	if (str_array_icase_find(client->proxy_xclient, "SESSION")) {
		str_append(str, " SESSION=");
		smtp_xtext_encode_cstr(
			str, client_get_session_id(&client->common));
	}
	if (str_array_icase_find(client->proxy_xclient, "TTL"))
		str_printfa(str, " TTL=%u", client->common.proxy_ttl - 1);
	if (str_array_icase_find(client->proxy_xclient, "FORWARD")) {
		buffer_t *fwd = proxy_compose_xclient_forward(client);

		if (fwd != NULL) {
			str_append(str, " FORWARD=");
			smtp_xtext_encode(str, fwd->data, fwd->used);
		}
	}
	str_append(str, "\r\n");
	o_stream_nsend(output, str_data(str), str_len(str));
	client->proxy_state = SUBMISSION_PROXY_XCLIENT;
}

static int
proxy_send_login(struct submission_client *client, struct ostream *output)
{
	struct dsasl_client_settings sasl_set;
	const unsigned char *sasl_output;
	size_t len;
	const char *mech_name, *error;
	string_t *str;

	if ((client->proxy_capability & SMTP_CAPABILITY_AUTH) == 0) {
		/* Prevent sending credentials to a server that has login
		   disabled; i.e., due to the lack of TLS */
		login_proxy_failed(client->common.login_proxy,
			login_proxy_get_event(client->common.login_proxy),
			LOGIN_PROXY_FAILURE_TYPE_REMOTE_CONFIG,
			"Authentication support not advertised (TLS required?)");
		return -1;
	}

	i_assert(client->common.proxy_ttl > 1);
	proxy_send_xclient(client, output);

	str = t_str_new(128);

	if (client->common.proxy_mech == NULL)
		client->common.proxy_mech = &dsasl_client_mech_plain;

	i_assert(client->common.proxy_sasl_client == NULL);
	i_zero(&sasl_set);
	sasl_set.authid = client->common.proxy_master_user != NULL ?
		client->common.proxy_master_user : client->common.proxy_user;
	sasl_set.authzid = client->common.proxy_user;
	sasl_set.password = client->common.proxy_password;
	client->common.proxy_sasl_client =
		dsasl_client_new(client->common.proxy_mech, &sasl_set);
	mech_name = dsasl_client_mech_get_name(client->common.proxy_mech);

	str_printfa(str, "AUTH %s ", mech_name);
	if (dsasl_client_output(client->common.proxy_sasl_client,
				&sasl_output, &len, &error) < 0) {
		const char *reason = t_strdup_printf(
			"SASL mechanism %s init failed: %s",
			mech_name, error);
		login_proxy_failed(client->common.login_proxy,
			login_proxy_get_event(client->common.login_proxy),
			LOGIN_PROXY_FAILURE_TYPE_INTERNAL, reason);
		return -1;
	}
	if (len == 0)
		str_append_c(str, '=');
	else
		base64_encode(sasl_output, len, str);
	str_append(str, "\r\n");
	o_stream_nsend(output, str_data(str), str_len(str));

	proxy_free_password(&client->common);

	if (client->proxy_state != SUBMISSION_PROXY_XCLIENT)
		client->proxy_state = SUBMISSION_PROXY_AUTHENTICATE;
	return 0;
}

static int
submission_proxy_continue_sasl_auth(struct client *client, struct ostream *output,
				    const char *line)
{
	string_t *str;
	const unsigned char *data;
	size_t data_len;
	const char *error;
	int ret;

	str = t_str_new(128);
	if (base64_decode(line, strlen(line), NULL, str) < 0) {
		login_proxy_failed(client->login_proxy,
			login_proxy_get_event(client->login_proxy),
			LOGIN_PROXY_FAILURE_TYPE_PROTOCOL,
			"Invalid base64 data in AUTH response");
		return -1;
	}
	ret = dsasl_client_input(client->proxy_sasl_client,
				 str_data(str), str_len(str), &error);
	if (ret == 0) {
		ret = dsasl_client_output(client->proxy_sasl_client,
					  &data, &data_len, &error);
	}
	if (ret < 0) {
		const char *reason = t_strdup_printf(
			"Invalid authentication data: %s", error);
		login_proxy_failed(client->login_proxy,
			login_proxy_get_event(client->login_proxy),
			LOGIN_PROXY_FAILURE_TYPE_PROTOCOL, reason);
		return -1;
	}
	i_assert(ret == 0);

	str_truncate(str, 0);
	base64_encode(data, data_len, str);
	str_append(str, "\r\n");

	o_stream_nsend(output, str_data(str), str_len(str));
	return 0;
}

static const char *
strip_enhanced_code(const char *text, const char **enh_code_r)
{
	const char *p = text;
	unsigned int digits;

	*enh_code_r = NULL;

	if (*p != '2' && *p != '4' && *p != '5')
		return text;
	p++;
	if (*p != '.')
		return text;
	p++;

	digits = 0;
	while (i_isdigit(*p) && digits < 3) {
		p++;
		digits++;
	}
	if (*p != '.')
		return text;
	p++;

	digits = 0;
	while (i_isdigit(*p) && digits < 3) {
		p++;
		digits++;
	}
	if (*p != ' ')
		return text;
	*enh_code_r = t_strdup_until(text, p);
	p++;
	return p;
}

static void
submission_proxy_success_reply_sent(
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct submission_client *subm_client)
{
	client_proxy_finish_destroy_client(&subm_client->common);
}

int submission_proxy_parse_line(struct client *client, const char *line)
{
	struct submission_client *subm_client =
		container_of(client, struct submission_client, common);
	struct smtp_server_cmd_ctx *cmd = subm_client->pending_auth;
	struct smtp_server_command *command = cmd->cmd;
	struct ostream *output;
	enum login_proxy_ssl_flags ssl_flags;
	bool last_line = FALSE, invalid_line = FALSE;
	const char *text = NULL, *enh_code = NULL;
	unsigned int status = 0;

	i_assert(!client->destroyed);
	i_assert(cmd != NULL);

	if ((line[3] != ' ' && line[3] != '-') ||
	    str_parse_uint(line, &status, &text) < 0 ||
	    status < 200 || status >= 560) {
		invalid_line = TRUE;
	} else {
		text++;

		if ((subm_client->proxy_capability &
		    SMTP_CAPABILITY_ENHANCEDSTATUSCODES) != 0)
			text = strip_enhanced_code(text, &enh_code);
	}
	if (subm_client->proxy_reply_status != 0 &&
	    subm_client->proxy_reply_status != status) {
		const char *reason = t_strdup_printf(
			"Inconsistent SMTP reply: %s (status != %u)",
			str_sanitize(line, 160),
			subm_client->proxy_reply_status);
		login_proxy_failed(client->login_proxy,
				   login_proxy_get_event(client->login_proxy),
				   LOGIN_PROXY_FAILURE_TYPE_PROTOCOL, reason);
		return -1;
	}
	if (line[3] == ' ') {
		last_line = TRUE;
		subm_client->proxy_reply_status = 0;
	} else {
		subm_client->proxy_reply_status = status;
	}

	output = login_proxy_get_ostream(client->login_proxy);
	switch (subm_client->proxy_state) {
	case SUBMISSION_PROXY_BANNER:
		/* this is a banner */
		if (invalid_line || status != 220) {
			const char *reason = t_strdup_printf(
				"Invalid banner: %s", str_sanitize(line, 160));
			login_proxy_failed(client->login_proxy,
				login_proxy_get_event(client->login_proxy),
				LOGIN_PROXY_FAILURE_TYPE_PROTOCOL, reason);
			return -1;
		}
		if (!last_line)
			return 0;

		subm_client->proxy_state = SUBMISSION_PROXY_EHLO;
		o_stream_nsend_str(output, t_strdup_printf("EHLO %s\r\n",
			subm_client->set->hostname));
		return 0;
	case SUBMISSION_PROXY_EHLO:
	case SUBMISSION_PROXY_TLS_EHLO:
		if (invalid_line || (status / 100) != 2) {
			const char *reason = t_strdup_printf(
				"Invalid EHLO line: %s",
				str_sanitize(line, 160));
			login_proxy_failed(client->login_proxy,
				login_proxy_get_event(client->login_proxy),
				LOGIN_PROXY_FAILURE_TYPE_PROTOCOL, reason);
			return -1;
		}

		if (strncasecmp(text, "XCLIENT ", 8) == 0) {
			subm_client->proxy_capability |=
				SMTP_CAPABILITY_XCLIENT;
			i_free_and_null(subm_client->proxy_xclient);
			subm_client->proxy_xclient = p_strarray_dup(
				default_pool, t_strsplit_spaces(text + 8, " "));
		} else if (strncasecmp(text, "STARTTLS", 9) == 0) {
			subm_client->proxy_capability |=
				SMTP_CAPABILITY_STARTTLS;
		} else if (strncasecmp(text, "AUTH", 4) == 0 &&
			text[4] == ' ' && text[5] != '\0') {
			subm_client->proxy_capability |=
				SMTP_CAPABILITY_AUTH;
		} else if (strcasecmp(text, "ENHANCEDSTATUSCODES") == 0) {
			subm_client->proxy_capability |=
				SMTP_CAPABILITY_ENHANCEDSTATUSCODES;
		}
		if (!last_line)
			return 0;

		if (subm_client->proxy_state == SUBMISSION_PROXY_TLS_EHLO) {
			if (proxy_send_login(subm_client, output) < 0)
				return -1;
			return 0;
		}

		ssl_flags = login_proxy_get_ssl_flags(client->login_proxy);
		if ((ssl_flags & PROXY_SSL_FLAG_STARTTLS) == 0) {
			if (proxy_send_login(subm_client, output) < 0)
				return -1;
		} else {
			if ((subm_client->proxy_capability &
			     SMTP_CAPABILITY_STARTTLS) == 0) {
				login_proxy_failed(client->login_proxy,
					login_proxy_get_event(client->login_proxy),
					LOGIN_PROXY_FAILURE_TYPE_REMOTE_CONFIG,
					"STARTTLS not supported");
				return -1;
			}
			o_stream_nsend_str(output, "STARTTLS\r\n");
			subm_client->proxy_state = SUBMISSION_PROXY_STARTTLS;
		}
		return 0;
	case SUBMISSION_PROXY_STARTTLS:
		if (invalid_line || status != 220) {
			const char *reason = t_strdup_printf(
				"STARTTLS failed: %s",
				str_sanitize(line, 160));
			login_proxy_failed(client->login_proxy,
				login_proxy_get_event(client->login_proxy),
				LOGIN_PROXY_FAILURE_TYPE_REMOTE, reason);
			return -1;
		}
		if (!last_line)
			return 0;
		if (login_proxy_starttls(client->login_proxy) < 0)
			return -1;
		/* i/ostreams changed. */
		output = login_proxy_get_ostream(client->login_proxy);

		subm_client->proxy_capability = 0;
		i_free_and_null(subm_client->proxy_xclient);
		subm_client->proxy_state = SUBMISSION_PROXY_TLS_EHLO;
		o_stream_nsend_str(output, t_strdup_printf(
			"EHLO %s\r\n", subm_client->set->hostname));
		return 0;
	case SUBMISSION_PROXY_XCLIENT:
		if (invalid_line || (status / 100) != 2) {
			const char *reason = t_strdup_printf(
				"XCLIENT failed: %s", str_sanitize(line, 160));
			login_proxy_failed(client->login_proxy,
				login_proxy_get_event(client->login_proxy),
				LOGIN_PROXY_FAILURE_TYPE_REMOTE, reason);
			return -1;
		}
		if (!last_line)
			return 0;
		subm_client->proxy_state = SUBMISSION_PROXY_AUTHENTICATE;
		return 0;
	case SUBMISSION_PROXY_AUTHENTICATE:
		if (invalid_line)
			break;
		if (status == 334 && client->proxy_sasl_client != NULL) {
			/* continue SASL authentication */
			if (submission_proxy_continue_sasl_auth(client, output,
								text) < 0)
				return -1;
			return 0;
		}

		if (subm_client->proxy_reply == NULL) {
			subm_client->proxy_reply = smtp_server_reply_create(
				command, status, enh_code);
		}
		smtp_server_reply_add_text(subm_client->proxy_reply, text);

		if (!last_line)
			return 0;
		if ((status / 100) != 2)
			break;

		smtp_server_connection_input_lock(cmd->conn);

		smtp_server_command_add_hook(
			command, SMTP_SERVER_COMMAND_HOOK_DESTROY,
			submission_proxy_success_reply_sent, subm_client);

		subm_client->pending_auth = NULL;

		/* Login successful. Send this reply to client. */
		smtp_server_reply_submit(subm_client->proxy_reply);

		return 1;
	case SUBMISSION_PROXY_STATE_COUNT:
		i_unreached();
	}

	/* Login failed. Pass through the error message to client.

	   If the backend server isn't Dovecot, the error message may
	   be different from Dovecot's "user doesn't exist" error. This
	   would allow an attacker to find out what users exist in the
	   system.

	   The optimal way to handle this would be to replace the
	   backend's "password failed" error message with Dovecot's
	   AUTH_FAILED_MSG, but this would require a new setting and
	   the sysadmin to actually bother setting it properly.

	   So for now we'll just forward the error message. This
	   shouldn't be a real problem since of course everyone will
	   be using only Dovecot as their backend :) */
	i_assert((status / 100) != 2);
	i_assert(subm_client->proxy_reply != NULL);
	smtp_server_reply_submit(subm_client->proxy_reply);
	subm_client->pending_auth = NULL;

	if (client->set->auth_verbose) {
		client_proxy_log_failure(client, text);
	}
	login_proxy_failed(client->login_proxy,
			   login_proxy_get_event(client->login_proxy),
			   LOGIN_PROXY_FAILURE_TYPE_AUTH, NULL);
	return -1;
}

void submission_proxy_reset(struct client *client)
{
	struct submission_client *subm_client =
		container_of(client, struct submission_client, common);

	subm_client->proxy_state = SUBMISSION_PROXY_BANNER;
	subm_client->proxy_capability = 0;
	i_free_and_null(subm_client->proxy_xclient);
	subm_client->proxy_reply_status = 0;
	subm_client->proxy_reply = NULL;
}

void submission_proxy_error(struct client *client, const char *text)
{
	struct submission_client *subm_client =
		container_of(client, struct submission_client, common);

	struct smtp_server_cmd_ctx *cmd = subm_client->pending_auth;
	if (cmd != NULL) {
		subm_client->pending_auth = NULL;
		smtp_server_reply(cmd, 535, "5.7.8", "%s", text);
	}
}

const char *submission_proxy_get_state(struct client *client)
{
	struct submission_client *subm_client =
		container_of(client, struct submission_client, common);

	i_assert(subm_client->proxy_state < SUBMISSION_PROXY_STATE_COUNT);
	return submission_proxy_state_names[subm_client->proxy_state];
}
