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
	"banner", "ehlo", "starttls", "tls-ehlo", "xclient", "xclient-ehlo", "authenticate"
};

static void
submission_proxy_success_reply_sent(
	struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	struct submission_client *subm_client)
{
	client_proxy_finish_destroy_client(&subm_client->common);
}

static int
proxy_send_starttls(struct submission_client *client, struct ostream *output)
{
	enum auth_proxy_ssl_flags ssl_flags;

	ssl_flags = login_proxy_get_ssl_flags(client->common.login_proxy);
	if ((ssl_flags & AUTH_PROXY_SSL_FLAG_STARTTLS) == 0)
		return 0;

	if ((client->proxy_capability & SMTP_CAPABILITY_STARTTLS) == 0) {
		login_proxy_failed(
			client->common.login_proxy,
			login_proxy_get_event(client->common.login_proxy),
			LOGIN_PROXY_FAILURE_TYPE_REMOTE_CONFIG,
			"STARTTLS not supported");
		return -1;
	}
	o_stream_nsend_str(output, "STARTTLS\r\n");
	client->proxy_state = SUBMISSION_PROXY_STARTTLS;
	return 1;
}

static buffer_t *
proxy_compose_xclient_forward(struct submission_client *client)
{
	const char *const *arg, *value;
	string_t *str;

	if (*client->common.auth_passdb_args == NULL)
		return NULL;

	str = t_str_new(128);
	for (arg = client->common.auth_passdb_args; *arg != NULL; arg++) {
		if (str_begins_icase(*arg, "forward_", &value)) {
			if (str_len(str) > 0)
				str_append_c(str, '\t');
			str_append_tabescaped(str, value);
		}
	}
	if (str_len(str) == 0)
		return NULL;

	return t_base64_encode(0, 0, str_data(str), str_len(str));
}

static void
proxy_send_xclient_more_data(struct submission_client *client,
			     struct ostream *output, string_t *buf,
			     const char *field, const unsigned char *value,
			     size_t value_size)
{
	const size_t cmd_len = strlen("XCLIENT");
	size_t prev_len = str_len(buf);

	str_append_c(buf, ' ');
	str_append(buf, field);
	str_append_c(buf, '=');
	smtp_xtext_encode(buf, value, value_size);

	if (str_len(buf) > 512) {
		if (prev_len <= cmd_len)
			prev_len = str_len(buf);
		o_stream_nsend(output, str_data(buf), prev_len);
		o_stream_nsend(output, "\r\n", 2);
		client->proxy_xclient_replies_expected++;
		str_delete(buf, cmd_len, prev_len - cmd_len);
	}
}

static void
proxy_send_xclient_more(struct submission_client *client,
			struct ostream *output, string_t *buf,
			const char *field, const char *value)
{
	proxy_send_xclient_more_data(client, output, buf, field,
				     (const unsigned char *)value,
				     strlen(value));
}

static int
proxy_send_xclient(struct submission_client *client, struct ostream *output)
{
	string_t *str;

	if ((client->proxy_capability & SMTP_CAPABILITY_XCLIENT) == 0 ||
	    client->common.proxy_not_trusted)
		return 0;

	struct smtp_proxy_data proxy_data;

	smtp_server_connection_get_proxy_data(client->conn, &proxy_data);
	i_assert(client->common.proxy_ttl > 1);

	/* remote supports XCLIENT, send it */
	client->proxy_xclient_replies_expected = 0;
	str = t_str_new(128);
	str_append(str, "XCLIENT");
	if (str_array_icase_find(client->proxy_xclient, "HELO")) {
		if (proxy_data.helo != NULL) {
			proxy_send_xclient_more(client, output, str, "HELO",
						proxy_data.helo);
		} else {
			proxy_send_xclient_more(client, output, str, "HELO",
						"[UNAVAILABLE]");
		}
	}
	if (str_array_icase_find(client->proxy_xclient, "PROTO")) {
		const char *proto = "[UNAVAILABLE]";

		switch (proxy_data.proto) {
		case SMTP_PROXY_PROTOCOL_UNKNOWN:
			break;
		case SMTP_PROXY_PROTOCOL_SMTP:
			proto = "SMTP";
			break;
		case SMTP_PROXY_PROTOCOL_ESMTP:
			proto = "ESMTP";
			break;
		case SMTP_PROXY_PROTOCOL_LMTP:
			proto = "LMTP";
			break;
		}
		proxy_send_xclient_more(client, output, str, "PROTO", proto);
	}
	if (client->common.proxy_noauth &&
	    str_array_icase_find(client->proxy_xclient, "LOGIN")) {
		if (proxy_data.login != NULL) {
			proxy_send_xclient_more(client, output, str, "LOGIN",
						proxy_data.login);
		} else if (client->common.virtual_user != NULL) {
			proxy_send_xclient_more(client, output, str, "LOGIN",
						client->common.virtual_user);
		} else {
			proxy_send_xclient_more(client, output, str, "LOGIN",
						"[UNAVAILABLE]");
		}
	}
	if (str_array_icase_find(client->proxy_xclient, "TTL")) {
		proxy_send_xclient_more(
			client, output, str, "TTL",
			t_strdup_printf("%u",client->common.proxy_ttl - 1));
	}
	if (str_array_icase_find(client->proxy_xclient, "PORT")) {
		proxy_send_xclient_more(
			client, output, str, "PORT",
			t_strdup_printf("%u", client->common.remote_port));
	}
	if (str_array_icase_find(client->proxy_xclient, "ADDR")) {
		const char *addr = net_ip2addr(&client->common.ip);
		if (client->common.ip.family == AF_INET6)
			addr = t_strconcat("IPV6:", addr, NULL);
		proxy_send_xclient_more(client, output, str, "ADDR", addr);
	}
	if (str_array_icase_find(client->proxy_xclient, "SESSION")) {
		proxy_send_xclient_more(client, output, str, "SESSION",
					client_get_session_id(&client->common));
	}
	if (str_array_icase_find(client->proxy_xclient, "FORWARD")) {
		buffer_t *fwd = proxy_compose_xclient_forward(client);

		if (fwd != NULL) {
			proxy_send_xclient_more_data(
				client, output, str, "FORWARD",
				fwd->data, fwd->used);
		}
	}
	str_append(str, "\r\n");
	o_stream_nsend(output, str_data(str), str_len(str));
	client->proxy_state = SUBMISSION_PROXY_XCLIENT;
	client->proxy_xclient_replies_expected++;
	return 1;
}

static int
proxy_send_login(struct submission_client *client, struct ostream *output)
{
	struct dsasl_client_settings sasl_set;
	const unsigned char *sasl_output;
	size_t sasl_output_len;
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

	str_printfa(str, "AUTH %s", mech_name);
	if (dsasl_client_output(client->common.proxy_sasl_client,
				&sasl_output, &sasl_output_len, &error) < 0) {
		const char *reason = t_strdup_printf(
			"SASL mechanism %s init failed: %s",
			mech_name, error);
		login_proxy_failed(client->common.login_proxy,
			login_proxy_get_event(client->common.login_proxy),
			LOGIN_PROXY_FAILURE_TYPE_INTERNAL, reason);
		return -1;
	}

	string_t *sasl_output_base64 = t_str_new(
		MAX_BASE64_ENCODED_SIZE(sasl_output_len));
	base64_encode(sasl_output, sasl_output_len, sasl_output_base64);

	/* RFC 4954, Section 4:

	   Note that the AUTH command is still subject to the line length
	   limitations defined in [SMTP]. If use of the initial response
	   argument would cause the AUTH command to exceed this length, the
	   client MUST NOT use the initial response parameter (and instead
	   proceed as defined in Section 5.1 of [SASL]).

	   If the client is transmitting an initial response of zero length, it
	   MUST instead transmit the response as a single equals sign ("=").
	   This indicates that the response is present, but contains no data.
	 */

	i_assert(client->proxy_sasl_ir == NULL);
	if (str_len(sasl_output_base64) == 0)
		str_append(str, " =");
	else if ((5 + strlen(mech_name) + 1 + str_len(sasl_output_base64)) >
		 SMTP_BASE_LINE_LENGTH_LIMIT)
		client->proxy_sasl_ir = i_strdup(str_c(sasl_output_base64));
	else {
		str_append_c(str, ' ');
		str_append_str(str, sasl_output_base64);
	}

	str_append(str, "\r\n");
	o_stream_nsend(output, str_data(str), str_len(str));

	client->proxy_state = SUBMISSION_PROXY_AUTHENTICATE;
	return 0;
}

static int
proxy_handle_ehlo_reply(struct submission_client *client,
			struct ostream *output)
{
	struct smtp_server_cmd_ctx *cmd = client->pending_auth;
	int ret;

	switch (client->proxy_state) {
	case SUBMISSION_PROXY_EHLO:
		ret = proxy_send_starttls(client, output);
		if (ret < 0)
			return -1;
		if (ret != 0)
			return 0;
		/* Fall through */
	case SUBMISSION_PROXY_TLS_EHLO:
		ret = proxy_send_xclient(client, output);
		if (ret < 0)
			return -1;
		if (ret != 0) {
			client->proxy_capability = 0;
			i_free_and_null(client->proxy_xclient);
			o_stream_nsend_str(output, t_strdup_printf(
					   "EHLO %s\r\n",
					   client->set->hostname));
			return 0;
		}
		break;
	case SUBMISSION_PROXY_XCLIENT_EHLO:
		break;
	default:
		i_unreached();
	}

	if (client->common.proxy_noauth) {
		smtp_server_connection_input_lock(cmd->conn);

		smtp_server_command_add_hook(
			cmd->cmd, SMTP_SERVER_COMMAND_HOOK_DESTROY,
			submission_proxy_success_reply_sent, client);
		client->pending_auth = NULL;

		smtp_server_reply(cmd, 235, "2.7.0", "Logged in.");
		return 1;
	}

	return proxy_send_login(client, output);
}

static int
submission_proxy_continue_sasl_auth(struct client *client,
				    struct ostream *output, const char *line,
				    bool last_line)
{
	struct submission_client *subm_client =
		container_of(client, struct submission_client, common);
	string_t *str;
	const unsigned char *data;
	size_t data_len;
	const char *error;
	int ret;

	if (!last_line) {
		const char *reason = t_strdup_printf(
			"Server returned multi-line challenge: 334 %s",
			str_sanitize(line, 1024));
		login_proxy_failed(client->login_proxy,
			login_proxy_get_event(client->login_proxy),
			LOGIN_PROXY_FAILURE_TYPE_PROTOCOL, reason);
		return -1;
	}
	if (subm_client->proxy_sasl_ir != NULL) {
		if (*line == '\0') {
			/* Send initial response */
			o_stream_nsend(output, subm_client->proxy_sasl_ir,
				       strlen(subm_client->proxy_sasl_ir));
			o_stream_nsend_str(output, "\r\n");
			i_free(subm_client->proxy_sasl_ir);
			return 0;
		}
		const char *reason = t_strdup_printf(
			"Server sent unexpected server-first challenge: "
			"334 %s", str_sanitize(line, 1024));
		login_proxy_failed(client->login_proxy,
			login_proxy_get_event(client->login_proxy),
			LOGIN_PROXY_FAILURE_TYPE_PROTOCOL, reason);
		return -1;
	}

	str = t_str_new(128);
	if (base64_decode(line, strlen(line), str) < 0) {
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

static int
submission_proxy_parse_redirect(const char *resp, const char **userhostport_r,
				const char **error_r)
{
	const char *destuser, *host;
	struct ip_addr ip;
	in_port_t port;

	if (smtp_proxy_redirect_parse(resp, &destuser, &host, &ip, &port,
				      error_r) < 0)
		return -1;

	string_t *str = t_str_new(128);
	if (destuser != NULL)
		str_append(str, destuser);
	str_append_c(str, '@');
	if (ip.family == AF_INET)
		str_append(str, net_ip2addr(&ip));
	else if (ip.family == AF_INET6)
		str_printfa(str, "[%s]", net_ip2addr(&ip));
	else
		str_append(str, host);
	if (port != 0)
		str_printfa(str, ":%u", port);
	*userhostport_r = str_c(str);
	return 0;
}

static bool
submission_proxy_handle_redirect(struct client *client, unsigned int status,
				 const char *enh_code, const char *resp,
				 enum login_proxy_failure_type *failure_type_r,
				 const char **text_r)
{
	const char *error;

	if (!smtp_reply_code_is_proxy_redirect(status, enh_code))
		return FALSE;

	if (submission_proxy_parse_redirect(resp, text_r, &error) < 0) {
		e_debug(login_proxy_get_event(client->login_proxy),
			"Backend server returned invalid redirect "
			"'%03u %s %s': %s",
			status, enh_code, str_sanitize(resp, 160), error);
		*failure_type_r = LOGIN_PROXY_FAILURE_TYPE_AUTH_TEMPFAIL;
		*text_r = "Temporary internal proxy error";
		return TRUE;
	}

	*failure_type_r = LOGIN_PROXY_FAILURE_TYPE_AUTH_REDIRECT;
	return TRUE;
}

int submission_proxy_parse_line(struct client *client, const char *line)
{
	struct submission_client *subm_client =
		container_of(client, struct submission_client, common);
	struct smtp_server_cmd_ctx *cmd = subm_client->pending_auth;
	struct smtp_server_command *command = cmd->cmd;
	struct ostream *output;
	bool last_line = FALSE, invalid_line = FALSE;
	const char *suffix, *text = NULL, *enh_code = NULL;
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
	case SUBMISSION_PROXY_XCLIENT_EHLO:
		if (invalid_line || (status / 100) != 2) {
			const char *reason = t_strdup_printf(
				"Invalid EHLO line: %s",
				str_sanitize(line, 160));
			login_proxy_failed(client->login_proxy,
				login_proxy_get_event(client->login_proxy),
				LOGIN_PROXY_FAILURE_TYPE_PROTOCOL, reason);
			return -1;
		}

		if (str_begins_icase(text, "XCLIENT ", &suffix)) {
			subm_client->proxy_capability |=
				SMTP_CAPABILITY_XCLIENT;
			i_free_and_null(subm_client->proxy_xclient);
			subm_client->proxy_xclient = p_strarray_dup(
				default_pool, t_strsplit_spaces(suffix, " "));
		} else if (strcasecmp(text, "STARTTLS") == 0) {
			subm_client->proxy_capability |=
				SMTP_CAPABILITY_STARTTLS;
		} else if (str_begins_icase(text, "AUTH ", &suffix) &&
			   suffix[0] != '\0') {
			subm_client->proxy_capability |=
				SMTP_CAPABILITY_AUTH;
		} else if (strcasecmp(text, "ENHANCEDSTATUSCODES") == 0) {
			subm_client->proxy_capability |=
				SMTP_CAPABILITY_ENHANCEDSTATUSCODES;
		}
		if (!last_line)
			return 0;

		return proxy_handle_ehlo_reply(subm_client, output);
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
		i_assert(subm_client->proxy_xclient_replies_expected > 0);
		if (--subm_client->proxy_xclient_replies_expected > 0)
			return 0;
		subm_client->proxy_state = SUBMISSION_PROXY_XCLIENT_EHLO;
		return 0;
	case SUBMISSION_PROXY_AUTHENTICATE:
		if (invalid_line)
			break;
		if (status == 334 && client->proxy_sasl_client != NULL) {
			/* continue SASL authentication */
			if (submission_proxy_continue_sasl_auth(
				client, output, text, last_line) < 0)
				return -1;
			return 0;
		}

		i_assert(subm_client->proxy_reply == NULL);
		subm_client->proxy_reply = smtp_server_reply_create(
			command, status, enh_code);
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
	enum login_proxy_failure_type failure_type =
		LOGIN_PROXY_FAILURE_TYPE_AUTH;
	if ((status / 100) == 4)
		failure_type = LOGIN_PROXY_FAILURE_TYPE_AUTH_TEMPFAIL;
	else if (!submission_proxy_handle_redirect(
			client, status, enh_code, text, &failure_type, &text)) {
		i_assert((status / 100) != 2);
		i_assert(subm_client->proxy_reply != NULL);
		smtp_server_reply_submit(subm_client->proxy_reply);
		subm_client->pending_auth = NULL;
	}

	login_proxy_failed(client->login_proxy,
			   login_proxy_get_event(client->login_proxy),
			   failure_type, text);
	return -1;
}

void submission_proxy_reset(struct client *client)
{
	struct submission_client *subm_client =
		container_of(client, struct submission_client, common);

	subm_client->proxy_state = SUBMISSION_PROXY_BANNER;
	subm_client->proxy_capability = 0;
	i_free_and_null(subm_client->proxy_xclient);
	i_free(subm_client->proxy_sasl_ir);
	subm_client->proxy_reply_status = 0;
	subm_client->proxy_reply = NULL;
}

static void
submission_proxy_send_failure_reply(struct submission_client *subm_client,
				    enum login_proxy_failure_type type,
				    const char *reason ATTR_UNUSED)
{
	struct smtp_server_cmd_ctx *cmd = subm_client->pending_auth;

	switch (type) {
	case LOGIN_PROXY_FAILURE_TYPE_CONNECT:
	case LOGIN_PROXY_FAILURE_TYPE_INTERNAL:
	case LOGIN_PROXY_FAILURE_TYPE_INTERNAL_CONFIG:
	case LOGIN_PROXY_FAILURE_TYPE_REMOTE:
	case LOGIN_PROXY_FAILURE_TYPE_REMOTE_CONFIG:
	case LOGIN_PROXY_FAILURE_TYPE_PROTOCOL:
	case LOGIN_PROXY_FAILURE_TYPE_AUTH_REDIRECT:
		i_assert(cmd != NULL);
		subm_client->pending_auth = NULL;
		smtp_server_reply(cmd, 454, "4.7.0", LOGIN_PROXY_FAILURE_MSG);
		break;
	case LOGIN_PROXY_FAILURE_TYPE_AUTH_TEMPFAIL:
		i_assert(cmd != NULL);
		subm_client->pending_auth = NULL;

		i_assert(subm_client->proxy_reply != NULL);
		smtp_server_reply_submit(subm_client->proxy_reply);
		break;
	case LOGIN_PROXY_FAILURE_TYPE_AUTH:
		/* reply was already sent */
		i_assert(cmd == NULL);
		break;
	}
}

void submission_proxy_failed(struct client *client,
			     enum login_proxy_failure_type type,
			     const char *reason, bool reconnecting)
{
	struct submission_client *subm_client =
		container_of(client, struct submission_client, common);

	if (!reconnecting)
		submission_proxy_send_failure_reply(subm_client, type, reason);
	client_common_proxy_failed(client, type, reason, reconnecting);
}

const char *submission_proxy_get_state(struct client *client)
{
	struct submission_client *subm_client =
		container_of(client, struct submission_client, common);

	i_assert(subm_client->proxy_state < SUBMISSION_PROXY_STATE_COUNT);
	return submission_proxy_state_names[subm_client->proxy_state];
}
