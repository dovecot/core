/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

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
#include "pop3-proxy.h"

static const char *pop3_proxy_state_names[POP3_PROXY_STATE_COUNT] = {
	"banner", "starttls", "xclient", "login1", "login2"
};

static void proxy_free_password(struct client *client)
{
	if (client->proxy_password == NULL)
		return;

	safe_memset(client->proxy_password, 0, strlen(client->proxy_password));
	i_free_and_null(client->proxy_password);
}

static int proxy_send_login(struct pop3_client *client, struct ostream *output)
{
	struct dsasl_client_settings sasl_set;
	const unsigned char *sasl_output;
	size_t len;
	const char *mech_name, *error;
	string_t *str = t_str_new(128);

	i_assert(client->common.proxy_ttl > 1);
	if (client->proxy_xclient &&
	    !client->common.proxy_not_trusted) {
		string_t *fwd = t_str_new(128);
                for(const char *const *ptr = client->common.auth_passdb_args;*ptr != NULL; ptr++) {
                        if (strncasecmp(*ptr, "forward_", 8) == 0) {
                                if (str_len(fwd) > 0)
                                        str_append_c(fwd, '\t');
                                str_append_tabescaped(fwd, (*ptr)+8);
                        }
		}

		str_printfa(str, "XCLIENT ADDR=%s PORT=%u SESSION=%s TTL=%u",
			    net_ip2addr(&client->common.ip),
			    client->common.remote_port,
			    client_get_session_id(&client->common),
			    client->common.proxy_ttl - 1);
		if (str_len(fwd) > 0) {
			str_append(str, " FORWARD=");
			base64_encode(str_data(fwd), str_len(fwd), str);
		}
		str_append(str, "\r\n");
		/* remote supports XCLIENT, send it */
		o_stream_nsend(output, str_data(str), str_len(str));
		client->proxy_state = POP3_PROXY_XCLIENT;
	} else {
		client->proxy_state = POP3_PROXY_LOGIN1;
	}

	str_truncate(str, 0);

	if (client->common.proxy_mech == NULL) {
		/* send USER command */
		str_append(str, "USER ");
		str_append(str, client->common.proxy_user);
		str_append(str, "\r\n");
		o_stream_nsend(output, str_data(str), str_len(str));
		return 0;
	}

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
		e_error(login_proxy_get_event(client->common.login_proxy),
			"SASL mechanism %s init failed: %s",
			mech_name, error);
		client_proxy_failed(&client->common, TRUE);
		return -1;
	}
	if (len == 0)
		str_append_c(str, '=');
	else
		base64_encode(sasl_output, len, str);
	str_append(str, "\r\n");
	o_stream_nsend(output, str_data(str), str_len(str));

	proxy_free_password(&client->common);
	if (client->proxy_state != POP3_PROXY_XCLIENT)
		client->proxy_state = POP3_PROXY_LOGIN2;
	return 0;
}

static int
pop3_proxy_continue_sasl_auth(struct client *client, struct ostream *output,
			      const char *line)
{
	string_t *str;
	const unsigned char *data;
	size_t data_len;
	const char *error;
	int ret;

	str = t_str_new(128);
	if (base64_decode(line, strlen(line), NULL, str) < 0) {
		e_error(login_proxy_get_event(client->login_proxy),
			"Server sent invalid base64 data in AUTH response");
		client_proxy_failed(client, TRUE);
		return -1;
	}
	ret = dsasl_client_input(client->proxy_sasl_client,
				 str_data(str), str_len(str), &error);
	if (ret == 0) {
		ret = dsasl_client_output(client->proxy_sasl_client,
					  &data, &data_len, &error);
	}
	if (ret < 0) {
		e_error(login_proxy_get_event(client->login_proxy),
			"Server sent invalid authentication data: %s", error);
		client_proxy_failed(client, TRUE);
		return -1;
	}
	i_assert(ret == 0);

	str_truncate(str, 0);
	base64_encode(data, data_len, str);
	str_append(str, "\r\n");

	o_stream_nsend(output, str_data(str), str_len(str));
	return 0;
}

int pop3_proxy_parse_line(struct client *client, const char *line)
{
	struct pop3_client *pop3_client = (struct pop3_client *)client;
	struct ostream *output;
	enum login_proxy_ssl_flags ssl_flags;

	i_assert(!client->destroyed);

	output = login_proxy_get_ostream(client->login_proxy);
	switch (pop3_client->proxy_state) {
	case POP3_PROXY_BANNER:
		/* this is a banner */
		if (!str_begins(line, "+OK")) {
			e_error(login_proxy_get_event(client->login_proxy),
				"Remote returned invalid banner: %s",
				str_sanitize(line, 160));
			client_proxy_failed(client, TRUE);
			return -1;
		}
		pop3_client->proxy_xclient =
			str_begins(line+3, " [XCLIENT]");

		ssl_flags = login_proxy_get_ssl_flags(client->login_proxy);
		if ((ssl_flags & PROXY_SSL_FLAG_STARTTLS) == 0) {
			if (proxy_send_login(pop3_client, output) < 0)
				return -1;
		} else {
			o_stream_nsend_str(output, "STLS\r\n");
			pop3_client->proxy_state = POP3_PROXY_STARTTLS;
		}
		return 0;
	case POP3_PROXY_STARTTLS:
		if (!str_begins(line, "+OK")) {
			e_error(login_proxy_get_event(client->login_proxy),
				"Remote STLS failed: %s",
				str_sanitize(line, 160));
			client_proxy_failed(client, TRUE);
			return -1;
		}
		if (login_proxy_starttls(client->login_proxy) < 0)
			return -1;
		/* i/ostreams changed. */
		output = login_proxy_get_ostream(client->login_proxy);
		if (proxy_send_login(pop3_client, output) < 0)
			return -1;
		return 1;
	case POP3_PROXY_XCLIENT:
		if (!str_begins(line, "+OK")) {
			e_error(login_proxy_get_event(client->login_proxy),
				"Remote XCLIENT failed: %s",
				str_sanitize(line, 160));
			client_proxy_failed(client, TRUE);
			return -1;
		}
		pop3_client->proxy_state = client->proxy_sasl_client == NULL ?
			POP3_PROXY_LOGIN1 : POP3_PROXY_LOGIN2;
		return 0;
	case POP3_PROXY_LOGIN1:
		i_assert(client->proxy_sasl_client == NULL);
		if (!str_begins(line, "+OK"))
			break;

		/* USER successful, send PASS */
		o_stream_nsend_str(output, t_strdup_printf(
			"PASS %s\r\n", client->proxy_password));
		proxy_free_password(client);
		pop3_client->proxy_state = POP3_PROXY_LOGIN2;
		return 0;
	case POP3_PROXY_LOGIN2:
		if (str_begins(line, "+ ") &&
		    client->proxy_sasl_client != NULL) {
			/* continue SASL authentication */
			if (pop3_proxy_continue_sasl_auth(client, output,
							  line+2) < 0)
				return -1;
			return 0;
		}
		if (!str_begins(line, "+OK"))
			break;

		/* Login successful. Send this line to client. */
		line = t_strconcat(line, "\r\n", NULL);
		o_stream_nsend_str(client->output, line);

		client_proxy_finish_destroy_client(client);
		return 1;
	case POP3_PROXY_STATE_COUNT:
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
	if (!str_begins(line, "-ERR ")) {
		client_send_reply(client, POP3_CMD_REPLY_ERROR,
				  AUTH_FAILED_MSG);
	} else {
		client_send_raw(client, t_strconcat(line, "\r\n", NULL));
	}

	if (client->set->auth_verbose) {
		if (str_begins(line, "-ERR "))
			line += 5;
		client_proxy_log_failure(client, line);
	}
	login_proxy_failed(client->login_proxy,
			   login_proxy_get_event(client->login_proxy),
			   LOGIN_PROXY_FAILURE_TYPE_AUTH, NULL);
	return -1;
}

void pop3_proxy_reset(struct client *client)
{
	struct pop3_client *pop3_client = (struct pop3_client *)client;

	pop3_client->proxy_state = POP3_PROXY_BANNER;
}

void pop3_proxy_error(struct client *client, const char *text)
{
	client_send_reply(client, POP3_CMD_REPLY_ERROR, text);
}

const char *pop3_proxy_get_state(struct client *client)
{
	struct pop3_client *pop3_client = (struct pop3_client *)client;

	return pop3_proxy_state_names[pop3_client->proxy_state];
}
