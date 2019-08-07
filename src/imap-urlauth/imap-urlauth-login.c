/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "str.h"
#include "strescape.h"
#include "base64.h"
#include "net.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "master-service.h"
#include "auth-client.h"
#include "client-common.h"
#include "imap-urlauth-login-settings.h"

#define IMAP_URLAUTH_PROTOCOL_MAJOR_VERSION 2
#define IMAP_URLAUTH_PROTOCOL_MINOR_VERSION 0

struct imap_urlauth_client {
	struct client common;

	const struct imap_urlauth_login_settings *set;

	bool version_received:1;
};

static void
imap_urlauth_client_auth_result(struct client *client,
				enum client_auth_result result,
				const struct client_auth_reply *reply ATTR_UNUSED,
				const char *text ATTR_UNUSED)
{
	if (result != CLIENT_AUTH_RESULT_SUCCESS) {
		/* failed or otherwise invalid status */
		client_send_raw(client, "FAILED\n");
		client_destroy(client, "Disconnected: Authentication failed");
	} else {
		/* authentication succeeded */
	}
}

static void imap_urlauth_client_handle_input(struct client *client)
{
#define AUTH_ARG_COUNT 6
	struct imap_urlauth_client *uauth_client =
		(struct imap_urlauth_client *)client;
	struct net_unix_cred cred;
	const char *line;
	const char *const *args;
	pid_t pid;

	if (!uauth_client->version_received) {
		if ((line = i_stream_next_line(client->input)) == NULL)
			return;

		if (!version_string_verify(line, "imap-urlauth",
				IMAP_URLAUTH_PROTOCOL_MAJOR_VERSION)) {
			i_error("IMAP URLAUTH client not compatible with this server "
				"(mixed old and new binaries?) %s", line);
			client_destroy(client, "Disconnected: Version mismatch");
			return;
		}
		uauth_client->version_received = TRUE;
	}

	if ((line = i_stream_next_line(client->input)) == NULL)
		return;

	/* read authentication info from input;
	   "AUTH"\t<service>\t<session-pid>\t<auth-username>\t<session_id>\t<token> */
	args = t_strsplit_tabescaped(line);
	if (str_array_length(args) < AUTH_ARG_COUNT ||
	    strcmp(args[0], "AUTH") != 0 || str_to_pid(args[2], &pid) < 0) {
		i_error("IMAP URLAUTH client sent unexpected AUTH input: %s", line);
		client_destroy(client, "Disconnected: Unexpected input");
		return;
	}

	/* only imap and submission have direct access to urlauth service */
	if (strcmp(args[1], "imap") != 0 && strcmp(args[1], "submission") != 0) {
		i_error("IMAP URLAUTH accessed from inappropriate service: %s", args[1]);
		client_destroy(client, "Disconnected: Unexpected input");
		return;
	}

	/* verify session pid if possible */
	if (net_getunixcred(client->fd, &cred) == 0 &&
	    cred.pid != (pid_t)-1 && pid != cred.pid) {
		i_error("IMAP URLAUTH client sent invalid session pid %ld in AUTH request: "
			"it did not match peer credentials (pid=%ld, uid=%ld)",
			(long)pid, (long)cred.pid, (long)cred.uid);
		client_destroy(client, "Disconnected: Invalid AUTH request");
		return;
	}

	T_BEGIN {
		string_t *auth_data = t_str_new(128);
		string_t *init_resp;
		unsigned int i;

		str_append(auth_data, args[1]);
		for (i = 2; i < AUTH_ARG_COUNT; i++) {
			str_append_c(auth_data, '\0');
			str_append(auth_data, args[i]);
		}
		init_resp = t_str_new(256);
		base64_encode(str_data(auth_data),
			      str_len(auth_data), init_resp);

		(void)client_auth_begin(client, "DOVECOT-TOKEN",
					str_c(init_resp));
	} T_END;
}

static void imap_urlauth_client_input(struct client *client)
{
	if (!client_read(client))
		return;

	client_ref(client);
	o_stream_cork(client->output);
	if (!auth_client_is_connected(auth_client)) {
		/* we're not currently connected to auth process -
		   don't allow any commands */
		timeout_remove(&client->to_auth_waiting);
		client->input_blocked = TRUE;
	} else {
		imap_urlauth_client_handle_input(client);
	}
	o_stream_uncork(client->output);
	client_unref(&client);
}

static struct client *imap_urlauth_client_alloc(pool_t pool)
{
	struct imap_urlauth_client *uauth_client;

	uauth_client = p_new(pool, struct imap_urlauth_client, 1);
	return &uauth_client->common;
}

static void imap_urlauth_client_create
(struct client *client, void **other_sets)
{
	struct imap_urlauth_client *uauth_client =
		(struct imap_urlauth_client *)client;

	uauth_client->set = other_sets[0];
	client->io = io_add_istream(client->input, client_input, client);
}

static void imap_urlauth_login_preinit(void)
{
	login_set_roots = imap_urlauth_login_setting_roots;
}

static void imap_urlauth_login_init(void)
{
}

static void imap_urlauth_login_deinit(void)
{
	clients_destroy_all();
}

static struct client_vfuncs imap_urlauth_vfuncs = {
	.alloc = imap_urlauth_client_alloc,
	.create = imap_urlauth_client_create,
	.input = imap_urlauth_client_input,
	.auth_result = imap_urlauth_client_auth_result,
	.send_raw_data = client_common_send_raw_data,
	.free = client_common_default_free,
};

static const struct login_binary imap_urlauth_login_binary = {
	.protocol = "imap-urlauth",
	.process_name = "imap-urlauth-login",
	.default_login_socket = LOGIN_TOKEN_DEFAULT_SOCKET,

	.client_vfuncs = &imap_urlauth_vfuncs,
	.preinit = imap_urlauth_login_preinit,
	.init = imap_urlauth_login_init,
	.deinit = imap_urlauth_login_deinit,
};

int main(int argc, char *argv[])
{
	return login_binary_run(&imap_urlauth_login_binary, argc, argv);
}
