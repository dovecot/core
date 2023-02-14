/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "imap-urlauth-common.h"
#include "array.h"
#include "ioloop.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "eacces-error.h"
#include "hostpid.h"
#include "execv-const.h"
#include "env-util.h"
#include "var-expand.h"
#include "restrict-access.h"
#include "master-service.h"
#include "master-interface.h"

#include "imap-urlauth-worker-client.h"

#include <unistd.h>
#include <sys/wait.h>

/* Disconnect client after idling this many milliseconds */
#define CLIENT_IDLE_TIMEOUT_MSECS (10*60*1000)

#define IS_STANDALONE() \
        (getenv(MASTER_IS_PARENT_ENV) == NULL)

static struct event_category event_category_urlauth = {
	.name = "imap-urlauth",
};

struct connection_list *imap_urlauth_clist;

int client_create(const char *service, const char *username,
		  int fd_in, int fd_out,
		  const struct imap_urlauth_settings *set,
		  struct client **client_r)
{
	struct client *client;
	const char *app;

	/* always use nonblocking I/O */
	net_set_nonblock(fd_in, TRUE);
	net_set_nonblock(fd_out, TRUE);

	client = i_new(struct client, 1);
	client->set = set;

	client->event = event_create(NULL);
	event_set_forced_debug(client->event, set->mail_debug);
	event_add_category(client->event, &event_category_urlauth);
	event_set_append_log_prefix(client->event, t_strdup_printf(
		"user %s: ", username));

	/* determine user's special privileges */
	i_array_init(&client->access_apps, 4);
	if (username != NULL) {
		if (set->imap_urlauth_submit_user != NULL &&
		    strcmp(set->imap_urlauth_submit_user, username) == 0) {
			e_debug(client->event,
				"User has URLAUTH submit access");
			app = "submit+";
			array_push_back(&client->access_apps, &app);
		}
		if (set->imap_urlauth_stream_user != NULL &&
		    strcmp(set->imap_urlauth_stream_user, username) == 0) {
			e_debug(client->event,
				"User has URLAUTH stream access");
			app = "stream";
			array_push_back(&client->access_apps, &app);
		}
	}

	client->username = i_strdup(username);
	client->service = i_strdup(service);

	client->conn.event_parent = client->event;
	connection_init_server(imap_urlauth_clist, &client->conn, NULL,
			       fd_in, fd_out);
	connection_input_halt(&client->conn); /* No input handler */

	client->worker_client = imap_urlauth_worker_client_init(client);
	if (imap_urlauth_worker_client_connect(client->worker_client) < 0) {
		client_destroy(client, "Failed to connect to worker");
		return -1;
	}

	imap_urlauth_refresh_proctitle();
	*client_r = client;
	return 0;
}

void client_send_line(struct client *client, const char *fmt, ...)
{
	va_list va;
	ssize_t ret;

	if (client->conn.output->closed)
		return;

	va_start(va, fmt);

	T_BEGIN {
		string_t *str;

		str = t_str_new(256);
		str_vprintfa(str, fmt, va);
		str_append(str, "\n");

		ret = o_stream_send(client->conn.output,
				    str_data(str), str_len(str));
		i_assert(ret < 0 || (size_t)ret == str_len(str));
	} T_END;

	va_end(va);
}

void client_destroy(struct client *client, const char *reason)
{
	i_assert(reason != NULL || client->disconnected);

	if (!client->disconnected)
		e_info(client->event, "Disconnected: %s", reason);

	timeout_remove(&client->to_destroy);

	imap_urlauth_worker_client_deinit(&client->worker_client);

	connection_deinit(&client->conn);
	event_unref(&client->event);

	i_free(client->username);
	i_free(client->service);
	array_free(&client->access_apps);
	i_free(client);

	master_service_client_connection_destroyed(master_service);
	imap_urlauth_refresh_proctitle();
}

static void client_destroy_timeout(struct client *client)
{
	client_destroy(client, NULL);
}

void client_disconnect(struct client *client, const char *reason)
{
	if (client->disconnected)
		return;

	client->disconnected = TRUE;
	e_info(client->event, "Disconnected: %s", reason);

	client->to_destroy = timeout_add(0, client_destroy_timeout, client);
}

static void client_connection_destroy(struct connection *conn)
{
	struct client *client = container_of(conn, struct client, conn);

	switch (conn->disconnect_reason) {
	case CONNECTION_DISCONNECT_HANDSHAKE_FAILED:
	case CONNECTION_DISCONNECT_BUFFER_FULL:
		i_unreached();
	default:
		/* Disconnected */
		client_disconnect(client, "Client disconnected");
	}
}

static const struct connection_vfuncs client_connection_vfuncs = {
       .destroy = client_connection_destroy,
};

static const struct connection_settings client_connection_set = {
       .unix_client_connect_msecs = 1000,
       .input_max_size = SIZE_MAX,
       .output_max_size = SIZE_MAX,
};

void clients_init(void)
{
	imap_urlauth_clist = connection_list_init(&client_connection_set,
						  &client_connection_vfuncs);
}

void clients_deinit(void)
{
	struct connection *conn;

	for (conn = imap_urlauth_clist->connections;
	     conn != NULL; conn = conn->next) {
		struct client *client = container_of(conn, struct client, conn);

		client_destroy(client, MASTER_SERVICE_SHUTTING_DOWN_MSG);
	}
	connection_list_deinit(&imap_urlauth_clist);
}
