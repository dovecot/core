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
#include "llist.h"
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

#define IMAP_URLAUTH_PROTOCOL_MAJOR_VERSION 1
#define IMAP_URLAUTH_PROTOCOL_MINOR_VERSION 0

/* Disconnect client after idling this many milliseconds */
#define CLIENT_IDLE_TIMEOUT_MSECS (10*60*1000)

#define IS_STANDALONE() \
        (getenv(MASTER_IS_PARENT_ENV) == NULL)

static struct event_category event_category_urlauth = {
	.name = "imap-urlauth",
};

struct client *imap_urlauth_clients;
unsigned int imap_urlauth_client_count;

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
	client->fd_in = fd_in;
	client->fd_out = fd_out;
	client->fd_ctrl = -1;
	client->set = set;

	client->event = event_create(NULL);
	event_set_forced_debug(client->event, set->mail_debug);
	event_add_category(client->event, &event_category_urlauth);
	event_set_append_log_prefix(client->event, t_strdup_printf(
		"user %s: ", username));

	if (client_worker_connect(client) < 0) {
		event_unref(&client->event);
		i_free(client);
		return -1;
	}

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

	client->output = o_stream_create_fd(fd_out, SIZE_MAX);

	imap_urlauth_client_count++;
	DLLIST_PREPEND(&imap_urlauth_clients, client);

	imap_urlauth_refresh_proctitle();
	*client_r = client;
	return 0;
}

void client_send_line(struct client *client, const char *fmt, ...)
{
	va_list va;
	ssize_t ret;

	if (client->output->closed)
		return;

	va_start(va, fmt);

	T_BEGIN {
		string_t *str;

		str = t_str_new(256);
		str_vprintfa(str, fmt, va);
		str_append(str, "\n");

		ret = o_stream_send(client->output,
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

	imap_urlauth_client_count--;
	DLLIST_REMOVE(&imap_urlauth_clients, client);

	timeout_remove(&client->to_destroy);

	client_worker_disconnect(client);

	o_stream_destroy(&client->output);

	fd_close_maybe_stdio(&client->fd_in, &client->fd_out);

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

void clients_destroy_all(void)
{
	while (imap_urlauth_clients != NULL) {
		client_destroy(imap_urlauth_clients,
			       MASTER_SERVICE_SHUTTING_DOWN_MSG);
	}
}
