/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "dsync-client.h"

#include <unistd.h>

#define DSYNC_FAIL_TIMEOUT_MSECS (1000*5)
#define DOVEADM_HANDSHAKE "VERSION\tdoveadm-server\t1\t0\n"

struct dsync_client {
	char *path;
	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct timeout *to;

	char *dsync_params;
	char *username;
	char *state;
	enum dsync_type sync_type;
	dsync_callback_t *callback;
	void *context;

	time_t last_connect_failure;
	bool handshaked:1;
	bool cmd_sent:1;
};

struct dsync_client *
dsync_client_init(const char *path, const char *dsync_params)
{
	struct dsync_client *client;

	client = i_new(struct dsync_client, 1);
	client->path = i_strdup(path);
	client->fd = -1;
	client->dsync_params = i_strdup(dsync_params);
	return client;
}

static void dsync_callback(struct dsync_client *client,
			   const char *state, enum dsync_reply reply)
{
	dsync_callback_t *callback = client->callback;
	void *context = client->context;

	timeout_remove(&client->to);

	client->callback = NULL;
	client->context = NULL;

	/* make sure callback doesn't try to reuse this connection, since
	   we can't currently handle it */
	i_assert(!client->cmd_sent);
	client->cmd_sent = TRUE;
	callback(reply, state, context);
	client->cmd_sent = FALSE;
}

static void dsync_close(struct dsync_client *client)
{
	client->cmd_sent = FALSE;
	client->handshaked = FALSE;
	i_free_and_null(client->state);
	i_free_and_null(client->username);

	if (client->fd == -1)
		return;

	io_remove(&client->io);
	o_stream_destroy(&client->output);
	i_stream_destroy(&client->input);
	if (close(client->fd) < 0)
		i_error("close(dsync) failed: %m");
	client->fd = -1;
}

static void dsync_disconnect(struct dsync_client *client)
{
	dsync_close(client);
	if (client->callback != NULL)
		dsync_callback(client, "", DSYNC_REPLY_FAIL);
}

void dsync_client_deinit(struct dsync_client **_client)
{
	struct dsync_client *client = *_client;

	*_client = NULL;

	dsync_disconnect(client);
	i_free(client->dsync_params);
	i_free(client->path);
	i_free(client);
}

static int dsync_input_line(struct dsync_client *client, const char *line)
{
	const char *state;

	if (!client->handshaked) {
		if (strcmp(line, "+") != 0) {
			i_error("%s: Unexpected handshake: %s",
				client->path, line);
			return -1;
		}
		client->handshaked = TRUE;
		return 0;
	}
	if (client->callback == NULL) {
		i_error("%s: Unexpected input: %s", client->path, line);
		return -1;
	}
	if (client->state == NULL) {
		client->state = i_strdup(t_strcut(line, '\t'));
		return 0;
	}
	state = t_strdup(client->state);
	line = t_strdup(line);
	dsync_close(client);

	if (line[0] == '+')
		dsync_callback(client, state, DSYNC_REPLY_OK);
	else if (line[0] == '-') {
		if (strcmp(line+1, "NOUSER") == 0)
			dsync_callback(client, "", DSYNC_REPLY_NOUSER);
		else if (strcmp(line+1, "NOREPLICATE") == 0)
			dsync_callback(client, "", DSYNC_REPLY_NOREPLICATE);
		else
			dsync_callback(client, "", DSYNC_REPLY_FAIL);
	} else {
		i_error("%s: Invalid input: %s", client->path, line);
		return -1;
	}
	/* FIXME: disconnect after each request for now.
	   doveadm server's getopt() handling seems to break otherwise.
	   also with multiple UIDs doveadm-server fails because setid() fails */
	return -1;
}

static void dsync_input(struct dsync_client *client)
{
	const char *line;

	while ((line = i_stream_read_next_line(client->input)) != NULL) {
		if (dsync_input_line(client, line) < 0) {
			dsync_disconnect(client);
			return;
		}
	}
	if (client->input->eof)
		dsync_disconnect(client);
}

static int dsync_connect(struct dsync_client *client)
{
	if (client->fd != -1)
		return 0;

	if (client->last_connect_failure == ioloop_time)
		return -1;

	client->fd = net_connect_unix(client->path);
	if (client->fd == -1) {
		i_error("net_connect_unix(%s) failed: %m", client->path);
		client->last_connect_failure = ioloop_time;
		return -1;
	}
	client->last_connect_failure = 0;
	client->io = io_add(client->fd, IO_READ, dsync_input, client);
	client->input = i_stream_create_fd(client->fd, (size_t)-1);
	client->output = o_stream_create_fd(client->fd, (size_t)-1);
	o_stream_set_no_error_handling(client->output, TRUE);
	o_stream_nsend_str(client->output, DOVEADM_HANDSHAKE);
	return 0;
}

static void dsync_fail_timeout(struct dsync_client *client)
{
	dsync_disconnect(client);
}

void dsync_client_sync(struct dsync_client *client,
		       const char *username, const char *state, bool full,
		       dsync_callback_t *callback, void *context)
{
	string_t *cmd;
	unsigned int pos;
	char *p;

	i_assert(callback != NULL);
	i_assert(!dsync_client_is_busy(client));

	client->username = i_strdup(username);
	client->cmd_sent = TRUE;
	client->callback = callback;
	client->context = context;
	if (full)
		client->sync_type = DSYNC_TYPE_FULL;
	else if (state != NULL && state[0] != '\0')
		client->sync_type = DSYNC_TYPE_INCREMENTAL;
	else
		client->sync_type = DSYNC_TYPE_NORMAL;

	if (dsync_connect(client) < 0) {
		i_assert(client->to == NULL);
		client->to = timeout_add(DSYNC_FAIL_TIMEOUT_MSECS,
				       dsync_fail_timeout, client);
	} else {
		/* <flags> <username> <command> [<args>] */
		cmd = t_str_new(256);
		str_append_c(cmd, '\t');
		str_append_tabescaped(cmd, username);
		str_append(cmd, "\tsync\t");
		pos = str_len(cmd);
		/* insert the parameters. we can do it simply by converting
		   spaces into tabs, it's unlikely we'll ever need anything
		   more complex here. */
		str_append(cmd, client->dsync_params);
		p = str_c_modifiable(cmd) + pos;
		for (; *p != '\0'; p++) {
			if (*p == ' ')
				*p = '\t';
		}
		if (full)
			str_append(cmd, "\t-f");
		str_append(cmd, "\t-s\t");
		if (state != NULL)
			str_append(cmd, state);
		str_append_c(cmd, '\n');
		o_stream_nsend(client->output, str_data(cmd), str_len(cmd));
	}
}

bool dsync_client_is_busy(struct dsync_client *client)
{
	return client->cmd_sent;
}

const char *dsync_client_get_username(struct dsync_client *conn)
{
	return conn->username;
}

enum dsync_type dsync_client_get_type(struct dsync_client *conn)
{
	return conn->sync_type;
}

const char *dsync_client_get_state(struct dsync_client *conn)
{
	if (conn->fd == -1) {
		if (conn->last_connect_failure == 0)
			return "Not connected";
		return t_strdup_printf("Failed to connect to '%s' - last attempt %ld secs ago", conn->path,
				       (long)(ioloop_time - conn->last_connect_failure));
	}
	if (!dsync_client_is_busy(conn))
		return "Idle";
	if (!conn->handshaked)
		return "Waiting for handshake";
	if (conn->state == NULL)
		return "Waiting for dsync to finish";
	else
		return "Waiting for dsync to finish (second line)";
}
