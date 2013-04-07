/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

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

/* normally there shouldn't be any need for locking, since replicator doesn't
   start dsync in parallel for the same user. we'll do locking just in case
   anyway */
#define DSYNC_LOCK_TIMEOUT_SECS 30

struct dsync_client {
	char *path;
	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct timeout *to;

	char *state;
	dsync_callback_t *callback;
	void *context;

	time_t last_connect_failure;
	unsigned int handshaked:1;
	unsigned int cmd_sent:1;
};

struct dsync_client *dsync_client_init(const char *path)
{
	struct dsync_client *client;

	client = i_new(struct dsync_client, 1);
	client->path = i_strdup(path);
	client->fd = -1;
	return client;
}

static void dsync_callback(struct dsync_client *client,
			   const char *state, enum dsync_reply reply)
{
	dsync_callback_t *callback = client->callback;
	void *context = client->context;

	if (client->to != NULL)
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
	if (client->fd == -1)
		return;

	io_remove(&client->io);
	o_stream_destroy(&client->output);
	i_stream_destroy(&client->input);
	if (close(client->fd) < 0)
		i_error("close(dsync) failed: %m");
	client->fd = -1;
	i_free_and_null(client->state);
	client->cmd_sent = FALSE;
	client->handshaked = FALSE;
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
	client->input = i_stream_create_fd(client->fd, (size_t)-1, FALSE);
	client->output = o_stream_create_fd(client->fd, (size_t)-1, FALSE);
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

	i_assert(callback != NULL);
	i_assert(!dsync_client_is_busy(client));

	client->cmd_sent = TRUE;
	client->callback = callback;
	client->context = context;

	if (dsync_connect(client) < 0) {
		i_assert(client->to == NULL);
		client->to = timeout_add(DSYNC_FAIL_TIMEOUT_MSECS,
				       dsync_fail_timeout, client);
	} else {
		/* <flags> <username> <command> [<args>] */
		cmd = t_str_new(256);
		str_append_c(cmd, '\t');
		str_append_tabescaped(cmd, username);
		str_printfa(cmd, "\tsync\t-d\t-N\t-l\t%u", DSYNC_LOCK_TIMEOUT_SECS);
		if (full)
			str_append(cmd, "\t-f");
		str_append(cmd, "\t-U\t-s\t");
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
