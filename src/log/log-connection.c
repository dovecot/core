/* Copyright (c) 2005-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "llist.h"
#include "hash.h"
#include "master-interface.h"
#include "master-service.h"
#include "log-error-buffer.h"
#include "log-connection.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define FATAL_QUEUE_TIMEOUT_MSECS 500

struct log_client {
	struct ip_addr ip;
	char *prefix;
	unsigned int fatal_logged:1;
};

struct log_connection {
	struct log_connection *prev, *next;

	struct log_error_buffer *errorbuf;
	int fd;
	int listen_fd;
	struct io *io;
	struct istream *input;

	char *default_prefix;
	HASH_TABLE(void *, struct log_client *) clients;

	unsigned int master:1;
	unsigned int handshaked:1;
};

static struct log_connection *log_connections = NULL;
static ARRAY(struct log_connection *) logs_by_fd;

static void log_connection_destroy(struct log_connection *log);

static struct log_client *log_client_get(struct log_connection *log, pid_t pid)
{
	struct log_client *client;

	client = hash_table_lookup(log->clients, POINTER_CAST(pid));
	if (client == NULL) {
		client = i_new(struct log_client, 1);
		hash_table_insert(log->clients, POINTER_CAST(pid), client);
	}
	return client;
}

static void log_client_free(struct log_connection *log,
			    struct log_client *client, pid_t pid)
{
	hash_table_remove(log->clients, POINTER_CAST(pid));

	i_free(client->prefix);
	i_free(client);
}

static void log_parse_option(struct log_connection *log,
			     const struct failure_line *failure)
{
	struct log_client *client;

	client = log_client_get(log, failure->pid);
	if (strncmp(failure->text, "ip=", 3) == 0)
		(void)net_addr2ip(failure->text + 3, &client->ip);
	else if (strncmp(failure->text, "prefix=", 7) == 0) {
		i_free(client->prefix);
		client->prefix = i_strdup(failure->text + 7);
	}
}

static void
client_log_ctx(struct log_connection *log,
	       const struct failure_context *ctx, time_t log_time,
	       const char *prefix, const char *text)
{
	struct log_error err;

	switch (ctx->type) {
	case LOG_TYPE_DEBUG:
	case LOG_TYPE_INFO:
	case LOG_TYPE_COUNT:
	case LOG_TYPE_OPTION:
		break;
	case LOG_TYPE_WARNING:
	case LOG_TYPE_ERROR:
	case LOG_TYPE_FATAL:
	case LOG_TYPE_PANIC:
		memset(&err, 0, sizeof(err));
		err.type = ctx->type;
		err.timestamp = log_time;
		err.prefix = prefix;
		err.text = text;
		log_error_buffer_add(log->errorbuf, &err);
		break;
	}
	i_set_failure_prefix("%s", prefix);
	i_log_type(ctx, "%s", text);
	i_set_failure_prefix("log: ");
}

static void
client_log_fatal(struct log_connection *log, struct log_client *client,
		 const char *line, time_t log_time, const struct tm *tm)
{
	struct failure_context failure_ctx;
	const char *prefix = log->default_prefix;

	memset(&failure_ctx, 0, sizeof(failure_ctx));
	failure_ctx.type = LOG_TYPE_FATAL;
	failure_ctx.timestamp = tm;

	if (client != NULL) {
		if (client->prefix != NULL)
			prefix = client->prefix;
		else if (client->ip.family != 0) {
			line = t_strdup_printf("%s [last ip=%s]",
					       line, net_ip2addr(&client->ip));
		}
	}
	client_log_ctx(log, &failure_ctx, log_time, prefix,
		       t_strconcat("master: ", line, NULL));
}

static void
log_parse_master_line(const char *line, time_t log_time, const struct tm *tm)
{
	struct log_connection *const *logs, *log;
	struct log_client *client;
	const char *p, *p2, *cmd;
	unsigned int count;
	int service_fd;
	pid_t pid;

	p = strchr(line, ' ');
	if (p == NULL || (p2 = strchr(++p, ' ')) == NULL) {
		i_error("Received invalid input from master: %s", line);
		return;
	}
	service_fd = atoi(t_strcut(line, ' '));
	pid = strtol(t_strcut(p, ' '), NULL, 10);
	cmd = p2 + 1;

	logs = array_get(&logs_by_fd, &count);
	if (service_fd >= (int)count || logs[service_fd] == NULL) {
		if (strcmp(cmd, "BYE") == 0 && service_fd < (int)count) {
			/* master is probably shutting down and we already
			   noticed the log fd closing */
			return;
		}
		i_error("Received master input for invalid service_fd %d: %s",
			service_fd, line);
		return;
	}
	log = logs[service_fd];
	client = hash_table_lookup(log->clients, POINTER_CAST(pid));

	if (strcmp(cmd, "BYE") == 0) {
		if (client == NULL) {
			/* we haven't seen anything important from this client.
			   it's not an error. */
			return;
		}
		log_client_free(log, client, pid);
	} else if (strncmp(cmd, "FATAL ", 6) == 0) {
		client_log_fatal(log, client, cmd + 6, log_time, tm);
	} else if (strncmp(cmd, "DEFAULT-FATAL ", 14) == 0) {
		/* If the client has logged a fatal/panic, don't log this
		   message. */
		if (client == NULL || !client->fatal_logged)
			client_log_fatal(log, client, cmd + 14, log_time, tm);
	} else {
		i_error("Received unknown command from master: %s", cmd);
	}
}

static void
log_it(struct log_connection *log, const char *line,
       time_t log_time, const struct tm *tm)
{
	struct failure_line failure;
	struct failure_context failure_ctx;
	struct log_client *client = NULL;
	const char *prefix;

	if (log->master) {
		T_BEGIN {
			log_parse_master_line(line, log_time, tm);
		} T_END;
		return;
	}

	i_failure_parse_line(line, &failure);
	switch (failure.log_type) {
	case LOG_TYPE_FATAL:
	case LOG_TYPE_PANIC:
		if (failure.pid != 0) {
			client = log_client_get(log, failure.pid);
			client->fatal_logged = TRUE;
		}
		break;
	case LOG_TYPE_OPTION:
		log_parse_option(log, &failure);
		return;
	default:
		client = failure.pid == 0 ? NULL :
			hash_table_lookup(log->clients,
					  POINTER_CAST(failure.pid));
		break;
	}
	i_assert(failure.log_type < LOG_TYPE_COUNT);

	memset(&failure_ctx, 0, sizeof(failure_ctx));
	failure_ctx.type = failure.log_type;
	failure_ctx.timestamp = tm;

	prefix = client != NULL && client->prefix != NULL ?
		client->prefix : log->default_prefix;
	client_log_ctx(log, &failure_ctx, log_time, prefix, failure.text);
}

static int log_connection_handshake(struct log_connection *log)
{
	struct log_service_handshake handshake;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	ret = i_stream_read(log->input);
	if (ret < 0) {
		i_error("read(log pipe) failed: %m");
		return -1;
	}
	if ((size_t)ret < sizeof(handshake)) {
		/* this isn't a handshake */
		return 0;
	}

	data = i_stream_get_data(log->input, &size);
	i_assert(size >= sizeof(handshake));
	memcpy(&handshake, data, sizeof(handshake));

	if (handshake.log_magic != MASTER_LOG_MAGIC) {
		/* this isn't a handshake */
		return 0;
	}

	if (handshake.prefix_len > size - sizeof(handshake)) {
		i_error("Missing prefix data in handshake");
		return -1;
	}
	log->default_prefix = i_strndup(data + sizeof(handshake),
					handshake.prefix_len);
	i_stream_skip(log->input, sizeof(handshake) + handshake.prefix_len);

	if (strcmp(log->default_prefix, MASTER_LOG_PREFIX_NAME) == 0) {
		if (log->listen_fd != MASTER_LISTEN_FD_FIRST) {
			i_error("Received master prefix in handshake "
				"from non-master fd %d", log->fd);
			return -1;
		}
		log->master = TRUE;
	}
	log->handshaked = TRUE;
	return 0;
}

static void log_connection_input(struct log_connection *log)
{
	const char *line;
	ssize_t ret;
	time_t now;
	struct tm tm;

	if (!log->handshaked) {
		if (log_connection_handshake(log) < 0) {
			log_connection_destroy(log);
			return;
		}
	}

	while ((ret = i_stream_read(log->input)) > 0 || ret == -2) {
		/* get new timestamps for every read() */
		now = time(NULL);
		tm = *localtime(&now);

		while ((line = i_stream_next_line(log->input)) != NULL)
			log_it(log, line, now, &tm);
	}

	if (log->input->eof)
		log_connection_destroy(log);
	else if (log->input->stream_errno != 0) {
		i_error("read(log pipe) failed: %m");
		log_connection_destroy(log);
	} else {
		i_assert(!log->input->closed);
	}
}

void log_connection_create(struct log_error_buffer *errorbuf,
			   int fd, int listen_fd)
{
	struct log_connection *log;

	log = i_new(struct log_connection, 1);
	log->errorbuf = errorbuf;
	log->fd = fd;
	log->listen_fd = listen_fd;
	log->io = io_add(fd, IO_READ, log_connection_input, log);
	log->input = i_stream_create_fd(fd, PIPE_BUF, FALSE);
	hash_table_create_direct(&log->clients, default_pool, 0);
	array_idx_set(&logs_by_fd, listen_fd, &log);

	DLLIST_PREPEND(&log_connections, log);
	log_connection_input(log);
}

static void log_connection_destroy(struct log_connection *log)
{
	struct hash_iterate_context *iter;
	void *key;
	struct log_client *client;

	array_idx_clear(&logs_by_fd, log->listen_fd);

	DLLIST_REMOVE(&log_connections, log);

	iter = hash_table_iterate_init(log->clients);
	while (hash_table_iterate(iter, log->clients, &key, &client))
		i_free(client);
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&log->clients);

	i_stream_unref(&log->input);
	if (log->io != NULL)
		io_remove(&log->io);
	if (close(log->fd) < 0)
		i_error("close(log connection fd) failed: %m");
	i_free(log->default_prefix);
	i_free(log);

	master_service_client_connection_destroyed(master_service);
}

void log_connections_init(void)
{
	i_array_init(&logs_by_fd, 64);
}

void log_connections_deinit(void)
{
	/* normally we don't exit until all log connections are gone,
	   but we could get here when we're being killed by a signal */
	while (log_connections != NULL)
		log_connection_destroy(log_connections);
	array_free(&logs_by_fd);
}
