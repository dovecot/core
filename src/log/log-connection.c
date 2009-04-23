/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "llist.h"
#include "hash.h"
#include "master-interface.h"
#include "master-service.h"
#include "log-connection.h"

#include <unistd.h>

#define FATAL_QUEUE_TIMEOUT_MSECS 500

struct log_client {
	struct ip_addr ip;
	unsigned int fatal_logged:1;
};

struct log_connection {
	struct log_connection *prev, *next;

	int fd;
	struct io *io;

	char *prefix;
	struct hash_table *clients;

	unsigned int handshaked:1;
};

static struct log_connection *log_connections = NULL;

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

static void log_parse_ip(struct log_connection *log,
			 const struct failure_line *failure)
{
	struct log_client *client;

	client = log_client_get(log, failure->pid);
	(void)net_addr2ip(failure->text + 3, &client->ip);
}

static void log_remove_pid(struct log_connection *log, pid_t pid)
{
	struct log_client *client;

	client = hash_table_lookup(log->clients, POINTER_CAST(pid));
	if (client != NULL) {
		hash_table_remove(log->clients, POINTER_CAST(pid));
		i_free(client);
	}
}

static void log_parse_option(struct log_connection *log,
			     const struct failure_line *failure)
{
	if (strncmp(failure->text, "ip=", 3) == 0)
		log_parse_ip(log, failure);
	else if (strcmp(failure->text, "bye") == 0)
		log_remove_pid(log, failure->pid);
}

static bool
log_handle_seen_fatal(struct log_connection *log, const char **_text)
{
	const char *text = *_text;
	struct log_client *client;
	pid_t pid = 0;

	while (*text >= '0' && *text <= '9') {
		pid = pid*10 + (*text - '0');
		text++;
	}
	if (*text != ' ' || pid == 0)
		return FALSE;
	*_text = text;

	client = hash_table_lookup(log->clients, POINTER_CAST(pid));
	if (client != NULL && client->fatal_logged) {
		log_remove_pid(log, pid);
		return TRUE;
	}
	return FALSE;
}

static void log_it(struct log_connection *log, const char *line)
{
	struct failure_line failure;
	struct log_client *client;

	i_failure_parse_line(line, &failure);
	switch (failure.log_type) {
	case LOG_TYPE_FATAL:
	case LOG_TYPE_PANIC:
		client = log_client_get(log, failure.pid);
		client->fatal_logged = TRUE;
		break;
	case LOG_TYPE_ERROR_IGNORE_IF_SEEN_FATAL:
		/* Special case for master connection. If the following PID
		   has logged a fatal/panic, don't log this message. */
		failure.log_type = LOG_TYPE_ERROR;
		if (failure.pid != master_pid) {
			i_error("Non-master process %s "
				"sent LOG_TYPE_ERROR_IGNORE_IF_SEEN_FATAL",
				dec2str(failure.pid));
			break;
		}

		if (log_handle_seen_fatal(log, &failure.text))
			return;
		break;
	case LOG_TYPE_OPTION:
		log_parse_option(log, &failure);
		return;
	default:
		break;
	}
	i_assert(failure.log_type < LOG_TYPE_COUNT);

	i_set_failure_prefix(log->prefix);
	i_log_type(failure.log_type, "%s", failure.text);
	i_set_failure_prefix("log: ");
}

static bool log_connection_handshake(struct log_connection *log,
				     char **data, size_t size)
{
	struct log_service_handshake handshake;

	if (size < sizeof(handshake))
		return FALSE;

	memcpy(&handshake, *data, sizeof(handshake));
	if (handshake.log_magic != MASTER_LOG_MAGIC)
		return FALSE;

	if (handshake.prefix_len <= size - sizeof(handshake)) {
		log->prefix = i_strndup(*data + sizeof(handshake),
					handshake.prefix_len);
		*data += sizeof(handshake) + handshake.prefix_len;
	}
	log->handshaked = TRUE;
	return TRUE;
}

static void log_connection_input(struct log_connection *log)
{
	char data[PIPE_BUF+1], *p, *line;
	ssize_t ret;

	ret = read(log->fd, data, sizeof(data)-1);
	if (ret <= 0) {
		if (ret < 0)
			i_error("read(log pipe) failed: %m");
		log_connection_destroy(log);
		return;
	}
	data[ret] = '\0';

	line = data;
	if (!log->handshaked)
		log_connection_handshake(log, &line, ret);

	p = line;
	while ((p = strchr(line, '\n')) != NULL) {
		*p = '\0';
		log_it(log, line);
		line = p + 1;
	}
	if (line - data != ret) {
		i_error("Invalid log line follows: Missing LF");
		log_it(log, line);
	}
}

struct log_connection *log_connection_create(int fd)
{
	struct log_connection *log;

	log = i_new(struct log_connection, 1);
	log->fd = fd;
	log->io = io_add(fd, IO_READ, log_connection_input, log);
	log->clients = hash_table_create(default_pool, default_pool, 0,
					 NULL, NULL);

	DLLIST_PREPEND(&log_connections, log);
	log_connection_input(log);
	return log;
}

void log_connection_destroy(struct log_connection *log)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	DLLIST_REMOVE(&log_connections, log);

	iter = hash_table_iterate_init(log->clients);
	while (hash_table_iterate(iter, &key, &value))
		i_free(value);
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&log->clients);

	if (log->io != NULL)
		io_remove(&log->io);
	i_free(log->prefix);
	i_free(log);

        master_service_client_connection_destroyed(service);
}

void log_connections_deinit(void)
{
	/* normally we don't exit until all log connections are gone,
	   but we could get here when we're being killed by a signal */
	while (log_connections != NULL)
		log_connection_destroy(log_connections);
}
