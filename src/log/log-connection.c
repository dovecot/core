/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "ioloop.h"
#include "llist.h"
#include "hash.h"
#include "master-interface.h"
#include "master-service.h"
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

	int fd;
	int listen_fd;
	struct io *io;

	char *default_prefix;
	/* pid -> struct log_client* */
	struct hash_table *clients;

	unsigned int master:1;
	unsigned int handshaked:1;
};

static struct log_connection *log_connections = NULL;
static ARRAY_DEFINE(logs_by_fd, struct log_connection *);

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

static void log_parse_master_line(const char *line)
{
	struct log_connection *const *logs, *log;
	struct log_client *client;
	const char *p, *p2;
	unsigned int count;
	int service_fd;
	long pid;

	p = strchr(line, ' ');
	if (p == NULL || (p2 = strchr(++p, ' ')) == NULL) {
		i_error("Received invalid input from master: %s", line);
		return;
	}
	service_fd = atoi(t_strcut(line, ' '));
	pid = strtol(t_strcut(p, ' '), NULL, 10);

	logs = array_get(&logs_by_fd, &count);
	if (service_fd >= (int)count || logs[service_fd] == NULL) {
		i_error("Received master input for invalid service_fd %d: %s",
			service_fd, line);
		return;
	}
	log = logs[service_fd];
	client = hash_table_lookup(log->clients, POINTER_CAST(pid));
	line = p2 + 1;

	if (strcmp(line, "BYE") == 0) {
		if (client == NULL) {
			/* we haven't seen anything important from this client.
			   it's not an error. */
			return;
		}
		log_client_free(log, client, pid);
	} else if (strncmp(line, "DEFAULT-FATAL ", 14) == 0) {
		/* If the client has logged a fatal/panic, don't log this
		   message. */
		if (client == NULL || !client->fatal_logged)
			i_error("%s", line + 14);
		else
			log_client_free(log, client, pid);
	} else {
		i_error("Received unknown command from master: %s", line);
	}
}

static void log_it(struct log_connection *log, const char *line)
{
	struct failure_line failure;
	struct log_client *client = NULL;
	const char *prefix;

	if (log->master) {
		log_parse_master_line(line);
		return;
	}

	i_failure_parse_line(line, &failure);
	switch (failure.log_type) {
	case LOG_TYPE_FATAL:
	case LOG_TYPE_PANIC:
		client = log_client_get(log, failure.pid);
		client->fatal_logged = TRUE;
		break;
	case LOG_TYPE_OPTION:
		log_parse_option(log, &failure);
		return;
	default:
		client = hash_table_lookup(log->clients,
					   POINTER_CAST(failure.pid));
		break;
	}
	i_assert(failure.log_type < LOG_TYPE_COUNT);

	prefix = client != NULL && client->prefix != NULL ?
		client->prefix : log->default_prefix;
	i_set_failure_prefix(prefix);
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
		log->default_prefix = i_strndup(*data + sizeof(handshake),
						handshake.prefix_len);
		*data += sizeof(handshake) + handshake.prefix_len;
	}
	if (strcmp(log->default_prefix, MASTER_LOG_PREFIX_NAME) == 0) {
		if (log->listen_fd != MASTER_LISTEN_FD_FIRST) {
			i_error("Received master prefix in handshake "
				"from non-master fd %d", log->fd);
			return FALSE;
		}
		log->master = TRUE;
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
		(void)log_connection_handshake(log, &line, ret);

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

struct log_connection *log_connection_create(int fd, int listen_fd)
{
	struct log_connection *log;

	log = i_new(struct log_connection, 1);
	log->fd = fd;
	log->listen_fd = listen_fd;
	log->io = io_add(fd, IO_READ, log_connection_input, log);
	log->clients = hash_table_create(default_pool, default_pool, 0,
					 NULL, NULL);
	array_idx_set(&logs_by_fd, listen_fd, &log);

	DLLIST_PREPEND(&log_connections, log);
	log_connection_input(log);
	return log;
}

void log_connection_destroy(struct log_connection *log)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	array_idx_clear(&logs_by_fd, log->listen_fd);

	DLLIST_REMOVE(&log_connections, log);

	iter = hash_table_iterate_init(log->clients);
	while (hash_table_iterate(iter, &key, &value))
		i_free(value);
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&log->clients);

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
