/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "llist.h"
#include "hash.h"
#include "time-util.h"
#include "process-title.h"
#include "master-interface.h"
#include "master-service.h"
#include "log-error-buffer.h"
#include "log-connection.h"

#include <stdio.h>
#include <unistd.h>

#define FATAL_QUEUE_TIMEOUT_MSECS 500
#define MAX_MSECS_PER_CONNECTION 100

/* Log a warning after 1 secs when we've been all the time busy writing the
   log connection. */
#define LOG_WARN_PENDING_COUNT (1000 / MAX_MSECS_PER_CONNECTION)
/* If we keep being busy, log a warning every 60 seconds. */
#define LOG_WARN_PENDING_INTERVAL (60 * LOG_WARN_PENDING_COUNT)

struct log_client {
	struct ip_addr ip;
	char *prefix;
	bool fatal_logged:1;
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

	unsigned int pending_count;

	bool master:1;
	bool handshaked:1;
};

static struct log_connection *log_connections = NULL;
static ARRAY(struct log_connection *) logs_by_fd;
static unsigned int global_pending_count;
static struct log_connection *last_pending_log;

static void
log_connection_destroy(struct log_connection *log, bool shutting_down);

static void log_refresh_proctitle(void)
{
	if (!verbose_proctitle)
		return;

	if (global_pending_count == 0)
		process_title_set("");
	else if (last_pending_log == NULL) {
		process_title_set(t_strdup_printf(
			"[%u services too fast]", global_pending_count));
	} else if (global_pending_count > 1) {
		process_title_set(t_strdup_printf(
			"[%u services too fast, last: %d/%d/%s]",
			global_pending_count,
			last_pending_log->fd,
			last_pending_log->listen_fd,
			last_pending_log->default_prefix));
	} else {
		process_title_set(t_strdup_printf(
			"[service too fast: %d/%d/%s]",
			last_pending_log->fd,
			last_pending_log->listen_fd,
			last_pending_log->default_prefix));
	}
}

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
	if (str_begins(failure->text, "ip="))
		(void)net_addr2ip(failure->text + 3, &client->ip);
	else if (str_begins(failure->text, "prefix=")) {
		i_free(client->prefix);
		client->prefix = i_strdup(failure->text + 7);
	}
}

static void
client_log_ctx(struct log_connection *log,
	       const struct failure_context *ctx,
	       const struct timeval *log_time,
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
		i_zero(&err);
		err.type = ctx->type;
		err.timestamp = log_time->tv_sec;
		err.prefix = ctx->log_prefix != NULL ? ctx->log_prefix : prefix;
		err.text = text;
		log_error_buffer_add(log->errorbuf, &err);
		break;
	}
	/* log_prefix overrides the global prefix. Don't bother changing the
	   global prefix in that case. */
	if (ctx->log_prefix == NULL)
		i_set_failure_prefix("%s", prefix);
	i_log_type(ctx, "%s", text);
	if (ctx->log_prefix == NULL)
		i_set_failure_prefix("%s", global_log_prefix);
}

static void
client_log_fatal(struct log_connection *log, struct log_client *client,
		 const char *line, const struct timeval *log_time,
		 const struct tm *tm)
{
	struct failure_context failure_ctx;
	const char *prefix = log->default_prefix;

	i_zero(&failure_ctx);
	failure_ctx.type = LOG_TYPE_FATAL;
	failure_ctx.timestamp = tm;
	failure_ctx.timestamp_usecs = log_time->tv_usec;

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
log_parse_master_line(const char *line, const struct timeval *log_time,
		      const struct tm *tm)
{
	struct log_connection *const *logs, *log;
	struct log_client *client;
	const char *p, *p2, *cmd, *pidstr;
	unsigned int count;
	unsigned int service_fd;
	pid_t pid;

	p = strchr(line, ' ');
	if (p == NULL || (p2 = strchr(++p, ' ')) == NULL ||
	    str_to_uint(t_strcut(line, ' '), &service_fd) < 0) {
		i_error("Received invalid input from master: %s", line);
		return;
	}
	pidstr = t_strcut(p, ' ');
	if (str_to_pid(pidstr, &pid) < 0) {
		i_error("Received invalid pid from master: %s", pidstr);
		return;
	}
	cmd = p2 + 1;

	logs = array_get(&logs_by_fd, &count);
	if (service_fd >= count || logs[service_fd] == NULL) {
		if (strcmp(cmd, "BYE") == 0 && service_fd < count) {
			/* master is probably shutting down and we already
			   noticed the log fd closing */
			return;
		}
		i_error("Received master input for invalid service_fd %u: %s",
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
	} else if (str_begins(cmd, "FATAL ")) {
		client_log_fatal(log, client, cmd + 6, log_time, tm);
	} else if (str_begins(cmd, "DEFAULT-FATAL ")) {
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
       const struct timeval *log_time, const struct tm *tm)
{
	struct failure_line failure;
	struct failure_context failure_ctx;
	struct log_client *client = NULL;
	const char *prefix = "";

	if (log->master) {
		log_parse_master_line(line, log_time, tm);
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

	i_zero(&failure_ctx);
	failure_ctx.type = failure.log_type;
	failure_ctx.timestamp = tm;
	failure_ctx.timestamp_usecs = log_time->tv_usec;
	if (failure.log_prefix_len != 0) {
		failure_ctx.log_prefix =
			t_strndup(failure.text, failure.log_prefix_len);
		failure.text += failure.log_prefix_len;
	} else if (failure.disable_log_prefix) {
		failure_ctx.log_prefix = "";
	} else {
		prefix = client != NULL && client->prefix != NULL ?
			client->prefix : log->default_prefix;
	}
	client_log_ctx(log, &failure_ctx, log_time, prefix, failure.text);
}

static int log_connection_handshake(struct log_connection *log)
{
	struct log_service_handshake handshake;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	/* we're reading from a FIFO, so we're assuming that we're getting a
	   full handshake packet immediately. if not, treat it as an error
	   message that we want to log. */
	ret = i_stream_read(log->input);
	if (ret < 0) {
		i_error("read(log %s) failed: %s", log->default_prefix,
			i_stream_get_error(log->input));
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
	i_free(log->default_prefix);
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
	struct timeval now, start_timeval;
	struct tm tm;
	bool too_much = FALSE;

	if (!log->handshaked) {
		if (log_connection_handshake(log) < 0) {
			log_connection_destroy(log, FALSE);
			return;
		}
		/* come back here even if we read something else besides a
		   handshake. the first few lines could be coming from e.g.
		   libc before the proper handshake line is sent. */
	}

	io_loop_time_refresh();
	start_timeval = ioloop_timeval;
	while ((ret = i_stream_read(log->input)) > 0 || ret == -2) {
		/* get new timestamps for every read() */
		now = ioloop_timeval;
		tm = *localtime(&now.tv_sec);

		while ((line = i_stream_next_line(log->input)) != NULL) T_BEGIN {
			log_it(log, line, &now, &tm);
		} T_END;
		io_loop_time_refresh();
		if (timeval_diff_msecs(&ioloop_timeval, &start_timeval) > MAX_MSECS_PER_CONNECTION) {
			too_much = TRUE;
			break;
		}
	}

	if (log->input->eof) {
		if (log->input->stream_errno != 0)
			i_error("read(log %s) failed: %m", log->default_prefix);
		log_connection_destroy(log, FALSE);
	} else {
		i_assert(!log->input->closed);
		if (!too_much) {
			if (log->pending_count > 0) {
				log->pending_count = 0;
				i_assert(global_pending_count > 0);
				global_pending_count--;
				if (log == last_pending_log)
					last_pending_log = NULL;
				log_refresh_proctitle();
			}
			return;
		}
		last_pending_log = log;
		if (log->pending_count++ == 0) {
			global_pending_count++;
			log_refresh_proctitle();
		}
		if (log->pending_count == LOG_WARN_PENDING_COUNT ||
		    (log->pending_count % LOG_WARN_PENDING_INTERVAL) == 0) {
			i_warning("Log connection fd %d listen_fd %d prefix '%s' is sending input faster than we can write",
				  log->fd, log->listen_fd, log->default_prefix);
		}
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
	log->input = i_stream_create_fd(fd, PIPE_BUF);
	log->default_prefix = i_strdup_printf("listen_fd(%d): ", listen_fd);
	hash_table_create_direct(&log->clients, default_pool, 0);
	array_idx_set(&logs_by_fd, listen_fd, &log);

	DLLIST_PREPEND(&log_connections, log);
	log_connection_input(log);
}

static void
log_connection_destroy(struct log_connection *log, bool shutting_down)
{
	struct hash_iterate_context *iter;
	void *key;
	struct log_client *client;
	unsigned int client_count = 0;

	array_idx_clear(&logs_by_fd, log->listen_fd);

	DLLIST_REMOVE(&log_connections, log);

	iter = hash_table_iterate_init(log->clients);
	while (hash_table_iterate(iter, log->clients, &key, &client)) {
		i_free(client);
		client_count++;
	}
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&log->clients);

	if (client_count > 0 && shutting_down) {
		i_warning("Shutting down logging for '%s' with %u clients",
			  log->default_prefix, client_count);
	}

	i_stream_unref(&log->input);
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
		log_connection_destroy(log_connections, TRUE);
	array_free(&logs_by_fd);
}
