/* Copyright (C) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "env-util.h"
#include "config-request.h"
#include "config-connection.h"

#include <stdlib.h>
#include <unistd.h>

#define MAX_INBUF_SIZE 1024

#define CONFIG_CLIENT_PROTOCOL_MAJOR_VERSION 1
#define CONFIG_CLIENT_PROTOCOL_MINOR_VERSION 0

struct config_connection {
	struct config_connection *prev, *next;

	int fd;
	struct istream *input;
	struct ostream *output;
	struct io *io;

	unsigned int version_received:1;
	unsigned int handshaked:1;
};

struct config_connection *config_connections = NULL;

static const char *const *
config_connection_next_line(struct config_connection *conn)
{
	const char *line;

	line = i_stream_next_line(conn->input);
	if (line == NULL)
		return NULL;

	return t_strsplit(line, "\t");
}

static void
config_request_output(const char *key, const char *value,
		      bool list ATTR_UNUSED, void *context)
{
	struct ostream *output = context;

	o_stream_send_str(output, key);
	o_stream_send_str(output, "=");
	o_stream_send_str(output, value);
	o_stream_send_str(output, "\n");
}

struct config_request_get_string_ctx {
	pool_t pool;
	ARRAY_TYPE(const_string) strings;
};

static void
config_request_get_strings(const char *key, const char *value,
			   bool list, void *context)
{
	struct config_request_get_string_ctx *ctx = context;

	value = p_strdup_printf(ctx->pool, list ? "-%s=%s" : "%s=%s",
				key, value);
	array_append(&ctx->strings, &value, 1);
}

static int config_string_cmp(const void *p1, const void *p2)
{
	const char *s1 = *(const char *const *)p1;
	const char *s2 = *(const char *const *)p2;
	unsigned int i = 0;

	while (s1[i] == s2[i]) {
		if (s1[i] == '\0' || s1[i] == '=')
			return 0;
		i++;
	}

	if (s1[i] == '=')
		return -1;
	if (s2[i] == '=')
		return 1;
	return s1[i] - s2[i];
}

static unsigned int prefix_stack_pop(ARRAY_TYPE(uint) *stack)
{
	const unsigned int *indexes;
	unsigned int idx, count;

	indexes = array_get(stack, &count);
	idx = count <= 1 ? -1U : indexes[count-2];
	array_delete(stack, count-1, 1);
	return idx;
}

static void config_connection_request_human(struct ostream *output,
					    const char *service,
					    enum config_dump_flags flags)
{
	static const char *ident_str = "               ";
	ARRAY_TYPE(const_string) prefixes_arr;
	ARRAY_TYPE(uint) prefix_idx_stack;
	struct config_request_get_string_ctx ctx;
	const char **strings, *const *args, *p, *str, *const *prefixes;
	const char *key, *value;
	unsigned int i, j, count, len, prefix_count, skip_len;
	unsigned int indent = 0, prefix_idx = -1U;

	ctx.pool = pool_alloconly_create("config human strings", 10240);
	i_array_init(&ctx.strings, 256);
	config_request_handle(service, flags, config_request_get_strings, &ctx);

	strings = array_get_modifiable(&ctx.strings, &count);
	qsort(strings, count, sizeof(*strings), config_string_cmp);

	p_array_init(&prefixes_arr, ctx.pool, 32);
	for (i = 0; i < count && strings[i][0] == '-'; i++) T_BEGIN {
		p = strchr(strings[i], '=');
		i_assert(p != NULL);
		for (args = t_strsplit(p + 1, " "); *args != NULL; args++) {
			str = p_strdup_printf(ctx.pool, "%s/%s/",
					      t_strcut(strings[i]+1, '='),
					      *args);
			array_append(&prefixes_arr, &str, 1);
		}
	} T_END;
	prefixes = array_get(&prefixes_arr, &prefix_count);

	p_array_init(&prefix_idx_stack, ctx.pool, 8);
	for (; i < count; i++) T_BEGIN {
		value = strchr(strings[i], '=');
		i_assert(value != NULL);
		key = t_strdup_until(strings[i], value);
		value++;

		j = 0;
		while (prefix_idx != -1U) {
			len = strlen(prefixes[prefix_idx]);
			if (strncmp(prefixes[prefix_idx], key, len) != 0) {
				prefix_idx = prefix_stack_pop(&prefix_idx_stack);
				indent--;
				o_stream_send(output, ident_str, indent*2);
				o_stream_send_str(output, "}\n");
			} else if (strchr(key + len, '/') == NULL) {
				/* keep the prefix */
				j = prefix_count;
				break;
			} else {
				/* subprefix */
				break;
			}
		}
		for (; j < prefix_count; j++) {
			len = strlen(prefixes[j]);
			if (strncmp(prefixes[j], key, len) == 0 &&
			    strchr(key + len, '/') == NULL) {
				key += prefix_idx == -1U ? 0 :
					strlen(prefixes[prefix_idx]);
				o_stream_send(output, ident_str, indent*2);
				o_stream_send_str(output, t_strcut(key, '/'));
				o_stream_send_str(output, " {\n");
				indent++;
				prefix_idx = j;
				array_append(&prefix_idx_stack, &prefix_idx, 1);
				break;
			}
		}
		skip_len = prefix_idx == -1U ? 0 : strlen(prefixes[prefix_idx]);
		i_assert(strncmp(prefixes[prefix_idx], strings[i], skip_len) == 0);
		o_stream_send(output, ident_str, indent*2);
		key = strings[i] + skip_len;
		value = strchr(key, '=');
		o_stream_send(output, key, value-key);
		o_stream_send_str(output, " = ");
		o_stream_send_str(output, value+1);
		o_stream_send(output, "\n", 1);
	} T_END;

	while (prefix_idx != -1U) {
		prefix_idx = prefix_stack_pop(&prefix_idx_stack);
		indent--;
		o_stream_send(output, ident_str, indent*2);
		o_stream_send_str(output, "}\n");
	}

	array_free(&ctx.strings);
	pool_unref(&ctx.pool);
}

static void config_connection_request(struct config_connection *conn,
				      const char *const *args,
				      enum config_dump_flags flags)
{
	const char *service = "";

	/* [<service> [<args>]] */
	if (args[0] != NULL)
		service = args[0];

	o_stream_cork(conn->output);
	if ((flags & CONFIG_DUMP_FLAG_HUMAN) == 0) {
		config_request_handle(service, flags, config_request_output,
				      conn->output);
		o_stream_send_str(conn->output, "\n");
	} else {
		config_connection_request_human(conn->output, service, flags);
	}
	o_stream_uncork(conn->output);
}

static void config_connection_input(void *context)
{
	struct config_connection *conn = context;
	const char *const *args, *line;

	switch (i_stream_read(conn->input)) {
	case -2:
		i_error("BUG: Config client connection sent too much data");
                config_connection_destroy(conn);
		return;
	case -1:
                config_connection_destroy(conn);
		return;
	}

	if (!conn->version_received) {
		line = i_stream_next_line(conn->input);
		if (line == NULL)
			return;

		if (strncmp(line, "VERSION\t", 8) != 0 ||
		    atoi(t_strcut(line + 8, '\t')) !=
		    CONFIG_CLIENT_PROTOCOL_MAJOR_VERSION) {
			i_error("Config client not compatible with this server "
				"(mixed old and new binaries?)");
			config_connection_destroy(conn);
			return;
		}
		conn->version_received = TRUE;
	}

	while ((args = config_connection_next_line(conn)) != NULL) {
		if (args[0] == NULL)
			continue;
		if (strcmp(args[0], "REQ") == 0)
			config_connection_request(conn, args + 1, 0);
	}
}

struct config_connection *config_connection_create(int fd)
{
	struct config_connection *conn;

	conn = i_new(struct config_connection, 1);
	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	conn->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	conn->io = io_add(fd, IO_READ, config_connection_input, conn);
	DLLIST_PREPEND(&config_connections, conn);
	return conn;
}

void config_connection_destroy(struct config_connection *conn)
{
	DLLIST_REMOVE(&config_connections, conn);

	io_remove(&conn->io);
	i_stream_destroy(&conn->input);
	o_stream_destroy(&conn->output);
	if (close(conn->fd) < 0)
		i_error("close(config conn) failed: %m");
	i_free(conn);
}

void config_connection_dump_request(int fd, const char *service,
				    enum config_dump_flags flags)
{
	struct config_connection *conn;
	const char *args[2] = { service, NULL };

	conn = config_connection_create(fd);
	config_connection_request(conn, args, flags);
	config_connection_destroy(conn);
}

static void config_request_putenv(const char *key, const char *value,
				  bool list ATTR_UNUSED,
				  void *context ATTR_UNUSED)
{
	T_BEGIN {
		env_put(t_strconcat(t_str_ucase(key), "=", value, NULL));
	} T_END;
}

void config_connection_putenv(const char *service)
{
	config_request_handle(service, 0, config_request_putenv, NULL);
}

void config_connections_destroy_all(void)
{
	while (config_connections != NULL)
		config_connection_destroy(config_connections);
}
