/* Copyright (c) 2008-2012 Dovecot authors, see the included COPYING redis */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "connection.h"
#include "dict-private.h"

#define REDIS_DEFAULT_PORT 6379
#define REDIS_DEFAULT_LOOKUP_TIMEOUT_MSECS (1000*30)

struct redis_connection {
	struct connection conn;
	struct redis_dict *dict;

	string_t *last_reply;
	unsigned int bytes_left;
	bool value_not_found;
	bool value_received;
};

struct redis_dict {
	struct dict dict;
	struct ip_addr ip;
	unsigned int port;
	unsigned int timeout_msecs;

	struct ioloop *ioloop;
	struct redis_connection conn;
	bool connected;
};

static struct connection_list *redis_connections;

static void redis_conn_destroy(struct connection *_conn)
{
	struct redis_connection *conn = (struct redis_connection *)_conn;

	conn->dict->connected = FALSE;
	connection_disconnect(_conn);
	if (conn->dict->ioloop != NULL)
		io_loop_stop(conn->dict->ioloop);
}

static void redis_conn_input(struct connection *_conn)
{
	struct redis_connection *conn = (struct redis_connection *)_conn;
	const unsigned char *data;
	size_t size;
	const char *line;

	switch (i_stream_read(_conn->input)) {
	case 0:
		return;
	case -1:
		redis_conn_destroy(_conn);
		return;
	default:
		break;
	}

	if (conn->bytes_left == 0) {
		/* read the size first */
		line = i_stream_next_line(_conn->input);
		if (line == NULL)
			return;
		if (strcmp(line, "$-1") == 0) {
			conn->value_received = TRUE;
			conn->value_not_found = TRUE;
			if (conn->dict->ioloop != NULL)
				io_loop_stop(conn->dict->ioloop);
			return;
		}
		if (line[0] != '$' || str_to_uint(line+1, &conn->bytes_left) < 0) {
			i_error("redis: Unexpected input (wanted $size): %s",
				line);
			redis_conn_destroy(_conn);
			return;
		}
		conn->bytes_left += 2; /* include trailing CRLF */
	}

	data = i_stream_get_data(_conn->input, &size);
	if (size > conn->bytes_left)
		size = conn->bytes_left;
	str_append_n(conn->last_reply, data, size);

	conn->bytes_left -= size;
	i_stream_skip(_conn->input, size);

	if (conn->bytes_left == 0) {
		/* drop trailing CRLF */
		conn->value_received = TRUE;
		str_truncate(conn->last_reply, str_len(conn->last_reply)-2);
		if (conn->dict->ioloop != NULL)
			io_loop_stop(conn->dict->ioloop);
	}
}

static void redis_conn_connected(struct connection *_conn)
{
	struct redis_connection *conn = (struct redis_connection *)_conn;

	if ((errno = net_geterror(_conn->fd_in)) != 0) {
		i_error("redis: connect(%s, %u) failed: %m",
			net_ip2addr(&conn->dict->ip), conn->dict->port);
	} else {
		conn->dict->connected = TRUE;
	}
	if (conn->dict->ioloop != NULL)
		io_loop_stop(conn->dict->ioloop);
}

static const struct connection_settings redis_conn_set = {
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.client = TRUE
};

static const struct connection_vfuncs redis_conn_vfuncs = {
	.destroy = redis_conn_destroy,
	.input = redis_conn_input,
	.connected = redis_conn_connected
};

static struct dict *
redis_dict_init(struct dict *driver, const char *uri,
		enum dict_data_type value_type ATTR_UNUSED,
		const char *username ATTR_UNUSED,
		const char *base_dir ATTR_UNUSED)
{
	struct redis_dict *dict;
	const char *const *args;

	if (redis_connections == NULL) {
		redis_connections =
			connection_list_init(&redis_conn_set,
					     &redis_conn_vfuncs);
	}

	dict = i_new(struct redis_dict, 1);
	if (net_addr2ip("127.0.0.1", &dict->ip) < 0)
		i_unreached();
	dict->port = REDIS_DEFAULT_PORT;
	dict->timeout_msecs = REDIS_DEFAULT_LOOKUP_TIMEOUT_MSECS;

	args = t_strsplit(uri, ":");
	for (; *args != NULL; args++) {
		if (strncmp(*args, "host=", 5) == 0) {
			if (net_addr2ip(*args+5, &dict->ip) < 0)
				i_error("Invalid IP: %s", *args+5);
		} else if (strncmp(*args, "port=", 5) == 0) {
			if (str_to_uint(*args+5, &dict->port) < 0)
				i_error("Invalid port: %s", *args+5);
		} else if (strncmp(*args, "timeout_msecs=", 14) == 0) {
			if (str_to_uint(*args+14, &dict->timeout_msecs) < 0)
				i_error("Invalid timeout_msecs: %s", *args+14);
		} else {
			i_error("Unknown parameter: %s", *args);
		}
	}
	connection_init_client_ip(redis_connections, &dict->conn.conn,
				  &dict->ip, dict->port);

	dict->dict = *driver;
	dict->conn.last_reply = str_new(default_pool, 256);
	dict->conn.dict = dict;
	return &dict->dict;
}

static void redis_dict_deinit(struct dict *_dict)
{
	struct redis_dict *dict = (struct redis_dict *)_dict;

	connection_deinit(&dict->conn.conn);
	str_free(&dict->conn.last_reply);
	i_free(dict);

	if (redis_connections->connections == NULL)
		connection_list_deinit(&redis_connections);
}

static void redis_dict_lookup_timeout(struct redis_dict *dict)
{
	i_error("redis: Lookup timed out in %u.%03u secs",
		dict->timeout_msecs/1000, dict->timeout_msecs%1000);
	io_loop_stop(dict->ioloop);
}

static int redis_dict_lookup(struct dict *_dict, pool_t pool,
			     const char *key, const char **value_r)
{
	struct redis_dict *dict = (struct redis_dict *)_dict;
	struct timeout *to;
	const char *cmd;
	struct ioloop *prev_ioloop = current_ioloop;

	if (strncmp(key, DICT_PATH_SHARED, strlen(DICT_PATH_SHARED)) == 0)
		key += strlen(DICT_PATH_SHARED);
	else {
		i_error("redis: Only shared key lookups supported for now");
		return -1;
	}

	dict->conn.value_received = FALSE;
	dict->conn.value_not_found = FALSE;

	dict->ioloop = io_loop_create();
	connection_switch_ioloop(&dict->conn.conn);

	if (dict->conn.conn.fd_in == -1 &&
	    connection_client_connect(&dict->conn.conn) < 0) {
		i_error("redis: Couldn't connect to %s:%u",
			net_ip2addr(&dict->ip), dict->port);
	} else {
		to = timeout_add(dict->timeout_msecs,
				 redis_dict_lookup_timeout, dict);
		if (!dict->connected) {
			/* wait for connection */
			io_loop_run(dict->ioloop);
		}

		if (dict->connected) {
			cmd = t_strdup_printf("*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n",
					      (int)strlen(key), key);
			o_stream_send_str(dict->conn.conn.output, cmd);

			str_truncate(dict->conn.last_reply, 0);
			io_loop_run(dict->ioloop);
		}
		timeout_remove(&to);
	}

	current_ioloop = prev_ioloop;
	connection_switch_ioloop(&dict->conn.conn);
	current_ioloop = dict->ioloop;
	io_loop_destroy(&dict->ioloop);

	if (!dict->conn.value_received) {
		/* we failed in some way. make sure we disconnect since the
		   connection state isn't known anymore */
		redis_conn_destroy(&dict->conn.conn);
		return -1;
	}
	if (dict->conn.value_not_found)
		return 0;

	*value_r = p_strdup(pool, str_c(dict->conn.last_reply));
	return 1;
}

struct dict dict_driver_redis = {
	.name = "redis",
	{
		redis_dict_init,
		redis_dict_deinit,
		NULL,
		redis_dict_lookup,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	}
};
