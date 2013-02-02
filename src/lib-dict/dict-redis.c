/* Copyright (c) 2008-2013 Dovecot authors, see the included COPYING redis */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "connection.h"
#include "dict-private.h"

#define REDIS_DEFAULT_PORT 6379
#define REDIS_DEFAULT_LOOKUP_TIMEOUT_MSECS (1000*30)
#define DICT_USERNAME_SEPARATOR '/'

enum redis_input_state {
	/* expecting $-1 / $<size> followed by GET reply */
	REDIS_INPUT_STATE_GET,
	/* expecting +QUEUED */
	REDIS_INPUT_STATE_MULTI,
	/* expecting +OK reply for DISCARD */
	REDIS_INPUT_STATE_DISCARD,
	/* expecting *<nreplies> */
	REDIS_INPUT_STATE_EXEC,
	/* expecting EXEC reply */
	REDIS_INPUT_STATE_EXEC_REPLY
};

struct redis_connection {
	struct connection conn;
	struct redis_dict *dict;

	string_t *last_reply;
	unsigned int bytes_left;
	bool value_not_found;
	bool value_received;
};

struct redis_dict_reply {
	unsigned int reply_count;
	dict_transaction_commit_callback_t *callback;
	void *context;
};

struct redis_dict {
	struct dict dict;
	struct ip_addr ip;
	char *username, *key_prefix;
	unsigned int port;
	unsigned int timeout_msecs;

	struct ioloop *ioloop;
	struct redis_connection conn;

	ARRAY(enum redis_input_state) input_states;
	ARRAY(struct redis_dict_reply) replies;

	bool connected;
	bool transaction_open;
};

struct redis_dict_transaction_context {
	struct dict_transaction_context ctx;
	unsigned int cmd_count;
	bool failed;
};

static struct connection_list *redis_connections;

static void
redis_input_state_add(struct redis_dict *dict, enum redis_input_state state)
{
	array_append(&dict->input_states, &state, 1);
}

static void redis_input_state_remove(struct redis_dict *dict)
{
	array_delete(&dict->input_states, 0, 1);
}

static void redis_conn_destroy(struct connection *_conn)
{
	struct redis_connection *conn = (struct redis_connection *)_conn;
	const struct redis_dict_reply *reply;

	conn->dict->connected = FALSE;
	connection_disconnect(_conn);

	array_foreach(&conn->dict->replies, reply) {
		if (reply->callback != NULL)
			reply->callback(-1, reply->context);
	}
	array_clear(&conn->dict->replies);
	array_clear(&conn->dict->input_states);

	if (conn->dict->ioloop != NULL)
		io_loop_stop(conn->dict->ioloop);
}

static void redis_wait(struct redis_dict *dict)
{
	struct ioloop *prev_ioloop = current_ioloop;

	i_assert(dict->ioloop == NULL);

	dict->ioloop = io_loop_create();
	connection_switch_ioloop(&dict->conn.conn);

	do {
		io_loop_run(dict->ioloop);
	} while (array_count(&dict->input_states) > 0);

	current_ioloop = prev_ioloop;
	connection_switch_ioloop(&dict->conn.conn);
	current_ioloop = dict->ioloop;
	io_loop_destroy(&dict->ioloop);
}

static int redis_input_get(struct redis_connection *conn)
{
	const unsigned char *data;
	size_t size;
	const char *line;

	if (conn->bytes_left == 0) {
		/* read the size first */
		line = i_stream_next_line(conn->conn.input);
		if (line == NULL)
			return 0;
		if (strcmp(line, "$-1") == 0) {
			conn->value_received = TRUE;
			conn->value_not_found = TRUE;
			if (conn->dict->ioloop != NULL)
				io_loop_stop(conn->dict->ioloop);
			redis_input_state_remove(conn->dict);
			return 1;
		}
		if (line[0] != '$' || str_to_uint(line+1, &conn->bytes_left) < 0) {
			i_error("redis: Unexpected input (wanted $size): %s",
				line);
			redis_conn_destroy(&conn->conn);
			return 1;
		}
		conn->bytes_left += 2; /* include trailing CRLF */
	}

	data = i_stream_get_data(conn->conn.input, &size);
	if (size > conn->bytes_left)
		size = conn->bytes_left;
	str_append_n(conn->last_reply, data, size);

	conn->bytes_left -= size;
	i_stream_skip(conn->conn.input, size);

	if (conn->bytes_left > 0)
		return 0;

	/* reply fully read - drop trailing CRLF */
	conn->value_received = TRUE;
	str_truncate(conn->last_reply, str_len(conn->last_reply)-2);

	if (conn->dict->ioloop != NULL)
		io_loop_stop(conn->dict->ioloop);
	redis_input_state_remove(conn->dict);
	return 1;
}

static int redis_conn_input_more(struct redis_connection *conn)
{
	struct redis_dict *dict = conn->dict;
	struct redis_dict_reply *reply;
	const enum redis_input_state *states;
	enum redis_input_state state;
	unsigned int count, num_replies;
	const char *line;

	states = array_get(&dict->input_states, &count);
	if (count == 0) {
		line = i_stream_next_line(conn->conn.input);
		if (line == NULL)
			return 0;
		i_error("redis: Unexpected input (expected nothing): %s", line);
		return -1;
	}
	state = states[0];
	if (state == REDIS_INPUT_STATE_GET)
		return redis_input_get(conn);

	line = i_stream_next_line(conn->conn.input);
	if (line == NULL)
		return 0;

	redis_input_state_remove(dict);
	switch (state) {
	case REDIS_INPUT_STATE_GET:
		i_unreached();
	case REDIS_INPUT_STATE_MULTI:
	case REDIS_INPUT_STATE_DISCARD:
		if (line[0] != '+')
			break;
		return 1;
	case REDIS_INPUT_STATE_EXEC:
		if (line[0] != '*' || str_to_uint(line+1, &num_replies) < 0)
			break;

		reply = array_idx_modifiable(&dict->replies, 0);
		i_assert(reply->reply_count > 0);
		if (reply->reply_count != num_replies) {
			i_error("redis: EXEC expected %u replies, not %u",
				reply->reply_count, num_replies);
			return -1;
		}
		return 1;
	case REDIS_INPUT_STATE_EXEC_REPLY:
		if (*line != '+' && *line != ':')
			break;
		/* success, just ignore the actual reply */
		reply = array_idx_modifiable(&dict->replies, 0);
		i_assert(reply->reply_count > 0);
		if (--reply->reply_count == 0) {
			if (reply->callback != NULL)
				reply->callback(1, reply->context);
			array_delete(&dict->replies, 0, 1);
			/* if we're running in a dict-ioloop, we're handling a
			   synchronous commit and need to stop now */
			if (array_count(&dict->replies) == 0 &&
			    conn->dict->ioloop != NULL)
				io_loop_stop(conn->dict->ioloop);
		}
		return 1;
	}
	i_error("redis: Unexpected input (state=%d): %s", state, line);
	return -1;
}

static void redis_conn_input(struct connection *_conn)
{
	struct redis_connection *conn = (struct redis_connection *)_conn;
	int ret;

	switch (i_stream_read(_conn->input)) {
	case 0:
		return;
	case -1:
		if (conn->dict->ioloop != NULL)
			i_error("redis: Disconnected unexpectedly");
		redis_conn_destroy(_conn);
		return;
	default:
		break;
	}

	while ((ret = redis_conn_input_more(conn)) > 0) ;
	if (ret < 0)
		redis_conn_destroy(_conn);
}

static void redis_conn_connected(struct connection *_conn, bool success)
{
	struct redis_connection *conn = (struct redis_connection *)_conn;

	if (!success) {
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
	.client_connected = redis_conn_connected
};

static const char *redis_escape_username(const char *username)
{
	const char *p;
	string_t *str = t_str_new(64);

	for (p = username; *p != '\0'; p++) {
		switch (*p) {
		case DICT_USERNAME_SEPARATOR:
			str_append(str, "\\-");
			break;
		case '\\':
			str_append(str, "\\\\");
			break;
		default:
			str_append_c(str, *p);
		}
	}
	return str_c(str);
}

static int
redis_dict_init(struct dict *driver, const char *uri,
		enum dict_data_type value_type ATTR_UNUSED,
		const char *username,
		const char *base_dir ATTR_UNUSED, struct dict **dict_r,
		const char **error_r)
{
	struct redis_dict *dict;
	const char *const *args;
	int ret = 0;

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
	dict->key_prefix = i_strdup("");

	args = t_strsplit(uri, ":");
	for (; *args != NULL; args++) {
		if (strncmp(*args, "host=", 5) == 0) {
			if (net_addr2ip(*args+5, &dict->ip) < 0) {
				*error_r = t_strdup_printf("Invalid IP: %s",
							   *args+5);
				ret = -1;
			}
		} else if (strncmp(*args, "port=", 5) == 0) {
			if (str_to_uint(*args+5, &dict->port) < 0) {
				*error_r = t_strdup_printf("Invalid port: %s",
							   *args+5);
				ret = -1;
			}
		} else if (strncmp(*args, "prefix=", 7) == 0) {
			i_free(dict->key_prefix);
			dict->key_prefix = i_strdup(*args + 7);
		} else if (strncmp(*args, "timeout_msecs=", 14) == 0) {
			if (str_to_uint(*args+14, &dict->timeout_msecs) < 0) {
				*error_r = t_strdup_printf(
					"Invalid timeout_msecs: %s", *args+14);
				ret = -1;
			}
		} else {
			*error_r = t_strdup_printf("Unknown parameter: %s",
						   *args);
			ret = -1;
		}
	}
	if (ret < 0) {
		i_free(dict->key_prefix);
		i_free(dict);
		return -1;
	}
	connection_init_client_ip(redis_connections, &dict->conn.conn,
				  &dict->ip, dict->port);
	dict->dict = *driver;
	dict->conn.last_reply = str_new(default_pool, 256);
	dict->conn.dict = dict;

	i_array_init(&dict->input_states, 4);
	i_array_init(&dict->replies, 4);
	if (strchr(username, DICT_USERNAME_SEPARATOR) == NULL)
		dict->username = i_strdup(username);
	else {
		/* escape the username */
		dict->username = i_strdup(redis_escape_username(username));
	}

	*dict_r = &dict->dict;
	return 0;
}

static void redis_dict_deinit(struct dict *_dict)
{
	struct redis_dict *dict = (struct redis_dict *)_dict;

	if (array_count(&dict->input_states) > 0) {
		i_assert(dict->connected);
		redis_wait(dict);
	}
	connection_deinit(&dict->conn.conn);
	str_free(&dict->conn.last_reply);
	array_free(&dict->replies);
	array_free(&dict->input_states);
	i_free(dict->key_prefix);
	i_free(dict->username);
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

static const char *
redis_dict_get_full_key(struct redis_dict *dict, const char *key)
{
	if (strncmp(key, DICT_PATH_SHARED, strlen(DICT_PATH_SHARED)) == 0)
		key += strlen(DICT_PATH_SHARED);
	else if (strncmp(key, DICT_PATH_PRIVATE, strlen(DICT_PATH_PRIVATE)) == 0) {
		key = t_strdup_printf("%s%c%s", dict->username,
				      DICT_USERNAME_SEPARATOR,
				      key + strlen(DICT_PATH_PRIVATE));
	} else {
		i_unreached();
	}
	if (*dict->key_prefix != '\0')
		key = t_strconcat(dict->key_prefix, key, NULL);
	return key;
}

static int
redis_dict_lookup_real(struct redis_dict *dict, pool_t pool,
		       const char *key, const char **value_r)
{
	struct timeout *to;
	const char *cmd;
	struct ioloop *prev_ioloop = current_ioloop;

	key = redis_dict_get_full_key(dict, key);

	dict->conn.value_received = FALSE;
	dict->conn.value_not_found = FALSE;

	i_assert(dict->ioloop == NULL);

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
			o_stream_nsend_str(dict->conn.conn.output, cmd);

			str_truncate(dict->conn.last_reply, 0);
			redis_input_state_add(dict, REDIS_INPUT_STATE_GET);
			do {
				io_loop_run(dict->ioloop);
			} while (array_count(&dict->input_states) > 0);
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

static int redis_dict_lookup(struct dict *_dict, pool_t pool,
			     const char *key, const char **value_r)
{
	struct redis_dict *dict = (struct redis_dict *)_dict;
	int ret;

	i_assert(!dict->transaction_open);

	if (pool->datastack_pool)
		ret = redis_dict_lookup_real(dict, pool, key, value_r);
	else T_BEGIN {
		ret = redis_dict_lookup_real(dict, pool, key, value_r);
	} T_END;
	return ret;
}

static struct dict_transaction_context *
redis_transaction_init(struct dict *_dict)
{
	struct redis_dict *dict = (struct redis_dict *)_dict;
	struct redis_dict_transaction_context *ctx;

	i_assert(!dict->transaction_open);
	dict->transaction_open = TRUE;

	ctx = i_new(struct redis_dict_transaction_context, 1);
	ctx->ctx.dict = _dict;

	if (dict->conn.conn.fd_in == -1 &&
	    connection_client_connect(&dict->conn.conn) < 0) {
		i_error("redis: Couldn't connect to %s:%u",
			net_ip2addr(&dict->ip), dict->port);
	} else if (!dict->connected) {
		/* wait for connection */
		redis_wait(dict);
	}
	return &ctx->ctx;
}

static int
redis_transaction_commit(struct dict_transaction_context *_ctx, bool async,
			 dict_transaction_commit_callback_t *callback,
			 void *context)
{
	struct redis_dict_transaction_context *ctx =
		(struct redis_dict_transaction_context *)_ctx;
	struct redis_dict *dict = (struct redis_dict *)_ctx->dict;
	struct redis_dict_reply *reply;
	unsigned int i;
	int ret = 1;

	i_assert(dict->transaction_open);
	dict->transaction_open = FALSE;

	if (ctx->failed) {
		/* make sure we're disconnected */
		redis_conn_destroy(&dict->conn.conn);
		ret = -1;
	} else if (_ctx->changed) {
		i_assert(ctx->cmd_count > 0);

		o_stream_nsend_str(dict->conn.conn.output,
				   "*1\r\n$4\r\nEXEC\r\n");
		reply = array_append_space(&dict->replies);
		reply->callback = callback;
		reply->context = context;
		reply->reply_count = ctx->cmd_count;
		redis_input_state_add(dict, REDIS_INPUT_STATE_EXEC);
		for (i = 0; i < ctx->cmd_count; i++)
			redis_input_state_add(dict, REDIS_INPUT_STATE_EXEC_REPLY);
		if (async)
			return 1;
		redis_wait(dict);
	}
	if (callback != NULL)
		callback(ret, context);
	i_free(ctx);
	return ret;
}

static void redis_transaction_rollback(struct dict_transaction_context *_ctx)
{
	struct redis_dict_transaction_context *ctx =
		(struct redis_dict_transaction_context *)_ctx;
	struct redis_dict *dict = (struct redis_dict *)_ctx->dict;
	struct redis_dict_reply *reply;

	i_assert(dict->transaction_open);
	dict->transaction_open = FALSE;

	if (ctx->failed) {
		/* make sure we're disconnected */
		redis_conn_destroy(&dict->conn.conn);
	} else if (_ctx->changed) {
		o_stream_nsend_str(dict->conn.conn.output,
				   "*1\r\n$7\r\nDISCARD\r\n");
		reply = array_append_space(&dict->replies);
		reply->reply_count = 1;
		redis_input_state_add(dict, REDIS_INPUT_STATE_DISCARD);
	}
	i_free(ctx);
}

static int redis_check_transaction(struct redis_dict_transaction_context *ctx)
{
	struct redis_dict *dict = (struct redis_dict *)ctx->ctx.dict;

	if (ctx->failed)
		return -1;
	if (ctx->ctx.changed)
		return 0;

	redis_input_state_add(dict, REDIS_INPUT_STATE_MULTI);
	if (o_stream_send_str(dict->conn.conn.output,
			      "*1\r\n$5\r\nMULTI\r\n") < 0) {
		ctx->failed = TRUE;
		return -1;
	}
	return 0;
}

static void redis_set(struct dict_transaction_context *_ctx,
		      const char *key, const char *value)
{
	struct redis_dict_transaction_context *ctx =
		(struct redis_dict_transaction_context *)_ctx;
	struct redis_dict *dict = (struct redis_dict *)_ctx->dict;
	const char *cmd;

	if (redis_check_transaction(ctx) < 0)
		return;

	key = redis_dict_get_full_key(dict, key);
	cmd = t_strdup_printf("*3\r\n$3\r\nSET\r\n$%u\r\n%s\r\n$%u\r\n%s\r\n",
			      (unsigned int)strlen(key), key,
			      (unsigned int)strlen(value), value);
	if (o_stream_send_str(dict->conn.conn.output, cmd) < 0)
		ctx->failed = TRUE;
	redis_input_state_add(dict, REDIS_INPUT_STATE_MULTI);
	ctx->cmd_count++;
}

static void redis_unset(struct dict_transaction_context *_ctx,
			const char *key)
{
	struct redis_dict_transaction_context *ctx =
		(struct redis_dict_transaction_context *)_ctx;
	struct redis_dict *dict = (struct redis_dict *)_ctx->dict;
	const char *cmd;

	if (redis_check_transaction(ctx) < 0)
		return;

	key = redis_dict_get_full_key(dict, key);
	cmd = t_strdup_printf("*2\r\n$3\r\nDEL\r\n$%u\r\n%s\r\n",
			      (unsigned int)strlen(key), key);
	if (o_stream_send_str(dict->conn.conn.output, cmd) < 0)
		ctx->failed = TRUE;
	redis_input_state_add(dict, REDIS_INPUT_STATE_MULTI);
	ctx->cmd_count++;
}

static void redis_append(struct dict_transaction_context *_ctx,
			 const char *key, const char *value)
{
	struct redis_dict_transaction_context *ctx =
		(struct redis_dict_transaction_context *)_ctx;
	struct redis_dict *dict = (struct redis_dict *)_ctx->dict;
	const char *cmd;

	if (redis_check_transaction(ctx) < 0)
		return;

	key = redis_dict_get_full_key(dict, key);
	cmd = t_strdup_printf("*3\r\n$6\r\nAPPEND\r\n$%u\r\n%s\r\n$%u\r\n%s\r\n",
			      (unsigned int)strlen(key), key,
			      (unsigned int)strlen(value), value);
	if (o_stream_send_str(dict->conn.conn.output, cmd) < 0)
		ctx->failed = TRUE;
	redis_input_state_add(dict, REDIS_INPUT_STATE_MULTI);
	ctx->cmd_count++;
}

static void redis_atomic_inc(struct dict_transaction_context *_ctx,
			     const char *key, long long diff)
{
	struct redis_dict_transaction_context *ctx =
		(struct redis_dict_transaction_context *)_ctx;
	struct redis_dict *dict = (struct redis_dict *)_ctx->dict;
	const char *cmd, *diffstr;

	if (redis_check_transaction(ctx) < 0)
		return;

	key = redis_dict_get_full_key(dict, key);
	diffstr = t_strdup_printf("%lld", diff);
	cmd = t_strdup_printf("*3\r\n$6\r\nINCRBY\r\n$%u\r\n%s\r\n$%u\r\n%s\r\n",
			      (unsigned int)strlen(key), key,
			      (unsigned int)strlen(diffstr), diffstr);
	if (o_stream_send_str(dict->conn.conn.output, cmd) < 0)
		ctx->failed = TRUE;
	redis_input_state_add(dict, REDIS_INPUT_STATE_MULTI);
	ctx->cmd_count++;
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
		redis_transaction_init,
		redis_transaction_commit,
		redis_transaction_rollback,
		redis_set,
		redis_unset,
		redis_append,
		redis_atomic_inc
	}
};
