/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING redis */

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
	/* expecting +OK reply for AUTH */
	REDIS_INPUT_STATE_AUTH,
	/* expecting +OK reply for SELECT */
	REDIS_INPUT_STATE_SELECT,
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
	char *username, *password, *key_prefix, *expire_value;
	unsigned int timeout_msecs, db_id;

	struct ioloop *ioloop, *prev_ioloop;
	struct redis_connection conn;

	ARRAY(enum redis_input_state) input_states;
	ARRAY(struct redis_dict_reply) replies;

	bool connected;
	bool transaction_open;
	bool db_id_set;
};

struct redis_dict_transaction_context {
	struct dict_transaction_context ctx;
	unsigned int cmd_count;
	char *error;
};

static struct connection_list *redis_connections;

static void
redis_input_state_add(struct redis_dict *dict, enum redis_input_state state)
{
	array_push_back(&dict->input_states, &state);
}

static void redis_input_state_remove(struct redis_dict *dict)
{
	array_delete(&dict->input_states, 0, 1);
}

static void redis_callback(struct redis_dict *dict,
			   const struct redis_dict_reply *reply,
			   const struct dict_commit_result *result)
{
	if (reply->callback != NULL) {
		if (dict->prev_ioloop != NULL) {
			/* Don't let callback see that we've created our
			   internal ioloop in case it wants to add some ios
			   or timeouts. */
			current_ioloop = dict->prev_ioloop;
		}
		reply->callback(result, reply->context);
		if (dict->prev_ioloop != NULL)
			current_ioloop = dict->ioloop;
	}
}

static void
redis_disconnected(struct redis_connection *conn, const char *reason)
{
	const struct dict_commit_result result = {
		DICT_COMMIT_RET_FAILED, reason
	};
	const struct redis_dict_reply *reply;

	conn->dict->db_id_set = FALSE;
	conn->dict->connected = FALSE;
	connection_disconnect(&conn->conn);

	array_foreach(&conn->dict->replies, reply)
		redis_callback(conn->dict, reply, &result);
	array_clear(&conn->dict->replies);
	array_clear(&conn->dict->input_states);

	if (conn->dict->ioloop != NULL)
		io_loop_stop(conn->dict->ioloop);
}

static void redis_conn_destroy(struct connection *_conn)
{
	struct redis_connection *conn = (struct redis_connection *)_conn;

	redis_disconnected(conn, connection_disconnect_reason(_conn));
}

static void redis_dict_wait_timeout(struct redis_dict *dict)
{
	const char *reason = t_strdup_printf(
		"redis: Commit timed out in %u.%03u secs",
		dict->timeout_msecs/1000, dict->timeout_msecs%1000);
	redis_disconnected(&dict->conn, reason);
}

static void redis_wait(struct redis_dict *dict)
{
	struct timeout *to;

	i_assert(dict->ioloop == NULL);

	dict->prev_ioloop = current_ioloop;
	dict->ioloop = io_loop_create();
	to = timeout_add(dict->timeout_msecs, redis_dict_wait_timeout, dict);
	connection_switch_ioloop(&dict->conn.conn);

	do {
		io_loop_run(dict->ioloop);
	} while (array_count(&dict->input_states) > 0);

	timeout_remove(&to);
	io_loop_set_current(dict->prev_ioloop);
	connection_switch_ioloop(&dict->conn.conn);
	io_loop_set_current(dict->ioloop);
	io_loop_destroy(&dict->ioloop);
	dict->prev_ioloop = NULL;
}

static int redis_input_get(struct redis_connection *conn, const char **error_r)
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
			*error_r = t_strdup_printf(
				"redis: Unexpected input (wanted $size): %s", line);
			return -1;
		}
		conn->bytes_left += 2; /* include trailing CRLF */
	}

	data = i_stream_get_data(conn->conn.input, &size);
	if (size > conn->bytes_left)
		size = conn->bytes_left;
	str_append_data(conn->last_reply, data, size);

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

static int
redis_conn_input_more(struct redis_connection *conn, const char **error_r)
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
		*error_r = t_strdup_printf(
			"redis: Unexpected input (expected nothing): %s", line);
		return -1;
	}
	state = states[0];
	if (state == REDIS_INPUT_STATE_GET)
		return redis_input_get(conn, error_r);

	line = i_stream_next_line(conn->conn.input);
	if (line == NULL)
		return 0;

	redis_input_state_remove(dict);
	switch (state) {
	case REDIS_INPUT_STATE_GET:
		i_unreached();
	case REDIS_INPUT_STATE_AUTH:
	case REDIS_INPUT_STATE_SELECT:
	case REDIS_INPUT_STATE_MULTI:
	case REDIS_INPUT_STATE_DISCARD:
		if (line[0] != '+')
			break;
		return 1;
	case REDIS_INPUT_STATE_EXEC:
		if (line[0] != '*' || str_to_uint(line+1, &num_replies) < 0)
			break;

		reply = array_first_modifiable(&dict->replies);
		i_assert(reply->reply_count > 0);
		if (reply->reply_count != num_replies) {
			*error_r = t_strdup_printf(
				"redis: EXEC expected %u replies, not %u",
				reply->reply_count, num_replies);
			return -1;
		}
		return 1;
	case REDIS_INPUT_STATE_EXEC_REPLY:
		if (*line != '+' && *line != ':')
			break;
		/* success, just ignore the actual reply */
		reply = array_first_modifiable(&dict->replies);
		i_assert(reply->reply_count > 0);
		if (--reply->reply_count == 0) {
			const struct dict_commit_result result = {
				DICT_COMMIT_RET_OK, NULL
			};
			redis_callback(dict, reply, &result);
			array_delete(&dict->replies, 0, 1);
			/* if we're running in a dict-ioloop, we're handling a
			   synchronous commit and need to stop now */
			if (array_count(&dict->replies) == 0 &&
			    conn->dict->ioloop != NULL)
				io_loop_stop(conn->dict->ioloop);
		}
		return 1;
	}
	str_truncate(dict->conn.last_reply, 0);
	str_append(dict->conn.last_reply, line);
	*error_r = t_strdup_printf("redis: Unexpected input (state=%d): %s", state, line);
	return -1;
}

static void redis_conn_input(struct connection *_conn)
{
	struct redis_connection *conn = (struct redis_connection *)_conn;
	const char *error = NULL;
	int ret;

	switch (i_stream_read(_conn->input)) {
	case 0:
		return;
	case -1:
		redis_disconnected(conn, i_stream_get_error(_conn->input));
		return;
	default:
		break;
	}

	while ((ret = redis_conn_input_more(conn, &error)) > 0) ;
	if (ret < 0) {
		i_assert(error != NULL);
		redis_disconnected(conn, error);
	}
}

static void redis_conn_connected(struct connection *_conn, bool success)
{
	struct redis_connection *conn = (struct redis_connection *)_conn;

	if (!success) {
		i_error("redis: connect(%s) failed: %m", _conn->name);
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
		const struct dict_settings *set,
		struct dict **dict_r, const char **error_r)
{
	struct redis_dict *dict;
	struct ip_addr ip;
	unsigned int secs;
	in_port_t port = REDIS_DEFAULT_PORT;
	const char *const *args, *unix_path = NULL;
	int ret = 0;

	if (redis_connections == NULL) {
		redis_connections =
			connection_list_init(&redis_conn_set,
					     &redis_conn_vfuncs);
	}

	dict = i_new(struct redis_dict, 1);
	if (net_addr2ip("127.0.0.1", &ip) < 0)
		i_unreached();
	dict->timeout_msecs = REDIS_DEFAULT_LOOKUP_TIMEOUT_MSECS;
	dict->key_prefix = i_strdup("");
	dict->password   = i_strdup("");

	args = t_strsplit(uri, ":");
	for (; *args != NULL; args++) {
		if (str_begins(*args, "path=")) {
			unix_path = *args + 5;
		} else if (str_begins(*args, "host=")) {
			if (net_addr2ip(*args+5, &ip) < 0) {
				*error_r = t_strdup_printf("Invalid IP: %s",
							   *args+5);
				ret = -1;
			}
		} else if (str_begins(*args, "port=")) {
			if (net_str2port(*args+5, &port) < 0) {
				*error_r = t_strdup_printf("Invalid port: %s",
							   *args+5);
				ret = -1;
			}
		} else if (str_begins(*args, "prefix=")) {
			i_free(dict->key_prefix);
			dict->key_prefix = i_strdup(*args + 7);
		} else if (str_begins(*args, "db=")) {
			if (str_to_uint(*args+3, &dict->db_id) < 0) {
				*error_r = t_strdup_printf(
					"Invalid db number: %s", *args+3);
				ret = -1;
			}
		} else if (str_begins(*args, "expire_secs=")) {
			const char *value = *args + 12;

			if (str_to_uint(value, &secs) < 0 || secs == 0) {
				*error_r = t_strdup_printf(
					"Invalid expire_secs: %s", value);
				ret = -1;
			}
			i_free(dict->expire_value);
			dict->expire_value = i_strdup(value);
		} else if (str_begins(*args, "timeout_msecs=")) {
			if (str_to_uint(*args+14, &dict->timeout_msecs) < 0) {
				*error_r = t_strdup_printf(
					"Invalid timeout_msecs: %s", *args+14);
				ret = -1;
			}
		} else if (str_begins(*args, "password=")) {
			i_free(dict->password);
			dict->password = i_strdup(*args + 9);
		} else {
			*error_r = t_strdup_printf("Unknown parameter: %s",
						   *args);
			ret = -1;
		}
	}
	if (ret < 0) {
		i_free(dict->password);
		i_free(dict->key_prefix);
		i_free(dict);
		return -1;
	}
	if (unix_path != NULL) {
		connection_init_client_unix(redis_connections, &dict->conn.conn,
					    unix_path);
	} else {
		connection_init_client_ip(redis_connections, &dict->conn.conn,
					  &ip, port);
	}
	dict->dict = *driver;
	dict->conn.last_reply = str_new(default_pool, 256);
	dict->conn.dict = dict;

	i_array_init(&dict->input_states, 4);
	i_array_init(&dict->replies, 4);
	if (strchr(set->username, DICT_USERNAME_SEPARATOR) == NULL)
		dict->username = i_strdup(set->username);
	else {
		/* escape the username */
		dict->username = i_strdup(redis_escape_username(set->username));
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
	i_free(dict->expire_value);
	i_free(dict->key_prefix);
	i_free(dict->password);
	i_free(dict->username);
	i_free(dict);

	if (redis_connections->connections == NULL)
		connection_list_deinit(&redis_connections);
}

static void redis_dict_lookup_timeout(struct redis_dict *dict)
{
	const char *reason = t_strdup_printf(
		"redis: Lookup timed out in %u.%03u secs",
		dict->timeout_msecs/1000, dict->timeout_msecs%1000);
	redis_disconnected(&dict->conn, reason);
}

static const char *
redis_dict_get_full_key(struct redis_dict *dict, const char *key)
{
	if (str_begins(key, DICT_PATH_SHARED))
		key += strlen(DICT_PATH_SHARED);
	else if (str_begins(key, DICT_PATH_PRIVATE)) {
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

static void redis_dict_auth(struct redis_dict *dict)
{
	const char *cmd;

	if (*dict->password == '\0')
		return;

	cmd = t_strdup_printf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n",
	                      (int)strlen(dict->password), dict->password);
	o_stream_nsend_str(dict->conn.conn.output, cmd);
	redis_input_state_add(dict, REDIS_INPUT_STATE_AUTH);
}

static void redis_dict_select_db(struct redis_dict *dict)
{
	const char *cmd, *db_str;

	if (dict->db_id_set)
		return;
	dict->db_id_set = TRUE;
	if (dict->db_id == 0) {
		/* 0 is the default */
		return;
	}
	db_str = dec2str(dict->db_id);
	cmd = t_strdup_printf("*2\r\n$6\r\nSELECT\r\n$%d\r\n%s\r\n",
			      (int)strlen(db_str), db_str);
	o_stream_nsend_str(dict->conn.conn.output, cmd);
	redis_input_state_add(dict, REDIS_INPUT_STATE_SELECT);
}

static int redis_dict_lookup(struct dict *_dict, pool_t pool, const char *key,
			     const char **value_r, const char **error_r)
{
	struct redis_dict *dict = (struct redis_dict *)_dict;
	struct timeout *to;
	const char *cmd;

	key = redis_dict_get_full_key(dict, key);

	dict->conn.value_received = FALSE;
	dict->conn.value_not_found = FALSE;

	i_assert(dict->ioloop == NULL);

	dict->prev_ioloop = current_ioloop;
	dict->ioloop = io_loop_create();
	connection_switch_ioloop(&dict->conn.conn);

	if (dict->conn.conn.fd_in == -1 &&
	    connection_client_connect(&dict->conn.conn) < 0) {
		i_error("redis: Couldn't connect to %s", dict->conn.conn.name);
	} else {
		to = timeout_add(dict->timeout_msecs,
				 redis_dict_lookup_timeout, dict);
		if (!dict->connected) {
			/* wait for connection */
			io_loop_run(dict->ioloop);
			if (dict->connected)
				redis_dict_auth(dict);
		}

		if (dict->connected) {
			redis_dict_select_db(dict);
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

	io_loop_set_current(dict->prev_ioloop);
	connection_switch_ioloop(&dict->conn.conn);
	io_loop_set_current(dict->ioloop);
	io_loop_destroy(&dict->ioloop);
	dict->prev_ioloop = NULL;

	if (!dict->conn.value_received) {
		/* we failed in some way. make sure we disconnect since the
		   connection state isn't known anymore */
		*error_r = t_strdup_printf("redis: Communication failure (last reply: %s)",
					   str_c(dict->conn.last_reply));
		redis_disconnected(&dict->conn, *error_r);
		return -1;
	}
	if (dict->conn.value_not_found)
		return 0;

	*value_r = p_strdup(pool, str_c(dict->conn.last_reply));
	return 1;
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
		i_error("redis: Couldn't connect to %s",
			dict->conn.conn.name);
	} else if (!dict->connected) {
		/* wait for connection */
		redis_wait(dict);
		if (dict->connected)
			redis_dict_auth(dict);
	}
	if (dict->connected)
		redis_dict_select_db(dict);
	return &ctx->ctx;
}

static void
redis_transaction_commit(struct dict_transaction_context *_ctx, bool async,
			 dict_transaction_commit_callback_t *callback,
			 void *context)
{
	struct redis_dict_transaction_context *ctx =
		(struct redis_dict_transaction_context *)_ctx;
	struct redis_dict *dict = (struct redis_dict *)_ctx->dict;
	struct redis_dict_reply *reply;
	unsigned int i;
	struct dict_commit_result result = { .ret = DICT_COMMIT_RET_OK };

	i_assert(dict->transaction_open);
	dict->transaction_open = FALSE;

	if (ctx->error != NULL) {
		/* make sure we're disconnected */
		redis_disconnected(&dict->conn, ctx->error);
		result.ret = -1;
		result.error = ctx->error;
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
		if (async) {
			i_free(ctx);
			return;
		}
		redis_wait(dict);
	}
	callback(&result, context);
	i_free(ctx->error);
	i_free(ctx);
}

static void redis_transaction_rollback(struct dict_transaction_context *_ctx)
{
	struct redis_dict_transaction_context *ctx =
		(struct redis_dict_transaction_context *)_ctx;
	struct redis_dict *dict = (struct redis_dict *)_ctx->dict;
	struct redis_dict_reply *reply;

	i_assert(dict->transaction_open);
	dict->transaction_open = FALSE;

	if (ctx->error != NULL) {
		/* make sure we're disconnected */
		redis_disconnected(&dict->conn, ctx->error);
	} else if (_ctx->changed) {
		o_stream_nsend_str(dict->conn.conn.output,
				   "*1\r\n$7\r\nDISCARD\r\n");
		reply = array_append_space(&dict->replies);
		reply->reply_count = 1;
		redis_input_state_add(dict, REDIS_INPUT_STATE_DISCARD);
	}
	i_free(ctx->error);
	i_free(ctx);
}

static int redis_check_transaction(struct redis_dict_transaction_context *ctx)
{
	struct redis_dict *dict = (struct redis_dict *)ctx->ctx.dict;

	if (ctx->error != NULL)
		return -1;
	if (!dict->connected) {
		ctx->error = i_strdup("Disconnected during transaction");
		return -1;
	}
	if (ctx->ctx.changed)
		return 0;

	redis_input_state_add(dict, REDIS_INPUT_STATE_MULTI);
	if (o_stream_send_str(dict->conn.conn.output,
			      "*1\r\n$5\r\nMULTI\r\n") < 0) {
		ctx->error = i_strdup_printf("write() failed: %s",
			o_stream_get_error(dict->conn.conn.output));
		return -1;
	}
	return 0;
}

static void
redis_append_expire(struct redis_dict_transaction_context *ctx,
		    string_t *cmd, const char *key)
{
	struct redis_dict *dict = (struct redis_dict *)ctx->ctx.dict;

	if (dict->expire_value == NULL)
		return;

	str_printfa(cmd, "*3\r\n$6\r\nEXPIRE\r\n$%u\r\n%s\r\n$%u\r\n%s\r\n",
		    (unsigned int)strlen(key), key,
		    (unsigned int)strlen(dict->expire_value),
		    dict->expire_value);
	redis_input_state_add(dict, REDIS_INPUT_STATE_MULTI);
	ctx->cmd_count++;
}

static void redis_set(struct dict_transaction_context *_ctx,
		      const char *key, const char *value)
{
	struct redis_dict_transaction_context *ctx =
		(struct redis_dict_transaction_context *)_ctx;
	struct redis_dict *dict = (struct redis_dict *)_ctx->dict;
	string_t *cmd;

	if (redis_check_transaction(ctx) < 0)
		return;

	key = redis_dict_get_full_key(dict, key);
	cmd = t_str_new(128);
	str_printfa(cmd, "*3\r\n$3\r\nSET\r\n$%u\r\n%s\r\n$%u\r\n%s\r\n",
		    (unsigned int)strlen(key), key,
		    (unsigned int)strlen(value), value);
	redis_input_state_add(dict, REDIS_INPUT_STATE_MULTI);
	ctx->cmd_count++;
	redis_append_expire(ctx, cmd, key);
	if (o_stream_send(dict->conn.conn.output, str_data(cmd), str_len(cmd)) < 0) {
		ctx->error = i_strdup_printf("write() failed: %s",
			o_stream_get_error(dict->conn.conn.output));
	}
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
	if (o_stream_send_str(dict->conn.conn.output, cmd) < 0) {
		ctx->error = i_strdup_printf("write() failed: %s",
			o_stream_get_error(dict->conn.conn.output));
	}
	redis_input_state_add(dict, REDIS_INPUT_STATE_MULTI);
	ctx->cmd_count++;
}

static void redis_atomic_inc(struct dict_transaction_context *_ctx,
			     const char *key, long long diff)
{
	struct redis_dict_transaction_context *ctx =
		(struct redis_dict_transaction_context *)_ctx;
	struct redis_dict *dict = (struct redis_dict *)_ctx->dict;
	const char *diffstr;
	string_t *cmd;

	if (redis_check_transaction(ctx) < 0)
		return;

	key = redis_dict_get_full_key(dict, key);
	diffstr = t_strdup_printf("%lld", diff);
	cmd = t_str_new(128);
	str_printfa(cmd, "*3\r\n$6\r\nINCRBY\r\n$%u\r\n%s\r\n$%u\r\n%s\r\n",
		    (unsigned int)strlen(key), key,
		    (unsigned int)strlen(diffstr), diffstr);
	redis_input_state_add(dict, REDIS_INPUT_STATE_MULTI);
	ctx->cmd_count++;
	redis_append_expire(ctx, cmd, key);
	if (o_stream_send(dict->conn.conn.output, str_data(cmd), str_len(cmd)) < 0) {
		ctx->error = i_strdup_printf("write() failed: %s",
			o_stream_get_error(dict->conn.conn.output));
	}
}

struct dict dict_driver_redis = {
	.name = "redis",
	{
		.init = redis_dict_init,
		.deinit = redis_dict_deinit,
		.lookup = redis_dict_lookup,
		.transaction_init = redis_transaction_init,
		.transaction_commit = redis_transaction_commit,
		.transaction_rollback = redis_transaction_rollback,
		.set = redis_set,
		.unset = redis_unset,
		.atomic_inc = redis_atomic_inc,
	}
};
