/* Copyright (c) 2008-2013 Dovecot authors, see the included COPYING memcached_ascii */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "connection.h"
#include "dict-transaction-memory.h"
#include "dict-private.h"

#define MEMCACHED_DEFAULT_PORT 11211
#define MEMCACHED_DEFAULT_LOOKUP_TIMEOUT_MSECS (1000*30)
#define DICT_USERNAME_SEPARATOR '/'

enum memcached_ascii_input_state {
	/* GET: expecting VALUE or END */
	MEMCACHED_INPUT_STATE_GET,
	/* SET/(APPEND+ADD): expecting STORED / NOT_STORED */
	MEMCACHED_INPUT_STATE_STORED,
	/* DELETE: expecting DELETED */
	MEMCACHED_INPUT_STATE_DELETED,
	/* (INCR+ADD)/DECR: expecting number / NOT_FOUND / STORED / NOT_STORED */
	MEMCACHED_INPUT_STATE_INCRDECR
};

struct memcached_ascii_connection {
	struct connection conn;
	struct memcached_ascii_dict *dict;

	string_t *reply_str;
	unsigned int reply_bytes_left;
	bool value_received;
	bool value_waiting_end;
};

struct memcached_ascii_dict_reply {
	unsigned int reply_count;
	dict_transaction_commit_callback_t *callback;
	void *context;
};

struct dict_memcached_ascii_commit_ctx {
	struct memcached_ascii_dict *dict;
	struct dict_transaction_memory_context *memctx;
	string_t *str;

	dict_transaction_commit_callback_t *callback;
	void *context;
};

struct memcached_ascii_dict {
	struct dict dict;
	struct ip_addr ip;
	char *username, *key_prefix;
	unsigned int port;
	unsigned int timeout_msecs;

	struct ioloop *ioloop;
	struct timeout *to;
	struct memcached_ascii_connection conn;

	ARRAY(enum memcached_ascii_input_state) input_states;
	ARRAY(struct memcached_ascii_dict_reply) replies;
};

static struct connection_list *memcached_ascii_connections;

static void memcached_ascii_conn_destroy(struct connection *_conn)
{
	struct memcached_ascii_connection *conn =
		(struct memcached_ascii_connection *)_conn;
	const struct memcached_ascii_dict_reply *reply;

	connection_disconnect(_conn);
	if (conn->dict->ioloop != NULL)
		io_loop_stop(conn->dict->ioloop);

	array_foreach(&conn->dict->replies, reply) {
		if (reply->callback != NULL)
			reply->callback(-1, reply->context);
	}
	array_clear(&conn->dict->replies);
	array_clear(&conn->dict->input_states);
	conn->reply_bytes_left = 0;
}

static bool memcached_ascii_input_value(struct memcached_ascii_connection *conn)
{
	const unsigned char *data;
	size_t size;

	data = i_stream_get_data(conn->conn.input, &size);
	if (size > conn->reply_bytes_left)
		size = conn->reply_bytes_left;
	conn->reply_bytes_left -= size;

	str_append_n(conn->reply_str, data, size);
	i_stream_skip(conn->conn.input, size);
	if (conn->reply_bytes_left > 0)
		return FALSE;

	/* finished. drop the trailing CRLF */
	str_truncate(conn->reply_str, str_len(conn->reply_str)-2);
	conn->value_received = TRUE;
	return TRUE;
}

static int memcached_ascii_input_reply_read(struct memcached_ascii_dict *dict)
{
	struct memcached_ascii_connection *conn = &dict->conn;
	const enum memcached_ascii_input_state *states;
	const char *line, *p;
	unsigned int count;
	long long num;

	if (conn->reply_bytes_left > 0) {
		/* continue reading bulk reply */
		if (!memcached_ascii_input_value(conn))
			return 0;
		conn->value_waiting_end = TRUE;
	} else if (conn->value_waiting_end) {
		conn->value_waiting_end = FALSE;
	} else {
		str_truncate(conn->reply_str, 0);
		conn->value_received = FALSE;
	}

	line = i_stream_next_line(conn->conn.input);
	if (line == NULL)
		return 0;

	states = array_get(&dict->input_states, &count);
	if (count == 0) {
		i_error("memcached_ascii: Unexpected input (expected nothing): %s",
			line);
		return -1;
	}
	switch (states[0]) {
	case MEMCACHED_INPUT_STATE_GET:
		/* VALUE <key> <flags> <bytes>
		   END */
		if (strncmp(line, "VALUE ", 6) == 0) {
			p = strrchr(line, ' ');
			if (str_to_uint(p+1, &conn->reply_bytes_left) < 0)
				break;
			conn->reply_bytes_left += 2; /* CRLF */
			return memcached_ascii_input_reply_read(dict);
		} else if (strcmp(line, "END") == 0)
			return 1;
		break;
	case MEMCACHED_INPUT_STATE_STORED:
		if (strcmp(line, "STORED") != 0 &&
		    strcmp(line, "NOT_STORED") != 0)
			break;
		return 1;
	case MEMCACHED_INPUT_STATE_DELETED:
		if (strcmp(line, "DELETED") != 0)
			break;
		return 1;
	case MEMCACHED_INPUT_STATE_INCRDECR:
		if (strcmp(line, "NOT_FOUND") != 0 &&
		    strcmp(line, "STORED") != 0 &&
		    strcmp(line, "NOT_STORED") != 0 &&
		    str_to_llong(line, &num) < 0)
			break;
		return 1;
	}
	i_error("memcached_ascii: Unexpected input (state=%d): %s",
		states[0], line);
	return -1;
}

static int memcached_ascii_input_reply(struct memcached_ascii_dict *dict)
{
	struct memcached_ascii_dict_reply *replies;
	unsigned int count;
	int ret;

	if ((ret = memcached_ascii_input_reply_read(dict)) <= 0)
		return ret;
	/* finished a reply */
	array_delete(&dict->input_states, 0, 1);

	replies = array_get_modifiable(&dict->replies, &count);
	i_assert(count > 0);
	i_assert(replies[0].reply_count > 0);
	if (--replies[0].reply_count == 0) {
		if (replies[0].callback != NULL)
			replies[0].callback(1, replies[0].context);
		array_delete(&dict->replies, 0, 1);
	}
	return 1;
}

static void memcached_ascii_conn_input(struct connection *_conn)
{
	struct memcached_ascii_connection *conn =
		(struct memcached_ascii_connection *)_conn;
	int ret;

	switch (i_stream_read(_conn->input)) {
	case 0:
		return;
	case -1:
		memcached_ascii_conn_destroy(_conn);
		return;
	default:
		break;
	}

	while ((ret = memcached_ascii_input_reply(conn->dict)) > 0) ;
	if (ret < 0)
		memcached_ascii_conn_destroy(_conn);
	io_loop_stop(conn->dict->ioloop);
}

static int memcached_ascii_input_wait(struct memcached_ascii_dict *dict)
{
	struct ioloop *old_ioloop = current_ioloop;

	current_ioloop = dict->ioloop;
	if (dict->to != NULL)
		dict->to = io_loop_move_timeout(&dict->to);
	connection_switch_ioloop(&dict->conn.conn);
	io_loop_run(dict->ioloop);

	current_ioloop = old_ioloop;
	if (dict->to != NULL)
		dict->to = io_loop_move_timeout(&dict->to);
	connection_switch_ioloop(&dict->conn.conn);

	return dict->conn.conn.fd_in == -1 ? -1 : 0;
}

static void memcached_ascii_input_timeout(struct memcached_ascii_dict *dict)
{
	i_error("memcached_ascii: Request timed out in %u.%03u secs",
		dict->timeout_msecs/1000, dict->timeout_msecs%1000);
	memcached_ascii_conn_destroy(&dict->conn.conn);
}

static int memcached_ascii_wait_replies(struct memcached_ascii_dict *dict)
{
	int ret = 0;

	dict->to = timeout_add(dict->timeout_msecs,
			       memcached_ascii_input_timeout, dict);
	while (array_count(&dict->input_states) > 0) {
		i_assert(array_count(&dict->replies) > 0);

		if ((ret = memcached_ascii_input_reply(dict)) != 0) {
			if (ret < 0)
				memcached_ascii_conn_destroy(&dict->conn.conn);
			break;
		}
		ret = memcached_ascii_input_wait(dict);
		if (ret != 0)
			break;
	}

	timeout_remove(&dict->to);
	return ret < 0 ? -1 : 0;
}

static int memcached_ascii_wait(struct memcached_ascii_dict *dict)
{
	int ret;

	i_assert(dict->conn.conn.fd_in != -1);

	if (dict->conn.conn.input == NULL) {
		/* waiting for connection to finish */
		dict->to = timeout_add(dict->timeout_msecs,
				       memcached_ascii_input_timeout, dict);
		ret = memcached_ascii_input_wait(dict);
		timeout_remove(&dict->to);
		if (ret < 0)
			return -1;
	}
	if (memcached_ascii_wait_replies(dict) < 0)
		return -1;
	i_assert(array_count(&dict->input_states) == 0);
	i_assert(array_count(&dict->replies) == 0);
	return 0;
}

static void
memcached_ascii_conn_connected(struct connection *_conn, bool success)
{
	struct memcached_ascii_connection *conn = (struct memcached_ascii_connection *)_conn;

	if (!success) {
		i_error("memcached_ascii: connect(%s, %u) failed: %m",
			net_ip2addr(&conn->dict->ip), conn->dict->port);
	}
	if (conn->dict->ioloop != NULL)
		io_loop_stop(conn->dict->ioloop);
}

static const struct connection_settings memcached_ascii_conn_set = {
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.client = TRUE
};

static const struct connection_vfuncs memcached_ascii_conn_vfuncs = {
	.destroy = memcached_ascii_conn_destroy,
	.input = memcached_ascii_conn_input,
	.client_connected = memcached_ascii_conn_connected
};

static const char *memcached_ascii_escape_username(const char *username)
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
memcached_ascii_dict_init(struct dict *driver, const char *uri,
			  enum dict_data_type value_type ATTR_UNUSED,
			  const char *username,
			  const char *base_dir ATTR_UNUSED,
			  struct dict **dict_r, const char **error_r)
{
	struct memcached_ascii_dict *dict;
	const char *const *args;
	struct ioloop *old_ioloop = current_ioloop;
	int ret = 0;

	if (memcached_ascii_connections == NULL) {
		memcached_ascii_connections =
			connection_list_init(&memcached_ascii_conn_set,
					     &memcached_ascii_conn_vfuncs);
	}

	dict = i_new(struct memcached_ascii_dict, 1);
	if (net_addr2ip("127.0.0.1", &dict->ip) < 0)
		i_unreached();
	dict->port = MEMCACHED_DEFAULT_PORT;
	dict->timeout_msecs = MEMCACHED_DEFAULT_LOOKUP_TIMEOUT_MSECS;
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

	connection_init_client_ip(memcached_ascii_connections, &dict->conn.conn,
				  &dict->ip, dict->port);
	dict->dict = *driver;
	dict->conn.reply_str = str_new(default_pool, 256);
	dict->conn.dict = dict;

	if (strchr(username, DICT_USERNAME_SEPARATOR) == NULL)
		dict->username = i_strdup(username);
	else {
		/* escape the username */
		dict->username = i_strdup(memcached_ascii_escape_username(username));
	}
	i_array_init(&dict->input_states, 4);
	i_array_init(&dict->replies, 4);

	dict->ioloop = io_loop_create();
	current_ioloop = old_ioloop;
	*dict_r = &dict->dict;
	return 0;
}

static void memcached_ascii_dict_deinit(struct dict *_dict)
{
	struct memcached_ascii_dict *dict =
		(struct memcached_ascii_dict *)_dict;
	struct ioloop *old_ioloop = current_ioloop;

	if (array_count(&dict->input_states) > 0)
		(void)memcached_ascii_wait(dict);
	connection_deinit(&dict->conn.conn);

	current_ioloop = dict->ioloop;
	io_loop_destroy(&dict->ioloop);
	current_ioloop = old_ioloop;

	str_free(&dict->conn.reply_str);
	array_free(&dict->replies);
	array_free(&dict->input_states);
	i_free(dict->key_prefix);
	i_free(dict->username);
	i_free(dict);

	if (memcached_ascii_connections->connections == NULL)
		connection_list_deinit(&memcached_ascii_connections);
}

static int memcached_ascii_connect(struct memcached_ascii_dict *dict)
{
	if (dict->conn.conn.input != NULL)
		return 0;

	if (dict->conn.conn.fd_in == -1) {
		if (connection_client_connect(&dict->conn.conn) < 0) {
			i_error("memcached_ascii: Couldn't connect to %s:%u",
				net_ip2addr(&dict->ip), dict->port);
			return -1;
		}
	}
	return memcached_ascii_wait(dict);
}

static const char *
memcached_ascii_dict_get_full_key(struct memcached_ascii_dict *dict,
				  const char *key)
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
memcached_ascii_dict_lookup_real(struct memcached_ascii_dict *dict, pool_t pool,
				 const char *key, const char **value_r)
{
	enum memcached_ascii_input_state state = MEMCACHED_INPUT_STATE_GET;
	struct memcached_ascii_dict_reply *reply;

	if (memcached_ascii_connect(dict) < 0)
		return -1;

	key = memcached_ascii_dict_get_full_key(dict, key);
	o_stream_nsend_str(dict->conn.conn.output,
			   t_strdup_printf("get %s\r\n", key));
	array_append(&dict->input_states, &state, 1);

	reply = array_append_space(&dict->replies);
	reply->reply_count = 1;

	if (memcached_ascii_wait(dict) < 0)
		return -1;

	*value_r = p_strdup(pool, str_c(dict->conn.reply_str));
	return dict->conn.value_received ? 1 : 0;
}

static int
memcached_ascii_dict_lookup(struct dict *_dict, pool_t pool,
			    const char *key, const char **value_r)
{
	struct memcached_ascii_dict *dict = (struct memcached_ascii_dict *)_dict;
	int ret;

	if (pool->datastack_pool)
		ret = memcached_ascii_dict_lookup_real(dict, pool, key, value_r);
	else T_BEGIN {
		ret = memcached_ascii_dict_lookup_real(dict, pool, key, value_r);
	} T_END;
	return ret;
}

static struct dict_transaction_context *
memcached_ascii_transaction_init(struct dict *_dict)
{
	struct dict_transaction_memory_context *ctx;
	pool_t pool;

	pool = pool_alloconly_create("file dict transaction", 2048);
	ctx = p_new(pool, struct dict_transaction_memory_context, 1);
	dict_transaction_memory_init(ctx, _dict, pool);
	return &ctx->ctx;
}

static void
memcached_send_change(struct dict_memcached_ascii_commit_ctx *ctx,
		      const struct dict_transaction_memory_change *change)
{
	enum memcached_ascii_input_state state;
	const char *key, *value;

	key = memcached_ascii_dict_get_full_key(ctx->dict, change->key);

	str_truncate(ctx->str, 0);
	switch (change->type) {
	case DICT_CHANGE_TYPE_SET:
		state = MEMCACHED_INPUT_STATE_STORED;
		str_printfa(ctx->str, "set %s 0 0 %"PRIuSIZE_T"\r\n%s\r\n",
			    key, strlen(change->value.str), change->value.str);
		break;
	case DICT_CHANGE_TYPE_UNSET:
		state = MEMCACHED_INPUT_STATE_DELETED;
		str_printfa(ctx->str, "delete %s\r\n", key);
		break;
	case DICT_CHANGE_TYPE_APPEND:
		state = MEMCACHED_INPUT_STATE_STORED;
		str_printfa(ctx->str, "append %s 0 0 %"PRIuSIZE_T"\r\n%s\r\n",
			    key, strlen(change->value.str), change->value.str);
		array_append(&ctx->dict->input_states, &state, 1);
		/* we'd preferably want an append that always works, but
		   this kludge works for that too.. */
		str_printfa(ctx->str, "add %s 0 0 %"PRIuSIZE_T"\r\n%s\r\n",
			    key, strlen(change->value.str), change->value.str);
		break;
	case DICT_CHANGE_TYPE_INC:
		state = MEMCACHED_INPUT_STATE_INCRDECR;
		if (change->value.diff > 0) {
			str_printfa(ctx->str, "incr %s %lld\r\n",
				    key, change->value.diff);
			array_append(&ctx->dict->input_states, &state, 1);
			/* same kludge as with append */
			value = t_strdup_printf("%lld", change->value.diff);
			str_printfa(ctx->str, "add %s 0 0 %u\r\n%s\r\n",
				    key, (unsigned int)strlen(value), value);
		} else {
			str_printfa(ctx->str, "decr %s %lld\r\n",
				    key, -change->value.diff);
		}
		break;
	}
	array_append(&ctx->dict->input_states, &state, 1);
	o_stream_nsend(ctx->dict->conn.conn.output,
		       str_data(ctx->str), str_len(ctx->str));
}

static int
memcached_ascii_transaction_send(struct dict_memcached_ascii_commit_ctx *ctx)
{
	struct memcached_ascii_dict *dict = ctx->dict;
	struct memcached_ascii_dict_reply *reply;
	const struct dict_transaction_memory_change *changes;
	unsigned int i, count, old_state_count;

	if (memcached_ascii_connect(dict) < 0)
		return -1;

	old_state_count = array_count(&dict->input_states);
	changes = array_get(&ctx->memctx->changes, &count);
	i_assert(count > 0);

	o_stream_cork(dict->conn.conn.output);
	for (i = 0; i < count; i++) T_BEGIN {
		memcached_send_change(ctx, &changes[i]);
	} T_END;
	o_stream_uncork(dict->conn.conn.output);

	reply = array_append_space(&dict->replies);
	reply->callback = ctx->callback;
	reply->context = ctx->context;
	reply->reply_count = array_count(&dict->input_states) - old_state_count;
	return 1;
}

static int
memcached_ascii_transaction_commit(struct dict_transaction_context *_ctx,
				   bool async,
				   dict_transaction_commit_callback_t *callback,
				   void *context)
{
	struct dict_transaction_memory_context *ctx =
		(struct dict_transaction_memory_context *)_ctx;
	struct memcached_ascii_dict *dict =
		(struct memcached_ascii_dict *)_ctx->dict;
	struct dict_memcached_ascii_commit_ctx commit_ctx;
	int ret = 1;

	if (_ctx->changed) {
		memset(&commit_ctx, 0, sizeof(commit_ctx));
		commit_ctx.dict = dict;
		commit_ctx.memctx = ctx;
		commit_ctx.callback = callback;
		commit_ctx.context = context;
		commit_ctx.str = str_new(default_pool, 128);

		ret = memcached_ascii_transaction_send(&commit_ctx);
		if (!async && ret >= 0) {
			if (memcached_ascii_wait(dict) < 0)
				ret = -1;
		}
		str_free(&commit_ctx.str);
	}
	if (callback != NULL)
		callback(ret, context);
	pool_unref(&ctx->pool);
	return ret;
}

struct dict dict_driver_memcached_ascii = {
	.name = "memcached_ascii",
	{
		memcached_ascii_dict_init,
		memcached_ascii_dict_deinit,
		NULL,
		memcached_ascii_dict_lookup,
		NULL,
		NULL,
		NULL,
		memcached_ascii_transaction_init,
		memcached_ascii_transaction_commit,
		dict_transaction_memory_rollback,
		dict_transaction_memory_set,
		dict_transaction_memory_unset,
		dict_transaction_memory_append,
		dict_transaction_memory_atomic_inc
	}
};
