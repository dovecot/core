/* Copyright (c) 2005-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "dict-private.h"
#include "dict-client.h"

#include <unistd.h>
#include <fcntl.h>

struct client_dict {
	struct dict dict;

	pool_t pool;
	int fd;
	const char *uri;
	const char *username;
	const char *path;
	enum dict_data_type value_type;

	time_t last_connect_try;
	struct istream *input;
	struct ostream *output;

	unsigned int connect_counter;
	unsigned int transaction_id_counter;

	unsigned int in_iteration:1;
	unsigned int handshaked:1;
};

struct client_dict_iterate_context {
	struct dict_iterate_context ctx;

	pool_t pool;
	bool failed;
};

struct client_dict_transaction_context {
	struct dict_transaction_context ctx;

	unsigned int id;
	unsigned int connect_counter;

	unsigned int failed:1;
	unsigned int sent_begin:1;
};

static int client_dict_connect(struct client_dict *dict);
static void client_dict_disconnect(struct client_dict *dict);

const char *dict_client_escape(const char *src)
{
	const char *p;
	string_t *dest;

	/* first do a quick lookup to see if there's anything to escape.
	   probably not. */
	for (p = src; *p != '\0'; p++) {
		if (*p == '\t' || *p == '\n' || *p == '\001')
			break;
	}

	if (*p == '\0')
		return src;

	dest = t_str_new(256);
	str_append_n(dest, src, p - src);

	for (; *p != '\0'; p++) {
		switch (*p) {
		case '\t':
			str_append_c(dest, '\001');
			str_append_c(dest, 't');
			break;
		case '\n':
			str_append_c(dest, '\001');
			str_append_c(dest, 'n');
			break;
		case '\001':
			str_append_c(dest, '\001');
			str_append_c(dest, '1');
			break;
		default:
			str_append_c(dest, *p);
			break;
		}
	}
	return str_c(dest);
}

const char *dict_client_unescape(const char *src)
{
	const char *p;
	string_t *dest;

	/* first do a quick lookup to see if there's anything to unescape.
	   probably not. */
	for (p = src; *p != '\0'; p++) {
		if (*p == '\001')
			break;
	}

	if (*p == '\0')
		return src;

	dest = t_str_new(256);
	str_append_n(dest, src, p - src);
	for (; *p != '\0'; p++) {
		if (*p != '\001')
			str_append_c(dest, *p);
		else if (p[1] != '\0') {
			p++;
			switch (*p) {
			case '1':
				str_append_c(dest, '\001');
				break;
			case 't':
				str_append_c(dest, '\t');
				break;
			case 'n':
				str_append_c(dest, '\n');
				break;
			}
		}
	}
	return str_c(dest);
}

static int client_dict_send_query(struct client_dict *dict, const char *query)
{
	if (dict->output == NULL) {
		/* not connected currently */
		if (client_dict_connect(dict) < 0)
			return -1;
	}

	if (o_stream_send_str(dict->output, query) < 0 ||
	    o_stream_flush(dict->output) < 0) {
		/* Send failed */
		if (!dict->handshaked) {
			/* we're trying to send hello, don't try to reconnect */
			return -1;
		}

		/* Reconnect and try again. */
		client_dict_disconnect(dict);
		if (client_dict_connect(dict) < 0)
			return -1;

		if (o_stream_send_str(dict->output, query) < 0 ||
		    o_stream_flush(dict->output) < 0) {
			i_error("write(%s) failed: %m", dict->path);
			return -1;
		}
	}
	return 0;
}

static int
client_dict_transaction_send_begin(struct client_dict_transaction_context *ctx)
{
	struct client_dict *dict = (struct client_dict *)ctx->ctx.dict;

	if (ctx->failed)
		return -1;

	T_FRAME(
		const char *query;

		query = t_strdup_printf("%c%u\n", DICT_PROTOCOL_CMD_BEGIN,
					ctx->id);
		if (client_dict_send_query(dict, query) < 0)
			ctx->failed = TRUE;
		else
			ctx->connect_counter = dict->connect_counter;
	);

	return ctx->failed ? -1 : 0;
}

static int
client_dict_send_transaction_query(struct client_dict_transaction_context *ctx,
				   const char *query)
{
	struct client_dict *dict = (struct client_dict *)ctx->ctx.dict;

	if (!ctx->sent_begin) {
		if (client_dict_transaction_send_begin(ctx) < 0)
			return -1;
		ctx->sent_begin = TRUE;
	}

	if (ctx->connect_counter != dict->connect_counter || ctx->failed)
		return -1;

	if (dict->output == NULL) {
		/* not connected, this'll fail */
		return -1;
	}

	if (o_stream_send_str(dict->output, query) < 0 ||
	    o_stream_flush(dict->output) < 0) {
		/* Send failed. Our transactions have died, so don't even try
		   to re-send the command */
		ctx->failed = TRUE;
		client_dict_disconnect(dict);
		return -1;
	}
	return 0;
}

static char *client_dict_read_line(struct client_dict *dict)
{
	char *line;
	int ret;

	line = i_stream_next_line(dict->input);
	if (line != NULL)
		return line;

	while ((ret = i_stream_read(dict->input)) > 0) {
		line = i_stream_next_line(dict->input);
		if (line != NULL)
			return line;
	}
	i_assert(ret < 0);

	if (ret == -2)
		i_error("read(%s) returned too much data", dict->path);
	else
		i_error("read(%s) failed: %m", dict->path);
	return NULL;
}

static int client_dict_connect(struct client_dict *dict)
{
	const char *query;

	i_assert(dict->fd == -1);

	if (dict->last_connect_try == ioloop_time) {
		/* Try again later */
		return -1;
	}
	dict->last_connect_try = ioloop_time;

	dict->fd = net_connect_unix(dict->path);
	if (dict->fd == -1) {
		i_error("net_connect_unix(%s) failed: %m", dict->path);
		return -1;
	}

	/* Dictionary lookups are blocking */
	net_set_nonblock(dict->fd, FALSE);

	dict->input = i_stream_create_fd(dict->fd, (size_t)-1, FALSE);
	dict->output = o_stream_create_fd(dict->fd, 4096, FALSE);
	dict->transaction_id_counter = 0;

	query = t_strdup_printf("%c%u\t%u\t%d\t%s\t%s\n",
				DICT_PROTOCOL_CMD_HELLO,
				DICT_CLIENT_PROTOCOL_MAJOR_VERSION,
				DICT_CLIENT_PROTOCOL_MINOR_VERSION,
				dict->value_type, dict->username, dict->uri);
	if (client_dict_send_query(dict, query) < 0) {
		client_dict_disconnect(dict);
		return -1;
	}

	dict->handshaked = TRUE;
	return 0;
}

static void client_dict_disconnect(struct client_dict *dict)
{
	dict->connect_counter++;
	dict->handshaked = FALSE;

	if (dict->input != NULL)
		i_stream_destroy(&dict->input);
	if (dict->output != NULL)
		o_stream_destroy(&dict->output);

	if (dict->fd != -1) {
		if (close(dict->fd) < 0)
			i_error("close(%s) failed: %m", dict->path);
		dict->fd = -1;
	}
}

static struct dict *
client_dict_init(struct dict *driver, const char *uri,
		 enum dict_data_type value_type, const char *username)
{
	struct client_dict *dict;
	const char *dest_uri;
	pool_t pool;

	/* uri = [<path>] ":" <uri> */
	dest_uri = strchr(uri, ':');
	if (dest_uri == NULL) {
		i_error("dict-client: Invalid URI: %s", uri);
		return NULL;
	}

	pool = pool_alloconly_create("client dict", 1024);
	dict = p_new(pool, struct client_dict, 1);
	dict->pool = pool;
	dict->dict = *driver;
	dict->value_type = value_type;
	dict->username = p_strdup(pool, username);

	dict->fd = -1;

	if (*uri != ':') {
		/* path given */
		dict->path = p_strdup_until(pool, uri, dest_uri);
	} else {
		dict->path = DEFAULT_DICT_SERVER_SOCKET_PATH;
	}
	dict->uri = p_strdup(pool, dest_uri + 1);
	return &dict->dict;
}

static void client_dict_deinit(struct dict *_dict)
{
	struct client_dict *dict = (struct client_dict *)_dict;

        client_dict_disconnect(dict);
	pool_unref(&dict->pool);
}

static int client_dict_lookup(struct dict *_dict, pool_t pool,
			      const char *key, const char **value_r)
{
	struct client_dict *dict = (struct client_dict *)_dict;
	const char *line;
	int ret;

	T_FRAME(
		const char *query;

		query = t_strdup_printf("%c%s\n", DICT_PROTOCOL_CMD_LOOKUP,
					dict_client_escape(key));
		ret = client_dict_send_query(dict, query);
	);
	if (ret < 0)
		return -1;

	/* read reply */
	line = client_dict_read_line(dict);
	if (line == NULL)
		return -1;

	if (*line == DICT_PROTOCOL_REPLY_OK) {
		*value_r = p_strdup(pool, dict_client_unescape(line + 1));
		return 1;
	} else {
		*value_r = NULL;
		return *line == DICT_PROTOCOL_REPLY_NOTFOUND ? 0 : -1;
	}
}

static struct dict_iterate_context *
client_dict_iterate_init(struct dict *_dict, const char *path, 
			 enum dict_iterate_flags flags)
{
	struct client_dict *dict = (struct client_dict *)_dict;
        struct client_dict_iterate_context *ctx;

	if (dict->in_iteration)
		i_panic("dict-client: Only one iteration supported");
	dict->in_iteration = TRUE;

	ctx = i_new(struct client_dict_iterate_context, 1);
	ctx->ctx.dict = _dict;
	ctx->pool = pool_alloconly_create("client dict iteration", 512);

	T_FRAME(
		const char *query;

		query = t_strdup_printf("%c%d\t%s\n", DICT_PROTOCOL_CMD_ITERATE,
					flags, dict_client_escape(path));
		if (client_dict_send_query(dict, query) < 0)
			ctx->failed = TRUE;
	);
	return &ctx->ctx;
}

static int client_dict_iterate(struct dict_iterate_context *_ctx,
			       const char **key_r, const char **value_r)
{
	struct client_dict_iterate_context *ctx =
		(struct client_dict_iterate_context *)_ctx;
	struct client_dict *dict = (struct client_dict *)_ctx->dict;
	char *line, *value;

	if (ctx->failed)
		return -1;

	/* read next reply */
	line = client_dict_read_line(dict);
	if (line == NULL)
		return -1;

	if (*line == '\0') {
		/* end of iteration */
		return 0;
	}

	/* line contains key \t value */
	p_clear(ctx->pool);

	value = strchr(line, '\t');
	if (value == NULL) {
		/* broken protocol */
		i_error("dict client (%s) sent broken reply", dict->path);
		return -1;
	}
	*value++ = '\0';

	*key_r = p_strdup(ctx->pool, dict_client_unescape(line));
	*value_r = p_strdup(ctx->pool, dict_client_unescape(value));
	return 1;
}

static void client_dict_iterate_deinit(struct dict_iterate_context *_ctx)
{
	struct client_dict *dict = (struct client_dict *)_ctx->dict;
	struct client_dict_iterate_context *ctx =
		(struct client_dict_iterate_context *)_ctx;

	pool_unref(&ctx->pool);
	i_free(ctx);
	dict->in_iteration = TRUE;
}

static struct dict_transaction_context *
client_dict_transaction_init(struct dict *_dict)
{
	struct client_dict *dict = (struct client_dict *)_dict;
	struct client_dict_transaction_context *ctx;

	ctx = i_new(struct client_dict_transaction_context, 1);
	ctx->ctx.dict = _dict;
	ctx->id = ++dict->transaction_id_counter;

	return &ctx->ctx;
}

static int client_dict_transaction_commit(struct dict_transaction_context *_ctx)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;
	struct client_dict *dict = (struct client_dict *)_ctx->dict;
	int ret = ctx->failed ? -1 : 0;

	if (ctx->sent_begin) T_FRAME_BEGIN {
		const char *query, *line;

		query = t_strdup_printf("%c%u\n", !ctx->failed ?
					DICT_PROTOCOL_CMD_COMMIT :
					DICT_PROTOCOL_CMD_ROLLBACK, ctx->id);
		if (client_dict_send_transaction_query(ctx, query) < 0)
			ret = -1;
		else if (ret == 0) {
			/* read reply */
			line = client_dict_read_line(dict);
			if (line == NULL || *line != DICT_PROTOCOL_REPLY_OK)
				ret = -1;
		}
	} T_FRAME_END;

	i_free(ctx);
	return ret;
}

static void
client_dict_transaction_rollback(struct dict_transaction_context *_ctx)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;

	if (ctx->sent_begin) T_FRAME_BEGIN {
		const char *query;

		query = t_strdup_printf("%c%u\n", DICT_PROTOCOL_CMD_ROLLBACK,
					ctx->id);
		(void)client_dict_send_transaction_query(ctx, query);
	} T_FRAME_END;

	i_free(ctx);
}

static void client_dict_set(struct dict_transaction_context *_ctx,
			    const char *key, const char *value)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;

	T_FRAME(
		const char *query;

		query = t_strdup_printf("%c%u\t%s\t%s\n",
					DICT_PROTOCOL_CMD_SET, ctx->id,
					dict_client_escape(key),
					dict_client_escape(value));
		(void)client_dict_send_transaction_query(ctx, query);
	);
}

static void client_dict_unset(struct dict_transaction_context *_ctx,
			      const char *key)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;

	T_FRAME(
		const char *query;

		query = t_strdup_printf("%c%u\t%s\n",
					DICT_PROTOCOL_CMD_UNSET, ctx->id,
					dict_client_escape(key));
		(void)client_dict_send_transaction_query(ctx, query);
	);
}

static void client_dict_atomic_inc(struct dict_transaction_context *_ctx,
				   const char *key, long long diff)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;

	T_FRAME(
		const char *query;
		query = t_strdup_printf("%c%u\t%s\t%lld\n",
					DICT_PROTOCOL_CMD_ATOMIC_INC,
					ctx->id, dict_client_escape(key), diff);
		(void)client_dict_send_transaction_query(ctx, query);
	);
}

struct dict dict_driver_client = {
	MEMBER(name) "proxy",

	{
		client_dict_init,
		client_dict_deinit,
		client_dict_lookup,
		client_dict_iterate_init,
		client_dict_iterate,
		client_dict_iterate_deinit,
		client_dict_transaction_init,
		client_dict_transaction_commit,
		client_dict_transaction_rollback,
		client_dict_set,
		client_dict_unset,
		client_dict_atomic_inc
	}
};
