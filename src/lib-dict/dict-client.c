/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "str.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "eacces-error.h"
#include "dict-private.h"
#include "dict-client.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

/* Disconnect from dict server after this many milliseconds of idling after
   sending a command. Because dict server does blocking dict accesses, it can
   handle only one client at a time. This is why the default timeout is zero,
   so that there won't be many dict processes just doing nothing. Zero means
   that the socket is disconnected immediately after returning to ioloop. */
#define DICT_CLIENT_TIMEOUT_MSECS 0

/* Abort dict lookup after this many seconds. */
#define DICT_CLIENT_READ_TIMEOUT_SECS 30
/* Log a warning if dict lookup takes longer than this many seconds. */
#define DICT_CLIENT_READ_WARN_TIMEOUT_SECS 5

struct client_dict {
	struct dict dict;

	pool_t pool;
	int fd;
	const char *uri;
	const char *username;
	const char *path;
	enum dict_data_type value_type;

	time_t last_failed_connect;
	struct istream *input;
	struct ostream *output;
	struct io *io;
	struct timeout *to_idle;

	struct client_dict_transaction_context *transactions;

	unsigned int connect_counter;
	unsigned int transaction_id_counter;
	unsigned int async_commits;

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
	struct client_dict_transaction_context *prev, *next;

	/* for async commits */
	dict_transaction_commit_callback_t *callback;
	void *context;

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

	T_BEGIN {
		const char *query;

		query = t_strdup_printf("%c%u\n", DICT_PROTOCOL_CMD_BEGIN,
					ctx->id);
		if (client_dict_send_query(dict, query) < 0)
			ctx->failed = TRUE;
		else
			ctx->connect_counter = dict->connect_counter;
	} T_END;

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

static struct client_dict_transaction_context *
client_dict_transaction_find(struct client_dict *dict, unsigned int id)
{
	struct client_dict_transaction_context *ctx;

	for (ctx = dict->transactions; ctx != NULL; ctx = ctx->next) {
		if (ctx->id == id)
			return ctx;
	}
	return NULL;
}

static void
client_dict_finish_transaction(struct client_dict *dict,
			       unsigned int id, int ret)
{
	struct client_dict_transaction_context *ctx;

	ctx = client_dict_transaction_find(dict, id);
	if (ctx == NULL) {
		i_error("dict-client: Unknown transaction id %u", id);
		return;
	}
	if (ctx->callback != NULL)
		ctx->callback(ret, ctx->context);

	DLLIST_REMOVE(&dict->transactions, ctx);
	i_free(ctx);

	i_assert(dict->async_commits > 0);
	if (--dict->async_commits == 0)
		io_remove(&dict->io);
}

static ssize_t client_dict_read_timeout(struct client_dict *dict)
{
	time_t now, timeout;
	unsigned int diff;
	ssize_t ret;

	now = time(NULL);
	timeout = now + DICT_CLIENT_READ_TIMEOUT_SECS;

	do {
		alarm(timeout - now);
		ret = i_stream_read(dict->input);
		alarm(0);
		if (ret != 0)
			break;

		/* interrupted most likely because of timeout,
		   but check anyway. */
		now = time(NULL);
	} while (now < timeout);

	if (ret > 0) {
		diff = time(NULL) - now;
		if (diff >= DICT_CLIENT_READ_WARN_TIMEOUT_SECS) {
			i_warning("read(%s): dict lookup took %u seconds",
				  dict->path, diff);
		}
	}
	return ret;
}

static int client_dict_read_one_line(struct client_dict *dict, char **line_r)
{
	unsigned int id;
	char *line;
	ssize_t ret;

	*line_r = NULL;
	while ((line = i_stream_next_line(dict->input)) == NULL) {
		ret = client_dict_read_timeout(dict);
		switch (ret) {
		case -1:
			if (dict->input->stream_errno != 0)
				i_error("read(%s) failed: %m", dict->path);
			else {
				i_error("read(%s) failed: Remote disconnected",
					dict->path);
			}
			return -1;
		case -2:
			i_error("read(%s) returned too much data", dict->path);
			return -1;
		case 0:
			i_error("read(%s) failed: Timeout after %u seconds",
				dict->path, DICT_CLIENT_READ_TIMEOUT_SECS);
			return -1;
		default:
			i_assert(ret > 0);
			break;
		}
	}
	if (*line == DICT_PROTOCOL_REPLY_ASYNC_COMMIT) {
		switch (line[1]) {
		case DICT_PROTOCOL_REPLY_OK:
			ret = 1;
			break;
		case DICT_PROTOCOL_REPLY_NOTFOUND:
			ret = 0;
			break;
		case DICT_PROTOCOL_REPLY_FAIL:
			ret = -1;
			break;
		default:
			i_error("dict-client: Invalid async commit line: %s",
				line);
			return 0;
		}
		if (str_to_uint(line+2, &id) < 0) {
			i_error("dict-client: Invalid ID");
			return 0;
		}
		client_dict_finish_transaction(dict, id, ret);
		return 0;
	}
	*line_r = line;
	return 1;
}

static bool client_dict_is_finished(struct client_dict *dict)
{
	return dict->transactions == NULL && !dict->in_iteration &&
		dict->async_commits == 0;
}

static void client_dict_timeout(struct client_dict *dict)
{
	if (client_dict_is_finished(dict))
		client_dict_disconnect(dict);
}

static void client_dict_add_timeout(struct client_dict *dict)
{
	if (dict->to_idle != NULL) {
#if DICT_CLIENT_TIMEOUT_MSECS > 0
		timeout_reset(dict->to_idle);
#endif
	} else if (client_dict_is_finished(dict)) {
		dict->to_idle = timeout_add(DICT_CLIENT_TIMEOUT_MSECS,
					    client_dict_timeout, dict);
	}
}

static char *client_dict_read_line(struct client_dict *dict)
{
	char *line;

	while (client_dict_read_one_line(dict, &line) == 0)
		;

	client_dict_add_timeout(dict);
	return line;
}

static int client_dict_connect(struct client_dict *dict)
{
	const char *query;

	i_assert(dict->fd == -1);

	if (dict->last_failed_connect == ioloop_time) {
		/* Try again later */
		return -1;
	}

	dict->fd = net_connect_unix(dict->path);
	if (dict->fd == -1) {
		dict->last_failed_connect = ioloop_time;
		if (errno == EACCES) {
			i_error("%s", eacces_error_get("net_connect_unix",
						       dict->path));
		} else {
			i_error("net_connect_unix(%s) failed: %m",
				dict->path);
		}
		return -1;
	}

	/* Dictionary lookups are blocking */
	net_set_nonblock(dict->fd, FALSE);

	dict->input = i_stream_create_fd(dict->fd, (size_t)-1, FALSE);
	dict->output = o_stream_create_fd(dict->fd, 4096, FALSE);
	dict->transaction_id_counter = 0;
	dict->async_commits = 0;

	query = t_strdup_printf("%c%u\t%u\t%d\t%s\t%s\n",
				DICT_PROTOCOL_CMD_HELLO,
				DICT_CLIENT_PROTOCOL_MAJOR_VERSION,
				DICT_CLIENT_PROTOCOL_MINOR_VERSION,
				dict->value_type, dict->username, dict->uri);
	if (client_dict_send_query(dict, query) < 0) {
		dict->last_failed_connect = ioloop_time;
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

	if (dict->to_idle != NULL)
		timeout_remove(&dict->to_idle);
	if (dict->io != NULL)
		io_remove(&dict->io);
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
		 enum dict_data_type value_type, const char *username,
		 const char *base_dir)
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
		dict->path = p_strconcat(pool, base_dir,
				"/"DEFAULT_DICT_SERVER_SOCKET_FNAME, NULL);
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

static int client_dict_wait(struct dict *_dict)
{
	struct client_dict *dict = (struct client_dict *)_dict;
	char *line;
	int ret = 0;

	if (!dict->handshaked)
		return -1;

	while (dict->async_commits > 0) {
		if (client_dict_read_one_line(dict, &line) < 0) {
			ret = -1;
			break;
		}
	}
	return ret;
}

static int client_dict_lookup(struct dict *_dict, pool_t pool,
			      const char *key, const char **value_r)
{
	struct client_dict *dict = (struct client_dict *)_dict;
	const char *line;
	int ret;

	T_BEGIN {
		const char *query;

		query = t_strdup_printf("%c%s\n", DICT_PROTOCOL_CMD_LOOKUP,
					dict_client_escape(key));
		ret = client_dict_send_query(dict, query);
	} T_END;
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
client_dict_iterate_init(struct dict *_dict, const char *const *paths,
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

	T_BEGIN {
		string_t *query = t_str_new(256);
		unsigned int i;

		str_printfa(query, "%c%d", DICT_PROTOCOL_CMD_ITERATE, flags);
		for (i = 0; paths[i] != NULL; i++) {
			str_append_c(query, '\t');
			str_append(query, dict_client_escape(paths[i]));
		}
		str_append_c(query, '\n');
		if (client_dict_send_query(dict, str_c(query)) < 0)
			ctx->failed = TRUE;
	} T_END;
	return &ctx->ctx;
}

static bool client_dict_iterate(struct dict_iterate_context *_ctx,
				const char **key_r, const char **value_r)
{
	struct client_dict_iterate_context *ctx =
		(struct client_dict_iterate_context *)_ctx;
	struct client_dict *dict = (struct client_dict *)_ctx->dict;
	char *line, *value;

	if (ctx->failed)
		return FALSE;

	/* read next reply */
	line = client_dict_read_line(dict);
	if (line == NULL) {
		ctx->failed = TRUE;
		return FALSE;
	}

	if (*line == '\0') {
		/* end of iteration */
		return FALSE;
	}

	/* line contains key \t value */
	p_clear(ctx->pool);

	switch (*line) {
	case DICT_PROTOCOL_REPLY_OK:
		value = strchr(++line, '\t');
		break;
	case DICT_PROTOCOL_REPLY_FAIL:
		ctx->failed = TRUE;
		return FALSE;
	default:
		value = NULL;
		break;
	}
	if (value == NULL) {
		/* broken protocol */
		i_error("dict client (%s) sent broken reply", dict->path);
		ctx->failed = TRUE;
		return FALSE;
	}
	*value++ = '\0';

	*key_r = p_strdup(ctx->pool, dict_client_unescape(line));
	*value_r = p_strdup(ctx->pool, dict_client_unescape(value));
	return TRUE;
}

static int client_dict_iterate_deinit(struct dict_iterate_context *_ctx)
{
	struct client_dict *dict = (struct client_dict *)_ctx->dict;
	struct client_dict_iterate_context *ctx =
		(struct client_dict_iterate_context *)_ctx;
	int ret = ctx->failed ? -1 : 0;

	pool_unref(&ctx->pool);
	i_free(ctx);
	dict->in_iteration = FALSE;

	client_dict_add_timeout(dict);
	return ret;
}

static struct dict_transaction_context *
client_dict_transaction_init(struct dict *_dict)
{
	struct client_dict *dict = (struct client_dict *)_dict;
	struct client_dict_transaction_context *ctx;

	ctx = i_new(struct client_dict_transaction_context, 1);
	ctx->ctx.dict = _dict;
	ctx->id = ++dict->transaction_id_counter;

	DLLIST_PREPEND(&dict->transactions, ctx);
	return &ctx->ctx;
}

static void dict_async_input(struct client_dict *dict)
{
	char *line;
	size_t size;
	int ret;

	i_assert(!dict->in_iteration);

	do {
		ret = client_dict_read_one_line(dict, &line);
		(void)i_stream_get_data(dict->input, &size);
	} while (ret == 0 && size > 0);

	if (ret < 0)
		io_remove(&dict->io);
}

static int
client_dict_transaction_commit(struct dict_transaction_context *_ctx,
			       bool async,
			       dict_transaction_commit_callback_t *callback,
			       void *context)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;
	struct client_dict *dict = (struct client_dict *)_ctx->dict;
	int ret = ctx->failed ? -1 : 1;

	if (ctx->sent_begin && !ctx->failed) T_BEGIN {
		const char *query, *line;

		query = t_strdup_printf("%c%u\n", !async ?
					DICT_PROTOCOL_CMD_COMMIT :
					DICT_PROTOCOL_CMD_COMMIT_ASYNC,
					ctx->id);
		if (client_dict_send_transaction_query(ctx, query) < 0)
			ret = -1;
		else if (async) {
			ctx->callback = callback;
			ctx->context = context;
			if (dict->async_commits++ == 0) {
				dict->io = io_add(dict->fd, IO_READ,
						  dict_async_input, dict);
			}
		} else {
			/* sync commit, read reply */
			line = client_dict_read_line(dict);
			if (line == NULL)
				ret = -1;
			else if (*line == DICT_PROTOCOL_REPLY_OK)
				ret = 1;
			else if (*line == DICT_PROTOCOL_REPLY_NOTFOUND)
				ret = 0;
			else
				ret = -1;
		}
	} T_END;

	if (ret < 0 || !async) {
		DLLIST_REMOVE(&dict->transactions, ctx);
		i_free(ctx);

		client_dict_add_timeout(dict);
	}
	return ret;
}

static void
client_dict_transaction_rollback(struct dict_transaction_context *_ctx)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;
	struct client_dict *dict = (struct client_dict *)_ctx->dict;

	if (ctx->sent_begin) T_BEGIN {
		const char *query;

		query = t_strdup_printf("%c%u\n", DICT_PROTOCOL_CMD_ROLLBACK,
					ctx->id);
		(void)client_dict_send_transaction_query(ctx, query);
	} T_END;

	DLLIST_REMOVE(&dict->transactions, ctx);
	i_free(ctx);

	client_dict_add_timeout(dict);
}

static void client_dict_set(struct dict_transaction_context *_ctx,
			    const char *key, const char *value)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;

	T_BEGIN {
		const char *query;

		query = t_strdup_printf("%c%u\t%s\t%s\n",
					DICT_PROTOCOL_CMD_SET, ctx->id,
					dict_client_escape(key),
					dict_client_escape(value));
		(void)client_dict_send_transaction_query(ctx, query);
	} T_END;
}

static void client_dict_unset(struct dict_transaction_context *_ctx,
			      const char *key)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;

	T_BEGIN {
		const char *query;

		query = t_strdup_printf("%c%u\t%s\n",
					DICT_PROTOCOL_CMD_UNSET, ctx->id,
					dict_client_escape(key));
		(void)client_dict_send_transaction_query(ctx, query);
	} T_END;
}

static void client_dict_atomic_inc(struct dict_transaction_context *_ctx,
				   const char *key, long long diff)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;

	T_BEGIN {
		const char *query;
		query = t_strdup_printf("%c%u\t%s\t%lld\n",
					DICT_PROTOCOL_CMD_ATOMIC_INC,
					ctx->id, dict_client_escape(key), diff);
		(void)client_dict_send_transaction_query(ctx, query);
	} T_END;
}

struct dict dict_driver_client = {
	.name = "proxy",

	{
		client_dict_init,
		client_dict_deinit,
		client_dict_wait,
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
