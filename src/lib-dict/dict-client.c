/* Copyright (c) 2005-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "str.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "eacces-error.h"
#include "dict-private.h"
#include "dict-client.h"

#include <unistd.h>
#include <fcntl.h>

/* Disconnect from dict server after this many milliseconds of idling after
   sending a command. Because dict server does blocking dict accesses, it can
   handle only one client at a time. This is why the default timeout is zero,
   so that there won't be many dict processes just doing nothing. Zero means
   that the socket is disconnected immediately after returning to ioloop. */
#define DICT_CLIENT_DEFAULT_TIMEOUT_MSECS 0

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
	unsigned int idle_msecs;

	struct client_dict_transaction_context *transactions;

	unsigned int connect_counter;
	unsigned int transaction_id_counter;
	unsigned int async_commits;
	unsigned int iter_replies_skip;

	unsigned int in_iteration:1;
	unsigned int handshaked:1;
};

struct client_dict_iterate_context {
	struct dict_iterate_context ctx;
	char *error;

	pool_t pool;
	bool finished;
};

struct client_dict_transaction_context {
	struct dict_transaction_context ctx;
	struct client_dict_transaction_context *prev, *next;

	/* for async commits */
	dict_transaction_commit_callback_t *callback;
	void *context;

	char *error;

	unsigned int id;
	unsigned int connect_counter;

	unsigned int sent_begin:1;
	unsigned int async:1;
	unsigned int committed:1;
};

static int client_dict_connect(struct client_dict *dict, const char **error_r);
static void client_dict_disconnect(struct client_dict *dict, const char *reason);

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

static int client_dict_send_query(struct client_dict *dict, const char *query,
				  const char **error_r)
{
	if (dict->output == NULL) {
		/* not connected currently */
		if (client_dict_connect(dict, error_r) < 0)
			return -1;
	}

	if (o_stream_send_str(dict->output, query) < 0 ||
	    o_stream_flush(dict->output) < 0) {
		/* Send failed */
		*error_r = t_strdup_printf("write(%s) failed: %s",
			dict->path, o_stream_get_error(dict->output));
		if (!dict->handshaked) {
			/* we're trying to send hello, don't try to reconnect */
			return -1;
		}

		/* Reconnect and try again. */
		client_dict_disconnect(dict, *error_r);
		if (client_dict_connect(dict, error_r) < 0)
			return -1;

		if (o_stream_send_str(dict->output, query) < 0 ||
		    o_stream_flush(dict->output) < 0) {
			*error_r = t_strdup_printf("write(%s) failed: %s",
				dict->path, o_stream_get_error(dict->output));
			client_dict_disconnect(dict, *error_r);
			return -1;
		}
	}
	return 0;
}

static int
client_dict_transaction_send_begin(struct client_dict_transaction_context *ctx,
				   const char **error_r)
{
	struct client_dict *dict = (struct client_dict *)ctx->ctx.dict;
	const char *query;

	i_assert(ctx->error == NULL);

	query = t_strdup_printf("%c%u\n", DICT_PROTOCOL_CMD_BEGIN, ctx->id);
	if (client_dict_send_query(dict, query, error_r) < 0)
		return -1;
	ctx->connect_counter = dict->connect_counter;
	return 0;
}

static int
client_dict_send_transaction_query(struct client_dict_transaction_context *ctx,
				   const char *query, const char **error_r)
{
	struct client_dict *dict = (struct client_dict *)ctx->ctx.dict;

	i_assert(ctx->error == NULL);

	if (!ctx->sent_begin) {
		if (client_dict_transaction_send_begin(ctx, error_r) < 0)
			return -1;
		ctx->sent_begin = TRUE;
	}

	if (ctx->connect_counter != dict->connect_counter) {
		*error_r = "Reconnected to dict-server - transaction lost";
		return -1;
	}

	if (dict->output == NULL) {
		/* not connected, this'll fail */
		*error_r = "Disconnected from dict-server";
		return -1;
	}

	if (o_stream_send_str(dict->output, query) < 0 ||
	    o_stream_flush(dict->output) < 0) {
		/* Send failed. Our transactions have died, so don't even try
		   to re-send the command */
		*error_r = t_strdup_printf("write(%s) failed: %s",
			dict->path, o_stream_get_error(dict->output));
		client_dict_disconnect(dict, *error_r);
		return -1;
	}
	return 0;
}

static void
client_dict_try_send_transaction_query(struct client_dict_transaction_context *ctx,
				       const char *query)
{
	const char *error;

	if (ctx->error != NULL)
		return;
	if (client_dict_send_transaction_query(ctx, query, &error) < 0)
		ctx->error = i_strdup(error);
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
client_dict_finish_transaction(struct client_dict *dict, unsigned int id,
			       const struct dict_commit_result *result)
{
	struct client_dict_transaction_context *ctx;

	ctx = client_dict_transaction_find(dict, id);
	if (ctx == NULL) {
		i_error("dict-client: Unknown transaction id %u", id);
		return;
	}
	if (!ctx->committed) {
		/* transaction isn't committed yet, but we disconnected from
		   dict. mark it as failed so commit will fail later. */
		if (result->ret >= 0) {
			i_error("dict-client: Received transaction reply before it was committed");
			return;
		}
		if (ctx->error == NULL)
			ctx->error = i_strdup(result->error);
		return;
	}

	/* the callback may call the dict code again, so remove this
	   transaction before calling it */
	i_assert(dict->async_commits > 0);
	if (--dict->async_commits == 0) {
		if (dict->io != NULL)
			io_remove(&dict->io);
	}
	DLLIST_REMOVE(&dict->transactions, ctx);

	if (ctx->callback != NULL)
		ctx->callback(result, ctx->context);
	i_free(ctx);
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

static int
client_dict_read_one_line_real(struct client_dict *dict, char **line_r,
			       const char **error_r)
{
	unsigned int id;
	char *line;
	ssize_t ret;

	*line_r = NULL;
	while ((line = i_stream_next_line(dict->input)) == NULL) {
		ret = client_dict_read_timeout(dict);
		switch (ret) {
		case -1:
			*error_r = t_strdup_printf("read(%s) failed: %s",
				dict->path, i_stream_get_disconnect_reason(dict->input));
			return -1;
		case -2:
			*error_r = t_strdup_printf(
				"read(%s) returned too much data", dict->path);
			return -1;
		case 0:
			*error_r = t_strdup_printf(
				"read(%s) failed: Timeout after %u seconds",
				dict->path, DICT_CLIENT_READ_TIMEOUT_SECS);
			return -1;
		default:
			i_assert(ret > 0);
			break;
		}
	}
	if (*line == DICT_PROTOCOL_REPLY_ASYNC_COMMIT) {
		struct dict_commit_result result;

		memset(&result, 0, sizeof(result));
		switch (line[1]) {
		case DICT_PROTOCOL_REPLY_OK:
			result.ret = 1;
			break;
		case DICT_PROTOCOL_REPLY_NOTFOUND:
			result.ret = 0;
			break;
		case DICT_PROTOCOL_REPLY_FAIL: {
			const char *error = strchr(line+2, '\t');

			result.ret = -1;
			result.error = t_strdup_printf(
				"dict-server returned failure: %s",
				error != NULL ? dict_client_unescape(error) : "");
			break;
		}
		default:
			*error_r = t_strdup_printf(
				"dict-client: Invalid async commit line: %s", line);
			return -1;
		}
		if (str_to_uint(t_strcut(line+2, '\t'), &id) < 0) {
			*error_r = t_strdup_printf("dict-client: Invalid ID");
			return -1;
		}
		client_dict_finish_transaction(dict, id, &result);
		return 0;
	}
	if (dict->iter_replies_skip > 0) {
		/* called aborted the iteration before finishing it.
		   skip over the iteration reply */
		if (*line == DICT_PROTOCOL_REPLY_OK)
			return 0;
		if (*line != '\0' && *line != DICT_PROTOCOL_REPLY_FAIL) {
			*error_r = t_strdup_printf(
				"dict-client: Invalid iteration reply line: %s", line);
			return -1;
		}
		dict->iter_replies_skip--;
		return 0;
	}
	*line_r = line;
	return 1;
}

static int client_dict_read_one_line(struct client_dict *dict, char **line_r,
				     const char **error_r)
{
	int ret;

	if ((ret = client_dict_read_one_line_real(dict, line_r, error_r)) < 0)
		client_dict_disconnect(dict, *error_r);
	return ret;
}

static bool client_dict_is_finished(struct client_dict *dict)
{
	return dict->transactions == NULL && !dict->in_iteration &&
		dict->async_commits == 0;
}

static void client_dict_timeout(struct client_dict *dict)
{
	if (client_dict_is_finished(dict))
		client_dict_disconnect(dict, "Idle disconnection");
}

static void client_dict_add_timeout(struct client_dict *dict)
{
	if (dict->to_idle != NULL) {
		if (dict->idle_msecs > 0)
			timeout_reset(dict->to_idle);
	} else if (client_dict_is_finished(dict)) {
		dict->to_idle = timeout_add(dict->idle_msecs,
					    client_dict_timeout, dict);
	}
}

static int client_dict_read_line(struct client_dict *dict,
				 char **line_r, const char **error_r)
{
	int ret;

	while ((ret = client_dict_read_one_line(dict, line_r, error_r)) == 0)
		;
	i_assert(ret < 0 || *line_r != NULL);

	client_dict_add_timeout(dict);
	return ret < 0 ? -1 : 0;
}

static int client_dict_connect(struct client_dict *dict, const char **error_r)
{
	const char *query;

	if (dict->last_failed_connect == ioloop_time) {
		/* Try again later */
		*error_r = "Waiting until the next connect attempt";
		return -1;
	}

	dict->fd = net_connect_unix(dict->path);
	if (dict->fd == -1) {
		dict->last_failed_connect = ioloop_time;
		if (errno == EACCES) {
			*error_r = eacces_error_get("net_connect_unix",
						    dict->path);
		} else {
			*error_r = t_strdup_printf(
				"net_connect_unix(%s) failed: %m", dict->path);
		}
		return -1;
	}

	/* Dictionary lookups are blocking */
	net_set_nonblock(dict->fd, FALSE);

	dict->input = i_stream_create_fd(dict->fd, (size_t)-1, FALSE);
	dict->output = o_stream_create_fd(dict->fd, 4096, FALSE);

	query = t_strdup_printf("%c%u\t%u\t%d\t%s\t%s\n",
				DICT_PROTOCOL_CMD_HELLO,
				DICT_CLIENT_PROTOCOL_MAJOR_VERSION,
				DICT_CLIENT_PROTOCOL_MINOR_VERSION,
				dict->value_type, dict->username, dict->uri);
	if (client_dict_send_query(dict, query, error_r) < 0) {
		dict->last_failed_connect = ioloop_time;
		client_dict_disconnect(dict, *error_r);
		return -1;
	}

	dict->handshaked = TRUE;
	return 0;
}

static void client_dict_disconnect(struct client_dict *dict, const char *reason)
{
	struct client_dict_transaction_context *ctx, *next;
	struct dict_commit_result result = { -1, reason };

	dict->connect_counter++;
	dict->handshaked = FALSE;
	dict->iter_replies_skip = 0;

	/* abort all pending async commits */
	for (ctx = dict->transactions; ctx != NULL; ctx = next) {
		next = ctx->next;
		if (ctx->async)
			client_dict_finish_transaction(dict, ctx->id, &result);
	}

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

static int
client_dict_init(struct dict *driver, const char *uri,
		 const struct dict_settings *set,
		 struct dict **dict_r, const char **error_r)
{
	struct client_dict *dict;
	const char *p, *dest_uri;
	unsigned int idle_msecs = DICT_CLIENT_DEFAULT_TIMEOUT_MSECS;
	pool_t pool;

	/* uri = [idle_msecs=<n>:] [<path>] ":" <uri> */
	if (strncmp(uri, "idle_msecs=", 11) == 0) {
		p = strchr(uri+14, ':');
		if (p == NULL) {
			*error_r = t_strdup_printf("Invalid URI: %s", uri);
			return -1;
		}
		if (str_to_uint(t_strdup_until(uri+14, p), &idle_msecs) < 0) {
			*error_r = "Invalid idle_msecs";
			return -1;
		}
		uri = p+1;
	}
	dest_uri = strchr(uri, ':');
	if (dest_uri == NULL) {
		*error_r = t_strdup_printf("Invalid URI: %s", uri);
		return -1;
	}

	pool = pool_alloconly_create("client dict", 1024);
	dict = p_new(pool, struct client_dict, 1);
	dict->pool = pool;
	dict->dict = *driver;
	dict->value_type = set->value_type;
	dict->username = p_strdup(pool, set->username);
	dict->idle_msecs = idle_msecs;

	dict->fd = -1;

	if (uri[0] == ':') {
		/* default path */
		dict->path = p_strconcat(pool, set->base_dir,
				"/"DEFAULT_DICT_SERVER_SOCKET_FNAME, NULL);
	} else if (uri[0] == '/') {
		/* absolute path */
		dict->path = p_strdup_until(pool, uri, dest_uri);
	} else {
		/* relative path to base_dir */
		dict->path = p_strconcat(pool, set->base_dir, "/",
				p_strdup_until(pool, uri, dest_uri), NULL);
	}
	dict->uri = p_strdup(pool, dest_uri + 1);
	*dict_r = &dict->dict;
	return 0;
}

static void client_dict_deinit(struct dict *_dict)
{
	struct client_dict *dict = (struct client_dict *)_dict;

        client_dict_disconnect(dict, "Deinit");
	i_assert(dict->transactions == NULL);
	pool_unref(&dict->pool);
}

static void client_dict_wait(struct dict *_dict)
{
	struct client_dict *dict = (struct client_dict *)_dict;
	const char *error;
	char *line;
	int ret;

	while (dict->async_commits > 0) {
		if ((ret = client_dict_read_one_line(dict, &line, &error)) < 0) {
			i_error("%s", error);
			break;
		}

		if (ret > 0) {
			const char *reason = t_strdup_printf(
				"dict-client: Unexpected reply waiting waiting for async commits: %s", line);
			i_error("%s", reason);
			client_dict_disconnect(dict, reason);
			break;
		}
	}
	/* we should have aborted all the async calls if we disconnected */
	i_assert(dict->async_commits == 0);
}

static int client_dict_lookup(struct dict *_dict, pool_t pool, const char *key,
			      const char **value_r, const char **error_r)
{
	struct client_dict *dict = (struct client_dict *)_dict;
	const char *query;
	char *line;

	query = t_strdup_printf("%c%s\n", DICT_PROTOCOL_CMD_LOOKUP,
				dict_client_escape(key));
	if (client_dict_send_query(dict, query, error_r) < 0)
		return -1;

	/* read reply */
	if (client_dict_read_line(dict, &line, error_r) < 0)
		return -1;

	switch (*line) {
	case DICT_PROTOCOL_REPLY_OK:
		*value_r = p_strdup(pool, dict_client_unescape(line + 1));
		return 1;
	case DICT_PROTOCOL_REPLY_NOTFOUND:
		*value_r = NULL;
		return 0;
	case DICT_PROTOCOL_REPLY_FAIL:
		*error_r = line[1] == '\0' ? "dict-server returned failure" :
			t_strdup_printf("dict-server returned failure: %s",
			dict_client_unescape(line+1));
		return -1;
	default:
		*error_r = t_strdup_printf(
			"dict-client: Invalid lookup '%s' reply: %s", key, line);
		client_dict_disconnect(dict, *error_r);
		return -1;
	}
}

static struct dict_iterate_context *
client_dict_iterate_init(struct dict *_dict, const char *const *paths,
			 enum dict_iterate_flags flags)
{
	struct client_dict *dict = (struct client_dict *)_dict;
        struct client_dict_iterate_context *ctx;
	string_t *query = t_str_new(256);
	unsigned int i;
	const char *error;

	if (dict->in_iteration)
		i_panic("dict-client: Only one iteration supported");
	dict->in_iteration = TRUE;

	ctx = i_new(struct client_dict_iterate_context, 1);
	ctx->ctx.dict = _dict;
	ctx->pool = pool_alloconly_create("client dict iteration", 512);

	str_printfa(query, "%c%d", DICT_PROTOCOL_CMD_ITERATE, flags);
	for (i = 0; paths[i] != NULL; i++) {
		str_append_c(query, '\t');
			str_append(query, dict_client_escape(paths[i]));
	}
	str_append_c(query, '\n');
	if (client_dict_send_query(dict, str_c(query), &error) < 0)
		ctx->error = i_strdup(error);
	return &ctx->ctx;
}

static bool client_dict_iterate(struct dict_iterate_context *_ctx,
				const char **key_r, const char **value_r)
{
	struct client_dict_iterate_context *ctx =
		(struct client_dict_iterate_context *)_ctx;
	struct client_dict *dict = (struct client_dict *)_ctx->dict;
	char *line, *key, *value;
	const char *error;

	if (ctx->error != NULL)
		return FALSE;

	/* read next reply */
	if (client_dict_read_line(dict, &line, &error) < 0) {
		ctx->error = i_strdup(error);
		return FALSE;
	}

	if (*line == '\0') {
		/* end of iteration */
		ctx->finished = TRUE;
		return FALSE;
	}

	/* line contains key \t value */
	p_clear(ctx->pool);

	switch (*line) {
	case DICT_PROTOCOL_REPLY_OK:
		key = line+1;
		value = strchr(key, '\t');
		break;
	case DICT_PROTOCOL_REPLY_FAIL:
		ctx->error = i_strdup_printf("dict-server returned failure: %s", line+1);
		return FALSE;
	default:
		key = NULL;
		value = NULL;
		break;
	}
	if (value == NULL) {
		/* broken protocol */
		ctx->error = i_strdup_printf("dict client (%s) sent broken iterate reply: %s", dict->path, line);
		return FALSE;
	}
	*value++ = '\0';

	*key_r = p_strdup(ctx->pool, dict_client_unescape(key));
	*value_r = p_strdup(ctx->pool, dict_client_unescape(value));
	return TRUE;
}

static int client_dict_iterate_deinit(struct dict_iterate_context *_ctx,
				      const char **error_r)
{
	struct client_dict *dict = (struct client_dict *)_ctx->dict;
	struct client_dict_iterate_context *ctx =
		(struct client_dict_iterate_context *)_ctx;
	int ret = ctx->error != NULL ? -1 : 0;

	if (!ctx->finished)
		dict->iter_replies_skip++;

	*error_r = t_strdup(ctx->error);
	pool_unref(&ctx->pool);
	i_free(ctx->error);
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
	const char *error;
	char *line;
	int ret;

	i_assert(!dict->in_iteration);

	do {
		ret = client_dict_read_one_line(dict, &line, &error);
	} while (ret == 0 && i_stream_get_data_size(dict->input) > 0);

	if (ret < 0) {
		i_error("%s", error);
		io_remove(&dict->io);
	} else if (ret > 0) {
		const char *reason = t_strdup_printf(
			"dict-client: Unexpected reply waiting waiting for async commits: %s", line);
		i_error("%s", reason);
		client_dict_disconnect(dict, reason);
	}
}

static void
client_dict_transaction_commit(struct dict_transaction_context *_ctx,
			       bool async,
			       dict_transaction_commit_callback_t *callback,
			       void *context)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;
	struct client_dict *dict = (struct client_dict *)_ctx->dict;
	unsigned int id;
	struct dict_commit_result result;

	memset(&result, 0, sizeof(result));
	result.ret = ctx->error != NULL ? -1 : 1;
	result.error = t_strdup(ctx->error);

	ctx->committed = TRUE;
	if (ctx->sent_begin && ctx->error == NULL) {
		const char *query;
		char *line;

		query = t_strdup_printf("%c%u\n", !async ?
					DICT_PROTOCOL_CMD_COMMIT :
					DICT_PROTOCOL_CMD_COMMIT_ASYNC,
					ctx->id);
		if (client_dict_send_transaction_query(ctx, query, &result.error) < 0)
			result.ret = -1;
		else if (async) {
			ctx->callback = callback;
			ctx->context = context;
			ctx->async = TRUE;
			if (dict->async_commits++ == 0) {
				dict->io = io_add(dict->fd, IO_READ,
						  dict_async_input, dict);
			}
			return;
		} else {
			/* sync commit, read reply */
			if (client_dict_read_line(dict, &line, &result.error) < 0) {
				result.ret = -1;
			} else switch (*line) {
			case DICT_PROTOCOL_REPLY_OK:
				result.ret = 1;
				break;
			case DICT_PROTOCOL_REPLY_NOTFOUND:
				result.ret = 0;
				break;
			case DICT_PROTOCOL_REPLY_FAIL: {
				const char *error = strchr(line+1, '\t');

				result.ret = -1;
				result.error = t_strdup_printf(
					"dict-server returned failure: %s",
					error != NULL ? dict_client_unescape(error) : "");
				break;
			}
			default:
				result.ret = -1;
				result.error = t_strdup_printf(
					"dict-client: Invalid commit reply: %s", line);
				client_dict_disconnect(dict, result.error);
				line = NULL;
				break;
			}
			if (line != NULL &&
			    (str_to_uint(t_strcut(line+1, '\t'), &id) < 0 || ctx->id != id)) {
				result.ret = -1;
				result.error = t_strdup_printf(
					"dict-client: Invalid commit reply, "
					"expected id=%u: %s", ctx->id, line);
				client_dict_disconnect(dict, result.error);
			}
		}
	}
	DLLIST_REMOVE(&dict->transactions, ctx);

	callback(&result, context);
	i_free(ctx->error);
	i_free(ctx);

	client_dict_add_timeout(dict);
}

static void
client_dict_transaction_rollback(struct dict_transaction_context *_ctx)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;
	struct client_dict *dict = (struct client_dict *)_ctx->dict;

	if (ctx->sent_begin) {
		const char *query;

		query = t_strdup_printf("%c%u\n", DICT_PROTOCOL_CMD_ROLLBACK,
					ctx->id);
		client_dict_try_send_transaction_query(ctx, query);
	}

	DLLIST_REMOVE(&dict->transactions, ctx);
	i_free(ctx);

	client_dict_add_timeout(dict);
}

static void client_dict_set(struct dict_transaction_context *_ctx,
			    const char *key, const char *value)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;
	const char *query;

	query = t_strdup_printf("%c%u\t%s\t%s\n",
				DICT_PROTOCOL_CMD_SET, ctx->id,
				dict_client_escape(key),
				dict_client_escape(value));
	client_dict_try_send_transaction_query(ctx, query);
}

static void client_dict_unset(struct dict_transaction_context *_ctx,
			      const char *key)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;
	const char *query;

	query = t_strdup_printf("%c%u\t%s\n",
				DICT_PROTOCOL_CMD_UNSET, ctx->id,
				dict_client_escape(key));
	client_dict_try_send_transaction_query(ctx, query);
}

static void client_dict_atomic_inc(struct dict_transaction_context *_ctx,
				   const char *key, long long diff)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;
	const char *query;

	query = t_strdup_printf("%c%u\t%s\t%lld\n",
				DICT_PROTOCOL_CMD_ATOMIC_INC,
				ctx->id, dict_client_escape(key), diff);
	client_dict_try_send_transaction_query(ctx, query);
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
		client_dict_atomic_inc,
		NULL
	}
};
