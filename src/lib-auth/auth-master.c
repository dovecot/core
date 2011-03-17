/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "array.h"
#include "ioloop.h"
#include "eacces-error.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "master-interface.h"
#include "auth-master.h"

#include <stdlib.h>
#include <unistd.h>

#define AUTH_PROTOCOL_MAJOR 1
#define AUTH_PROTOCOL_MINOR 0

#define AUTH_MASTER_IDLE_SECS 60

#define MAX_INBUF_SIZE 8192
#define MAX_OUTBUF_SIZE 1024

#define DEFAULT_USERDB_LOOKUP_PREFIX "userdb lookup"

struct auth_master_connection {
	char *auth_socket_path;
	enum auth_master_flags flags;

	int fd;
	struct ioloop *ioloop;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct timeout *to;
	const char *prefix;

	unsigned int request_counter;

	bool (*reply_callback)(const char *cmd, const char *const *args,
			       void *context);
	void *reply_context;

	unsigned int sent_handshake:1;
	unsigned int handshaked:1;
	unsigned int aborted:1;
};

struct auth_master_lookup_ctx {
	struct auth_master_connection *conn;
	const char *user;
	const char *expected_reply;
	int return_value;

	pool_t pool;
	const char **fields;
};

struct auth_master_user_list_ctx {
	struct auth_master_connection *conn;
	pool_t pool;
	ARRAY_TYPE(const_string) users;
	const char *const *user_strings;
	unsigned int idx, user_count;
	bool failed;
};

static void auth_input(struct auth_master_connection *conn);

struct auth_master_connection *
auth_master_init(const char *auth_socket_path, enum auth_master_flags flags)
{
	struct auth_master_connection *conn;

	conn = i_new(struct auth_master_connection, 1);
	conn->auth_socket_path = i_strdup(auth_socket_path);
	conn->fd = -1;
	conn->flags = flags;
	conn->prefix = DEFAULT_USERDB_LOOKUP_PREFIX;
	return conn;
}

static void auth_connection_close(struct auth_master_connection *conn)
{
	if (conn->to != NULL)
		timeout_remove(&conn->to);
	if (conn->fd != -1) {
		if (close(conn->fd) < 0)
			i_error("close(%s) failed: %m", conn->auth_socket_path);
		conn->fd = -1;
	}

	conn->sent_handshake = FALSE;
	conn->handshaked = FALSE;
}

void auth_master_deinit(struct auth_master_connection **_conn)
{
	struct auth_master_connection *conn = *_conn;

	*_conn = NULL;
	auth_connection_close(conn);
	i_free(conn->auth_socket_path);
	i_free(conn);
}

static void auth_request_lookup_abort(struct auth_master_connection *conn)
{
	io_loop_stop(conn->ioloop);
	conn->aborted = TRUE;
}

static int auth_input_handshake(struct auth_master_connection *conn)
{
	const char *line, *const *tmp;

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		tmp = t_strsplit(line, "\t");
		if (strcmp(tmp[0], "VERSION") == 0 &&
		    tmp[1] != NULL && tmp[2] != NULL) {
			if (strcmp(tmp[1], dec2str(AUTH_PROTOCOL_MAJOR)) != 0) {
				i_error("userdb lookup: "
					"Auth protocol version mismatch "
					"(%s vs %d)", tmp[1],
					AUTH_PROTOCOL_MAJOR);
				auth_request_lookup_abort(conn);
				return -1;
			}
		} else if (strcmp(tmp[0], "SPID") == 0) {
			conn->handshaked = TRUE;
			break;
		}
	}
	return 0;
}

static int parse_reply(const char *cmd, const char *const *args,
		       const char *expected_reply, const char *user, bool debug)
{
	if (strcmp(cmd, expected_reply) == 0)
		return 1;
	if (strcmp(cmd, "NOTFOUND") == 0)
		return 0;
	if (strcmp(cmd, "FAIL") == 0) {
		if (*args == NULL) {
			i_error("user %s: Auth %s lookup failed",
				user, expected_reply);
		} else if (debug) {
			i_debug("user %s: Auth %s lookup returned temporary failure: %s",
				user, expected_reply, *args);
		}
		return -1;
	}
	i_error("Unknown reply: %s", cmd);
	return -1;
}

static bool auth_lookup_reply_callback(const char *cmd, const char *const *args,
				       void *context)
{
	struct auth_master_lookup_ctx *ctx = context;
	unsigned int i, len;
	bool debug = (ctx->conn->flags & AUTH_MASTER_FLAG_DEBUG) != 0;

	io_loop_stop(ctx->conn->ioloop);

	ctx->return_value =
		parse_reply(cmd, args, ctx->expected_reply, ctx->user, debug);

	len = str_array_length(args);
	if (ctx->return_value >= 0) {
		ctx->fields = p_new(ctx->pool, const char *, len + 1);
		for (i = 0; i < len; i++)
			ctx->fields[i] = p_strdup(ctx->pool, args[i]);
	} else {
		/* put the reason string into first field */
		ctx->fields = p_new(ctx->pool, const char *, 2);
		for (i = 0; i < len; i++) {
			if (strncmp(args[i], "reason=", 7) == 0) {
				ctx->fields[0] =
					p_strdup(ctx->pool, args[i] + 7);
				break;
			}
		}
	}
	if (debug)
		i_debug("auth input: %s", t_strarray_join(args, " "));
	return TRUE;
}

static bool
auth_handle_line(struct auth_master_connection *conn, const char *line)
{
	const char *cmd, *const *args, *id, *wanted_id;

	args = t_strsplit(line, "\t");
	cmd = *args; args++;
	if (*args == NULL)
		id = "";
	else {
		id = *args;
		args++;
	}

	wanted_id = dec2str(conn->request_counter);
	if (strcmp(id, wanted_id) == 0)
		return conn->reply_callback(cmd, args, conn->reply_context);

	if (strcmp(cmd, "CUID") == 0) {
		i_error("%s: %s is an auth client socket. "
			"It should be a master socket.",
			conn->prefix, conn->auth_socket_path);
	} else {
		i_error("%s: BUG: Unexpected input: %s", conn->prefix, line);
	}
	auth_request_lookup_abort(conn);
	return FALSE;
}

static void auth_input(struct auth_master_connection *conn)
{
	const char *line;
	bool ret;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		i_error("%s: Disconnected unexpectedly",
			conn->prefix);
		auth_request_lookup_abort(conn);
		return;
	case -2:
		/* buffer full */
		i_error("%s: BUG: Received more than %d bytes",
			conn->prefix, MAX_INBUF_SIZE);
		auth_request_lookup_abort(conn);
		return;
	}

	if (!conn->handshaked) {
		if (auth_input_handshake(conn) < 0)
			return;
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		T_BEGIN {
			ret = auth_handle_line(conn, line);
		} T_END;
		if (!ret)
			return;
	}
}

static int auth_master_connect(struct auth_master_connection *conn)
{
	int fd;

	i_assert(conn->fd == -1);

	/* max. 1 second wait here. */
	fd = net_connect_unix_with_retries(conn->auth_socket_path, 1000);
	if (fd == -1) {
		if (errno == EACCES) {
			i_error("userdb lookup: %s",
				eacces_error_get("connect",
						 conn->auth_socket_path));
		} else {
			i_error("userdb lookup: connect(%s) failed: %m",
				conn->auth_socket_path);
		}
		return -1;
	}
	conn->fd = fd;
	return 0;
}

static void auth_request_timeout(struct auth_master_connection *conn)
{
	if (!conn->handshaked)
		i_error("%s: Connecting timed out", conn->prefix);
	else
		i_error("%s: Request timed out", conn->prefix);
	auth_request_lookup_abort(conn);
}

static void auth_idle_timeout(struct auth_master_connection *conn)
{
	auth_connection_close(conn);
}

static void auth_master_set_io(struct auth_master_connection *conn)
{
	if (conn->to != NULL)
		timeout_remove(&conn->to);

	conn->ioloop = io_loop_create();
	conn->input = i_stream_create_fd(conn->fd, MAX_INBUF_SIZE, FALSE);
	conn->output = o_stream_create_fd(conn->fd, MAX_OUTBUF_SIZE, FALSE);
	conn->io = io_add(conn->fd, IO_READ, auth_input, conn);
	conn->to = timeout_add(1000*MASTER_AUTH_LOOKUP_TIMEOUT_SECS,
			       auth_request_timeout, conn);
	lib_signals_reset_ioloop();
}

static void auth_master_unset_io(struct auth_master_connection *conn,
				 struct ioloop *prev_ioloop)
{
	if (prev_ioloop != NULL) {
		io_loop_set_current(prev_ioloop);
		lib_signals_reset_ioloop();
	}
	io_loop_set_current(conn->ioloop);

	timeout_remove(&conn->to);
	io_remove(&conn->io);
	i_stream_unref(&conn->input);
	o_stream_unref(&conn->output);
	io_loop_destroy(&conn->ioloop);

	if ((conn->flags & AUTH_MASTER_FLAG_NO_IDLE_TIMEOUT) == 0) {
		if (prev_ioloop == NULL)
			auth_connection_close(conn);
		else {
			conn->to = timeout_add(1000*AUTH_MASTER_IDLE_SECS,
					       auth_idle_timeout, conn);
		}
	}
}

static bool is_valid_string(const char *str)
{
	const char *p;

	/* make sure we're not sending any characters that have a special
	   meaning. */
	for (p = str; *p != '\0'; p++) {
		if (*p == '\t' || *p == '\n' || *p == '\r')
			return FALSE;
	}
	return TRUE;
}

static int auth_master_run_cmd(struct auth_master_connection *conn,
			       const char *cmd)
{
	struct ioloop *prev_ioloop;
	const char *str;

	if (conn->fd == -1) {
		if (auth_master_connect(conn) < 0)
			return -1;
	}

	prev_ioloop = current_ioloop;
	auth_master_set_io(conn);

	o_stream_cork(conn->output);
	if (!conn->sent_handshake) {
		str = t_strdup_printf("VERSION\t%d\t%d\n",
				      AUTH_PROTOCOL_MAJOR, AUTH_PROTOCOL_MINOR);
		o_stream_send_str(conn->output, str);
		conn->sent_handshake = TRUE;
	}

	o_stream_send_str(conn->output, cmd);
	o_stream_uncork(conn->output);

	if (conn->output->stream_errno != 0) {
		errno = conn->output->stream_errno;
		i_error("write(auth socket) failed: %m");
		conn->aborted = TRUE;
	} else {
		io_loop_run(conn->ioloop);
	}

	auth_master_unset_io(conn, prev_ioloop);
	if (conn->aborted) {
		conn->aborted = FALSE;
		auth_connection_close(conn);
		return -1;
	}
	return 0;
}

static unsigned int
auth_master_next_request_id(struct auth_master_connection *conn)
{
	if (++conn->request_counter == 0) {
		/* avoid zero */
		conn->request_counter++;
	}
	return conn->request_counter;
}

static void
auth_user_info_export(string_t *str, const struct auth_user_info *info)
{
	str_append(str, "service=");
	str_append(str, info->service);

	if (info->local_ip.family != 0)
		str_printfa(str, "\tlip=%s", net_ip2addr(&info->local_ip));
	if (info->local_port != 0)
		str_printfa(str, "\tlport=%d", info->local_port);
	if (info->remote_ip.family != 0)
		str_printfa(str, "\trip=%s", net_ip2addr(&info->remote_ip));
	if (info->remote_port != 0)
		str_printfa(str, "\trport=%d", info->remote_port);
}

int auth_master_user_lookup(struct auth_master_connection *conn,
			    const char *user, const struct auth_user_info *info,
			    pool_t pool, const char **username_r,
			    const char *const **fields_r)
{
	struct auth_master_lookup_ctx ctx;
	string_t *str;

	if (!is_valid_string(user) || !is_valid_string(info->service)) {
		/* non-allowed characters, the user can't exist */
		*username_r = NULL;
		*fields_r = NULL;
		return 0;
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.conn = conn;
	ctx.return_value = -1;
	ctx.pool = pool;
	ctx.expected_reply = "USER";
	ctx.user = user;

	conn->reply_callback = auth_lookup_reply_callback;
	conn->reply_context = &ctx;

	str = t_str_new(128);
	str_printfa(str, "USER\t%u\t%s\t",
		    auth_master_next_request_id(conn), user);
	auth_user_info_export(str, info);
	str_append_c(str, '\n');

	conn->prefix = t_strdup_printf("userdb lookup(%s)", user);
	(void)auth_master_run_cmd(conn, str_c(str));
	conn->prefix = DEFAULT_USERDB_LOOKUP_PREFIX;

	if (ctx.return_value <= 0 || ctx.fields[0] == NULL) {
		*username_r = NULL;
		*fields_r = ctx.fields != NULL ? ctx.fields :
			p_new(pool, const char *, 1);
		if (ctx.return_value > 0) {
			i_error("Userdb lookup didn't return username");
			ctx.return_value = -1;
		}
	} else {
		*username_r = ctx.fields[0];
		*fields_r = ctx.fields + 1;
	}
	return ctx.return_value;
}

void auth_user_fields_parse(const char *const *fields, pool_t pool,
			    struct auth_user_reply *reply_r)
{
	memset(reply_r, 0, sizeof(*reply_r));
	reply_r->uid = (uid_t)-1;
	reply_r->gid = (gid_t)-1;
	p_array_init(&reply_r->extra_fields, pool, 64);

	for (; *fields != NULL; fields++) {
		if (strncmp(*fields, "uid=", 4) == 0) {
			if (str_to_uid(*fields + 4, &reply_r->uid) < 0)
				i_error("Invalid uid in reply");
		} else if (strncmp(*fields, "gid=", 4) == 0) {
			if (str_to_gid(*fields + 4, &reply_r->gid) < 0)
				i_error("Invalid gid in reply");
		} else if (strncmp(*fields, "home=", 5) == 0)
			reply_r->home = p_strdup(pool, *fields + 5);
		else if (strncmp(*fields, "chroot=", 7) == 0)
			reply_r->chroot = p_strdup(pool, *fields + 7);
		else {
			const char *field = p_strdup(pool, *fields);
			array_append(&reply_r->extra_fields, &field, 1);
		}
	}
}

int auth_master_pass_lookup(struct auth_master_connection *conn,
			    const char *user, const struct auth_user_info *info,
			    pool_t pool, const char *const **fields_r)
{
	struct auth_master_lookup_ctx ctx;
	string_t *str;

	if (!is_valid_string(user) || !is_valid_string(info->service)) {
		/* non-allowed characters, the user can't exist */
		*fields_r = NULL;
		return 0;
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.conn = conn;
	ctx.return_value = -1;
	ctx.pool = pool;
	ctx.expected_reply = "PASS";
	ctx.user = user;

	conn->reply_callback = auth_lookup_reply_callback;
	conn->reply_context = &ctx;

	str = t_str_new(128);
	str_printfa(str, "PASS\t%u\t%s\t",
		    auth_master_next_request_id(conn), user);
	auth_user_info_export(str, info);
	str_append_c(str, '\n');

	conn->prefix = t_strdup_printf("passdb lookup(%s)", user);
	(void)auth_master_run_cmd(conn, str_c(str));
	conn->prefix = DEFAULT_USERDB_LOOKUP_PREFIX;

	*fields_r = ctx.fields != NULL ? ctx.fields :
		p_new(pool, const char *, 1);
	return ctx.return_value;
}

static bool
auth_user_list_reply_callback(const char *cmd, const char *const *args,
			      void *context)
{
	struct auth_master_user_list_ctx *ctx = context;
	const char *user;

	timeout_reset(ctx->conn->to);

	if (strcmp(cmd, "DONE") == 0) {
		io_loop_stop(ctx->conn->ioloop);
		if (args[0] != NULL && strcmp(args[0], "fail") == 0) {
			i_error("User listing returned failure");
			ctx->failed = TRUE;
		}
		return TRUE;
	}
	if (strcmp(cmd, "LIST") == 0 && args[0] != NULL) {
		/* we'll just read all the users into memory. otherwise we'd
		   have to use a separate connection for listing and there's
		   a higher chance of a failure since the connection could be
		   open to dovecot-auth for a long time. */
		user = p_strdup(ctx->pool, args[0]);
		array_append(&ctx->users, &user, 1);
		return TRUE;
	}
	return FALSE;
}

struct auth_master_user_list_ctx *
auth_master_user_list_init(struct auth_master_connection *conn)
{
	struct auth_master_user_list_ctx *ctx;
	const char *str;
	pool_t pool;

	pool = pool_alloconly_create("auth master user list", 10240);
	ctx = p_new(pool, struct auth_master_user_list_ctx, 1);
	ctx->pool = pool;
	ctx->conn = conn;
	i_array_init(&ctx->users, 128);

	conn->reply_callback = auth_user_list_reply_callback;
	conn->reply_context = ctx;

	str = t_strdup_printf("LIST\t%u\n", auth_master_next_request_id(conn));
	conn->prefix = "userdb list";
	if (auth_master_run_cmd(conn, str) < 0)
		ctx->failed = TRUE;
	ctx->user_strings = array_get(&ctx->users, &ctx->user_count);
	conn->prefix = DEFAULT_USERDB_LOOKUP_PREFIX;
	return ctx;
}

const char *auth_master_user_list_next(struct auth_master_user_list_ctx *ctx)
{
	if (ctx->idx == ctx->user_count)
		return NULL;
	return ctx->user_strings[ctx->idx++];
}

unsigned int auth_master_user_list_count(struct auth_master_user_list_ctx *ctx)
{
	return ctx->user_count;
}

int auth_master_user_list_deinit(struct auth_master_user_list_ctx **_ctx)
{
	struct auth_master_user_list_ctx *ctx = *_ctx;
	int ret = ctx->failed ? -1 : 0;

	*_ctx = NULL;
	array_free(&ctx->users);
	pool_unref(&ctx->pool);
	return ret;
}
