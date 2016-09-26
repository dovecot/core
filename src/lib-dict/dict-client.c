/* Copyright (c) 2005-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "str.h"
#include "strescape.h"
#include "file-lock.h"
#include "time-util.h"
#include "connection.h"
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
#define DICT_CLIENT_REQUEST_TIMEOUT_MSECS 30000
/* Log a warning if dict lookup takes longer than this many milliseconds. */
#define DICT_CLIENT_REQUEST_WARN_TIMEOUT_MSECS 5000

struct client_dict_cmd {
	int refcount;
	struct client_dict *dict;
	struct timeval start_time;
	char *query;

	uint64_t start_main_ioloop_usecs;
	uint64_t start_dict_ioloop_usecs;
	uint64_t start_lock_usecs;

	bool retry_errors;
	bool no_replies;
	bool unfinished;
	bool background;

	void (*callback)(struct client_dict_cmd *cmd,
			 const char *line, const char *error,
			 bool disconnected);
        struct client_dict_iterate_context *iter;
	struct client_dict_transaction_context *trans;

	struct {
		dict_lookup_callback_t *lookup;
		dict_transaction_commit_callback_t *commit;
		void *context;
	} api_callback;
};

struct dict_connection {
	struct connection conn;
	struct client_dict *dict;
};

struct client_dict {
	struct dict dict;
	struct dict_connection conn;

	char *uri, *username;
	enum dict_data_type value_type;

	time_t last_failed_connect;
	char *last_connect_error;

	struct ioloop *ioloop, *prev_ioloop;
	struct timeout *to_requests;
	struct timeout *to_idle;
	unsigned int idle_msecs;

	ARRAY(struct client_dict_cmd *) cmds;
	struct client_dict_transaction_context *transactions;

	unsigned int transaction_id_counter;
};

struct client_dict_iter_result {
	const char *key, *value;
};

struct client_dict_iterate_context {
	struct dict_iterate_context ctx;
	char *error;

	pool_t results_pool;
	ARRAY(struct client_dict_iter_result) results;
	unsigned int result_idx;

	bool async;
	bool seen_results;
	bool finished;
	bool deinit;
};

struct client_dict_transaction_context {
	struct dict_transaction_context ctx;
	struct client_dict_transaction_context *prev, *next;

	char *first_query;
	char *error;

	unsigned int id;
	unsigned int query_count;

	bool sent_begin:1;
};

static struct connection_list *dict_connections;

static int client_dict_connect(struct client_dict *dict, const char **error_r);
static int client_dict_reconnect(struct client_dict *dict, const char *reason,
				 const char **error_r);
static void client_dict_disconnect(struct client_dict *dict, const char *reason);

static struct client_dict_cmd *
client_dict_cmd_init(struct client_dict *dict, const char *query)
{
	struct client_dict_cmd *cmd;

	io_loop_time_refresh();

	cmd = i_new(struct client_dict_cmd, 1);
	cmd->refcount = 1;
	cmd->dict = dict;
	cmd->query = i_strdup(query);
	cmd->start_time = ioloop_timeval;
	if (current_ioloop == dict->ioloop) {
		/* coming here from client_dict_wait() */
		i_assert(dict->prev_ioloop != NULL);
		cmd->start_main_ioloop_usecs =
			io_loop_get_wait_usecs(dict->prev_ioloop);
	} else {
		cmd->start_main_ioloop_usecs =
			io_loop_get_wait_usecs(current_ioloop);
	}
	cmd->start_dict_ioloop_usecs = io_loop_get_wait_usecs(dict->ioloop);
	cmd->start_lock_usecs = file_lock_wait_get_total_usecs();
	return cmd;
}

static void client_dict_cmd_ref(struct client_dict_cmd *cmd)
{
	i_assert(cmd->refcount > 0);
	cmd->refcount++;
}

static bool client_dict_cmd_unref(struct client_dict_cmd *cmd)
{
	i_assert(cmd->refcount > 0);
	if (--cmd->refcount > 0)
		return TRUE;

	i_assert(cmd->trans == NULL);

	i_free(cmd->query);
	i_free(cmd);
	return FALSE;
}

static void dict_pre_api_callback(struct client_dict *dict)
{
	if (dict->prev_ioloop != NULL) {
		/* Don't let callback see that we've created our
		   internal ioloop in case it wants to add some ios
		   or timeouts. */
		current_ioloop = dict->prev_ioloop;
	}
}

static void dict_post_api_callback(struct client_dict *dict)
{
	if (dict->prev_ioloop != NULL) {
		current_ioloop = dict->ioloop;
		/* stop client_dict_wait() */
		io_loop_stop(dict->ioloop);
	}
}

static bool
dict_cmd_callback_line(struct client_dict_cmd *cmd, const char *line)
{
	cmd->unfinished = FALSE;
	cmd->callback(cmd, line, NULL, FALSE);
	return !cmd->unfinished;
}

static void
dict_cmd_callback_error(struct client_dict_cmd *cmd, const char *error,
			bool disconnected)
{
	cmd->unfinished = FALSE;
	if (cmd->callback != NULL)
		cmd->callback(cmd, NULL, error, disconnected);
	i_assert(!cmd->unfinished);
}

static void client_dict_input_timeout(struct client_dict *dict)
{
	struct client_dict_cmd *const *cmds;
	unsigned int i, count;
	const char *error;
	int cmd_diff;

	/* find the first expired non-background command */
	cmds = array_get(&dict->cmds, &count);
	for (i = 0; i < count; i++) {
		if (cmds[i]->background)
			continue;
		cmd_diff = timeval_diff_msecs(&ioloop_timeval, &cmds[i]->start_time);
		if (cmd_diff < DICT_CLIENT_REQUEST_TIMEOUT_MSECS) {
			/* need to re-create this timeout. the currently-oldest
			   command was added when another command was still
			   running with an older timeout. */
			timeout_remove(&dict->to_requests);
			dict->to_requests =
				timeout_add(DICT_CLIENT_REQUEST_TIMEOUT_MSECS - cmd_diff,
					    client_dict_input_timeout, dict);
		}
		break;
	}
	i_assert(i < count); /* we can't have only background commands */

	(void)client_dict_reconnect(dict, t_strdup_printf(
		"Dict server timeout: %s "
		"(%u commands pending, oldest sent %u.%03u secs ago: %s)",
		connection_input_timeout_reason(&dict->conn.conn), count,
		cmd_diff/1000, cmd_diff%1000, cmds[0]->query), &error);
}

static int
client_dict_cmd_query_send(struct client_dict *dict, const char *query)
{
	struct const_iovec iov[2];
	ssize_t ret;

	iov[0].iov_base = query;
	iov[0].iov_len = strlen(query);
	iov[1].iov_base = "\n";
	iov[1].iov_len = 1;
	ret = o_stream_sendv(dict->conn.conn.output, iov, 2);
	if (ret < 0)
		return -1;
	i_assert((size_t)ret == iov[0].iov_len + 1);
	return 0;
}

static bool
client_dict_cmd_send(struct client_dict *dict, struct client_dict_cmd **_cmd,
		     const char **error_r)
{
	struct client_dict_cmd *cmd = *_cmd;
	const char *error = NULL;
	bool retry = cmd->retry_errors;
	int ret;

	*_cmd = NULL;

	/* we're no longer idling. even with no_replies=TRUE we're going to
	   wait for COMMIT/ROLLBACK. */
	if (dict->to_idle != NULL)
		timeout_remove(&dict->to_idle);

	if (client_dict_connect(dict, &error) < 0) {
		retry = FALSE;
		ret = -1;
	} else {
		ret = client_dict_cmd_query_send(dict, cmd->query);
		if (ret < 0) {
			error = t_strdup_printf("write(%s) failed: %s", dict->conn.conn.name,
					o_stream_get_error(dict->conn.conn.output));
		}
	}
	if (ret < 0 && retry) {
		/* Reconnect and try again. */
		if (client_dict_reconnect(dict, error, &error) < 0)
			;
		else if (client_dict_cmd_query_send(dict, cmd->query) < 0) {
			error = t_strdup_printf("write(%s) failed: %s", dict->conn.conn.name,
				o_stream_get_error(dict->conn.conn.output));
		} else {
			ret = 0;
		}
	}

	if (cmd->no_replies) {
		/* just send and forget */
		client_dict_cmd_unref(cmd);
		return TRUE;
	} else if (ret < 0) {
		i_assert(error != NULL);
		/* we didn't successfully send this command to dict */
		dict_cmd_callback_error(cmd, error, FALSE);
		client_dict_cmd_unref(cmd);
		if (error_r != NULL)
			*error_r = error;
		return FALSE;
	} else {
		if (dict->to_requests == NULL && !cmd->background) {
			dict->to_requests =
				timeout_add(DICT_CLIENT_REQUEST_TIMEOUT_MSECS,
					    client_dict_input_timeout, dict);
		}
		array_append(&dict->cmds, &cmd, 1);
		return TRUE;
	}
}

static bool
client_dict_transaction_send_begin(struct client_dict_transaction_context *ctx)
{
	struct client_dict *dict = (struct client_dict *)ctx->ctx.dict;
	struct client_dict_cmd *cmd;
	const char *query, *error;

	i_assert(ctx->error == NULL);

	ctx->sent_begin = TRUE;

	/* transactions commands don't have replies. only COMMIT has. */
	query = t_strdup_printf("%c%u", DICT_PROTOCOL_CMD_BEGIN, ctx->id);
	cmd = client_dict_cmd_init(dict, query);
	cmd->no_replies = TRUE;
	cmd->retry_errors = TRUE;
	if (!client_dict_cmd_send(dict, &cmd, &error)) {
		ctx->error = i_strdup(error);
		return FALSE;
	}
	return TRUE;
}

static void
client_dict_send_transaction_query(struct client_dict_transaction_context *ctx,
				   const char *query)
{
	struct client_dict *dict = (struct client_dict *)ctx->ctx.dict;
	struct client_dict_cmd *cmd;
	const char *error;

	if (ctx->error != NULL)
		return;

	if (!ctx->sent_begin) {
		if (!client_dict_transaction_send_begin(ctx))
			return;
	}

	ctx->query_count++;
	if (ctx->first_query == NULL)
		ctx->first_query = i_strdup(query);

	cmd = client_dict_cmd_init(dict, query);
	cmd->no_replies = TRUE;
	if (!client_dict_cmd_send(dict, &cmd, &error))
		ctx->error = i_strdup(error);
}

static bool client_dict_is_finished(struct client_dict *dict)
{
	return dict->transactions == NULL && array_count(&dict->cmds) == 0;
}

static void client_dict_timeout(struct client_dict *dict)
{
	if (client_dict_is_finished(dict))
		client_dict_disconnect(dict, "Idle disconnection");
}

static bool client_dict_have_nonbackground_cmds(struct client_dict *dict)
{
	struct client_dict_cmd *const *cmdp;

	array_foreach(&dict->cmds, cmdp) {
		if (!(*cmdp)->background)
			return TRUE;
	}
	return FALSE;
}

static void client_dict_add_timeout(struct client_dict *dict)
{
	if (dict->to_idle != NULL) {
		if (dict->idle_msecs > 0)
			timeout_reset(dict->to_idle);
	} else if (client_dict_is_finished(dict)) {
		dict->to_idle = timeout_add(dict->idle_msecs,
					    client_dict_timeout, dict);
		if (dict->to_requests != NULL)
			timeout_remove(&dict->to_requests);
	} else if (dict->transactions == NULL &&
		   !client_dict_have_nonbackground_cmds(dict)) {
		/* we had non-background commands, but now we're back to
		   having only background commands. remove timeouts. */
		if (dict->to_requests != NULL)
			timeout_remove(&dict->to_requests);
	}
}

static void client_dict_cmd_backgrounded(struct client_dict *dict)
{
	if (dict->to_requests == NULL)
		return;

	if (!client_dict_have_nonbackground_cmds(dict)) {
		/* we only have background-commands.
		   remove the request timeout. */
		timeout_remove(&dict->to_requests);
	}
}

static int dict_conn_input_line(struct connection *_conn, const char *line)
{
	struct dict_connection *conn = (struct dict_connection *)_conn;
	struct client_dict *dict = conn->dict;
	struct client_dict_cmd *const *cmds;
	unsigned int count;
	bool finished;

	if (dict->to_requests != NULL)
		timeout_reset(dict->to_requests);

	cmds = array_get(&conn->dict->cmds, &count);
	if (count == 0) {
		i_error("%s: Received reply without pending commands: %s",
			dict->conn.conn.name, line);
		return -1;
	}
	i_assert(!cmds[0]->no_replies);

	client_dict_cmd_ref(cmds[0]);
	finished = dict_cmd_callback_line(cmds[0], line);
	if (!client_dict_cmd_unref(cmds[0])) {
		/* disconnected during command handling */
		return -1;
	}
	if (!finished) {
		/* more lines needed for this command */
		return 1;
	}
	client_dict_cmd_unref(cmds[0]);
	array_delete(&dict->cmds, 0, 1);

	client_dict_add_timeout(dict);
	return 1;
}

static int client_dict_connect(struct client_dict *dict, const char **error_r)
{
	const char *query, *error;

	if (dict->conn.conn.fd_in != -1)
		return 0;
	if (dict->last_failed_connect == ioloop_time) {
		/* Try again later */
		*error_r = dict->last_connect_error;
		return -1;
	}

	if (connection_client_connect(&dict->conn.conn) < 0) {
		dict->last_failed_connect = ioloop_time;
		if (errno == EACCES) {
			error = eacces_error_get("net_connect_unix",
						 dict->conn.conn.name);
		} else {
			error = t_strdup_printf(
				"net_connect_unix(%s) failed: %m", dict->conn.conn.name);
		}
		i_free(dict->last_connect_error);
		dict->last_connect_error = i_strdup(error);
		*error_r = error;
		return -1;
	}

	query = t_strdup_printf("%c%u\t%u\t%d\t%s\t%s\n",
				DICT_PROTOCOL_CMD_HELLO,
				DICT_CLIENT_PROTOCOL_MAJOR_VERSION,
				DICT_CLIENT_PROTOCOL_MINOR_VERSION,
				dict->value_type, dict->username, dict->uri);
	o_stream_nsend_str(dict->conn.conn.output, query);
	client_dict_add_timeout(dict);
	return 0;
}

static void
client_dict_abort_commands(struct client_dict *dict, const char *reason)
{
	ARRAY(struct client_dict_cmd *) cmds_copy;
	struct client_dict_cmd *const *cmdp;

	/* abort all commands */
	t_array_init(&cmds_copy, array_count(&dict->cmds));
	array_append_array(&cmds_copy, &dict->cmds);
	array_clear(&dict->cmds);

	array_foreach(&cmds_copy, cmdp) {
		dict_cmd_callback_error(*cmdp, reason, TRUE);
		client_dict_cmd_unref(*cmdp);
	}
}

static void client_dict_disconnect(struct client_dict *dict, const char *reason)
{
	struct client_dict_transaction_context *ctx, *next;

	client_dict_abort_commands(dict, reason);

	/* all transactions that have sent BEGIN are no longer valid */
	for (ctx = dict->transactions; ctx != NULL; ctx = next) {
		next = ctx->next;
		if (ctx->sent_begin && ctx->error == NULL)
			ctx->error = i_strdup(reason);
	}

	if (dict->to_idle != NULL)
		timeout_remove(&dict->to_idle);
	if (dict->to_requests != NULL)
		timeout_remove(&dict->to_requests);
	connection_disconnect(&dict->conn.conn);
}

static int client_dict_reconnect(struct client_dict *dict, const char *reason,
				 const char **error_r)
{
	ARRAY(struct client_dict_cmd *) retry_cmds;
	struct client_dict_cmd *const *cmdp, *cmd;
	const char *error;
	int ret;

	t_array_init(&retry_cmds, array_count(&dict->cmds));
	for (unsigned int i = 0; i < array_count(&dict->cmds); ) {
		cmdp = array_idx(&dict->cmds, i);
		if (!(*cmdp)->retry_errors) {
			i++;
		} else if ((*cmdp)->iter != NULL &&
			   (*cmdp)->iter->seen_results) {
			/* don't retry iteration that already returned
			   something to the caller. otherwise we'd return
			   duplicates. */
			i++;
		} else {
			array_append(&retry_cmds, cmdp, 1);
			array_delete(&dict->cmds, i, 1);
		}
	}
	client_dict_disconnect(dict, reason);
	if (client_dict_connect(dict, error_r) < 0) {
		reason = t_strdup_printf("%s - reconnect failed: %s",
					 reason, *error_r);
		array_foreach(&retry_cmds, cmdp) {
			dict_cmd_callback_error(*cmdp, reason, TRUE);
			client_dict_cmd_unref(*cmdp);
		}
		return -1;
	}
	if (array_count(&retry_cmds) == 0)
		return 0;
	i_warning("%s - reconnected", reason);

	ret = 0; error = "";
	array_foreach(&retry_cmds, cmdp) {
		cmd = *cmdp;
		/* if it fails again, don't retry anymore */
		cmd->retry_errors = FALSE;
		if (ret < 0) {
			dict_cmd_callback_error(cmd, error, TRUE);
			client_dict_cmd_unref(cmd);
		} else if (!client_dict_cmd_send(dict, &cmd, &error))
			ret = -1;
	}
	return ret;
}

static void dict_conn_destroy(struct connection *_conn)
{
	struct dict_connection *conn = (struct dict_connection *)_conn;

	client_dict_disconnect(conn->dict, connection_disconnect_reason(_conn));
}

static const struct connection_settings dict_conn_set = {
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.unix_client_connect_msecs = 1000,
	.client = TRUE
};

static const struct connection_vfuncs dict_conn_vfuncs = {
	.destroy = dict_conn_destroy,
	.input_line = dict_conn_input_line
};

static int
client_dict_init(struct dict *driver, const char *uri,
		 const struct dict_settings *set,
		 struct dict **dict_r, const char **error_r)
{
	struct ioloop *old_ioloop = current_ioloop;
	struct client_dict *dict;
	const char *p, *dest_uri, *path;
	unsigned int idle_msecs = DICT_CLIENT_DEFAULT_TIMEOUT_MSECS;

	/* uri = [idle_msecs=<n>:] [<path>] ":" <uri> */
	if (strncmp(uri, "idle_msecs=", 11) == 0) {
		p = strchr(uri+11, ':');
		if (p == NULL) {
			*error_r = t_strdup_printf("Invalid URI: %s", uri);
			return -1;
		}
		if (str_to_uint(t_strdup_until(uri+11, p), &idle_msecs) < 0) {
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

	if (dict_connections == NULL) {
		dict_connections = connection_list_init(&dict_conn_set,
							&dict_conn_vfuncs);
	}

	dict = i_new(struct client_dict, 1);
	dict->dict = *driver;
	dict->conn.dict = dict;
	dict->value_type = set->value_type;
	dict->username = i_strdup(set->username);
	dict->idle_msecs = idle_msecs;
	i_array_init(&dict->cmds, 32);

	if (uri[0] == ':') {
		/* default path */
		path = t_strconcat(set->base_dir,
			"/"DEFAULT_DICT_SERVER_SOCKET_FNAME, NULL);
	} else if (uri[0] == '/') {
		/* absolute path */
		path = t_strdup_until(uri, dest_uri);
	} else {
		/* relative path to base_dir */
		path = t_strconcat(set->base_dir, "/",
			t_strdup_until(uri, dest_uri), NULL);
	}
	connection_init_client_unix(dict_connections, &dict->conn.conn, path);
	dict->uri = i_strdup(dest_uri + 1);

	dict->ioloop = io_loop_create();
	io_loop_set_current(old_ioloop);
	*dict_r = &dict->dict;
	return 0;
}

static void client_dict_deinit(struct dict *_dict)
{
	struct client_dict *dict = (struct client_dict *)_dict;
	struct ioloop *old_ioloop = current_ioloop;

	client_dict_disconnect(dict, "Deinit");
	connection_deinit(&dict->conn.conn);

	i_assert(dict->transactions == NULL);
	i_assert(array_count(&dict->cmds) == 0);

	io_loop_set_current(dict->ioloop);
	io_loop_destroy(&dict->ioloop);
	io_loop_set_current(old_ioloop);

	array_free(&dict->cmds);
	i_free(dict->last_connect_error);
	i_free(dict->username);
	i_free(dict->uri);
	i_free(dict);

	if (dict_connections->connections == NULL)
		connection_list_deinit(&dict_connections);
}

static void client_dict_wait(struct dict *_dict)
{
	struct client_dict *dict = (struct client_dict *)_dict;

	if (array_count(&dict->cmds) == 0)
		return;

	dict->prev_ioloop = current_ioloop;
	io_loop_set_current(dict->ioloop);
	dict_switch_ioloop(_dict);
	while (array_count(&dict->cmds) > 0)
		io_loop_run(dict->ioloop);

	io_loop_set_current(dict->prev_ioloop);
	dict->prev_ioloop = NULL;

	dict_switch_ioloop(_dict);
}

static bool client_dict_switch_ioloop(struct dict *_dict)
{
	struct client_dict *dict = (struct client_dict *)_dict;

	if (dict->to_idle != NULL)
		dict->to_idle = io_loop_move_timeout(&dict->to_idle);
	if (dict->to_requests != NULL)
		dict->to_requests = io_loop_move_timeout(&dict->to_requests);
	connection_switch_ioloop(&dict->conn.conn);
	return array_count(&dict->cmds) > 0;
}

static const char *dict_warnings_sec(const struct client_dict_cmd *cmd, int msecs)
{
	int main_ioloop_msecs;

	/* we'll assume that the main ioloop is always the same in here and
	   in client_dict_cmd_init(), which strictly doesn't have to be true,
	   but practically is. */
	if (current_ioloop == cmd->dict->ioloop) {
		/* coming here from client_dict_wait() */
		i_assert(cmd->dict->prev_ioloop != NULL);
		main_ioloop_msecs =
			(io_loop_get_wait_usecs(cmd->dict->prev_ioloop) -
			 cmd->start_main_ioloop_usecs + 999) / 1000;
	} else {
		main_ioloop_msecs =
			(io_loop_get_wait_usecs(current_ioloop) -
			 cmd->start_main_ioloop_usecs + 999) / 1000;
	}
	int dict_ioloop_msecs = (io_loop_get_wait_usecs(cmd->dict->ioloop) -
				 cmd->start_dict_ioloop_usecs + 999) / 1000;
	int lock_msecs = (file_lock_wait_get_total_usecs() -
			  cmd->start_lock_usecs + 999) / 1000;

	return t_strdup_printf(
		"%u.%03u secs (%u.%03u in main ioloop, %u.%03u in dict wait, "
		"%u.%03u in locks)", msecs/1000, msecs%1000,
		main_ioloop_msecs/1000, main_ioloop_msecs%1000,
		dict_ioloop_msecs/1000, dict_ioloop_msecs%1000,
		lock_msecs/1000, lock_msecs%1000);
}

static void
client_dict_lookup_async_callback(struct client_dict_cmd *cmd, const char *line,
				  const char *error, bool disconnected ATTR_UNUSED)
{
	struct client_dict *dict = cmd->dict;
	struct dict_lookup_result result;

	memset(&result, 0, sizeof(result));
	if (error != NULL) {
		result.ret = -1;
		result.error = error;
	} else switch (*line) {
	case DICT_PROTOCOL_REPLY_OK:
		result.value = t_str_tabunescape(line + 1);
		result.ret = 1;
		break;
	case DICT_PROTOCOL_REPLY_NOTFOUND:
		result.ret = 0;
		break;
	case DICT_PROTOCOL_REPLY_FAIL:
		result.error = line[1] == '\0' ? "dict-server returned failure" :
			t_strdup_printf("dict-server returned failure: %s",
			t_str_tabunescape(line+1));
		result.ret = -1;
		break;
	default:
		result.error = t_strdup_printf(
			"dict-client: Invalid lookup '%s' reply: %s",
			cmd->query, line);
		client_dict_disconnect(dict, result.error);
		result.ret = -1;
		break;
	}

	int diff = timeval_diff_msecs(&ioloop_timeval, &cmd->start_time);
	if (result.error != NULL) {
		/* include timing info always in error messages */
		result.error = t_strdup_printf("%s (reply took %s)",
			result.error, dict_warnings_sec(cmd, diff));
	} else if (!cmd->background &&
		   diff >= DICT_CLIENT_REQUEST_WARN_TIMEOUT_MSECS) {
		i_warning("read(%s): dict lookup took %s: %s",
			  dict->conn.conn.name, dict_warnings_sec(cmd, diff),
			  cmd->query);
	}

	dict_pre_api_callback(dict);
	cmd->api_callback.lookup(&result, cmd->api_callback.context);
	dict_post_api_callback(dict);
}

static void
client_dict_lookup_async(struct dict *_dict, const char *key,
			 dict_lookup_callback_t *callback, void *context)
{
	struct client_dict *dict = (struct client_dict *)_dict;
	struct client_dict_cmd *cmd;
	const char *query;

	query = t_strdup_printf("%c%s", DICT_PROTOCOL_CMD_LOOKUP,
				str_tabescape(key));
	cmd = client_dict_cmd_init(dict, query);
	cmd->callback = client_dict_lookup_async_callback;
	cmd->api_callback.lookup = callback;
	cmd->api_callback.context = context;
	cmd->retry_errors = TRUE;

	client_dict_cmd_send(dict, &cmd, NULL);
}

struct client_dict_sync_lookup {
	struct dict_lookup_result result;
	char *error;
};

static void client_dict_lookup_callback(const struct dict_lookup_result *result,
					void *context)
{
	struct client_dict_sync_lookup *lookup = context;

	lookup->result = *result;
	if (result->ret == -1)
		lookup->error = i_strdup(result->error);
}

static int client_dict_lookup(struct dict *_dict, pool_t pool, const char *key,
			      const char **value_r, const char **error_r)
{
	struct client_dict_sync_lookup lookup;

	memset(&lookup, 0, sizeof(lookup));
	lookup.result.ret = -2;

	client_dict_lookup_async(_dict, key, client_dict_lookup_callback, &lookup);
	if (lookup.result.ret == -2)
		client_dict_wait(_dict);

	switch (lookup.result.ret) {
	case -1:
		*error_r = t_strdup(lookup.error);
		i_free(lookup.error);
		return -1;
	case 0:
		*value_r = NULL;
		return 0;
	case 1:
		*value_r = p_strdup(pool, lookup.result.value);
		return 1;
	}
	i_unreached();
}

static void client_dict_iterate_free(struct client_dict_iterate_context *ctx)
{
	if (!ctx->deinit || !ctx->finished)
		return;
	i_free(ctx->error);
	i_free(ctx);
}

static void
client_dict_iter_api_callback(struct client_dict_iterate_context *ctx,
			      struct client_dict_cmd *cmd)
{
	struct client_dict *dict = cmd->dict;

	if (ctx->deinit) {
		/* iterator was already deinitialized */
		return;
	}
	if (ctx->finished) {
		int diff = timeval_diff_msecs(&ioloop_timeval, &cmd->start_time);
		if (ctx->error != NULL) {
			/* include timing info always in error messages */
			char *new_error = i_strdup_printf("%s (reply took %s)",
				ctx->error, dict_warnings_sec(cmd, diff));
			i_free(ctx->error);
			ctx->error = new_error;
		} else if (!cmd->background &&
			   diff >= DICT_CLIENT_REQUEST_WARN_TIMEOUT_MSECS) {
			i_warning("read(%s): dict iteration took %s: %s",
				  dict->conn.conn.name, dict_warnings_sec(cmd, diff),
				  cmd->query);
		}
	}
	if (ctx->ctx.async_callback != NULL) {
		dict_pre_api_callback(dict);
		ctx->ctx.async_callback(ctx->ctx.async_context);
		dict_post_api_callback(dict);
	} else {
		/* synchronous lookup */
		io_loop_stop(dict->ioloop);
	}
}

static void
client_dict_iter_async_callback(struct client_dict_cmd *cmd, const char *line,
				const char *error, bool disconnected ATTR_UNUSED)
{
	struct client_dict_iterate_context *ctx = cmd->iter;
	struct client_dict *dict = cmd->dict;
	struct client_dict_iter_result *result;
	const char *key = NULL, *value = NULL;

	if (ctx->deinit) {
		cmd->background = TRUE;
		client_dict_cmd_backgrounded(dict);
	}

	if (error != NULL) {
		/* failed */
	} else switch (*line) {
	case '\0':
		/* end of iteration */
		ctx->finished = TRUE;
		client_dict_iter_api_callback(ctx, cmd);
		client_dict_iterate_free(ctx);
		return;
	case DICT_PROTOCOL_REPLY_OK:
		/* key \t value */
		key = line+1;
		value = strchr(key, '\t');
		break;
	case DICT_PROTOCOL_REPLY_FAIL:
		error = t_strdup_printf("dict-server returned failure: %s", line+1);
		break;
	default:
		break;
	}
	if (value == NULL && error == NULL) {
		/* broken protocol */
		error = t_strdup_printf("dict client (%s) sent broken iterate reply: %s",
					dict->conn.conn.name, line);
		client_dict_disconnect(dict, error);
	}

	if (error != NULL) {
		if (ctx->error == NULL)
			ctx->error = i_strdup(error);
		ctx->finished = TRUE;
		client_dict_iter_api_callback(ctx, cmd);
		client_dict_iterate_free(ctx);
		return;
	}
	cmd->unfinished = TRUE;

	if (ctx->deinit) {
		/* iterator was already deinitialized */
		return;
	}

	if (value != NULL)
		key = t_strdup_until(key, value++);
	else
		value = "";
	result = array_append_space(&ctx->results);
	result->key = p_strdup(ctx->results_pool, t_str_tabunescape(key));
	result->value = p_strdup(ctx->results_pool, t_str_tabunescape(value));

	client_dict_iter_api_callback(ctx, cmd);
}

static struct dict_iterate_context *
client_dict_iterate_init(struct dict *_dict, const char *const *paths,
			 enum dict_iterate_flags flags)
{
	struct client_dict *dict = (struct client_dict *)_dict;
        struct client_dict_iterate_context *ctx;
	struct client_dict_cmd *cmd;
	string_t *query = t_str_new(256);
	unsigned int i;

	ctx = i_new(struct client_dict_iterate_context, 1);
	ctx->ctx.dict = _dict;
	ctx->results_pool = pool_alloconly_create("client dict iteration", 512);
	ctx->async = (flags & DICT_ITERATE_FLAG_ASYNC) != 0;
	i_array_init(&ctx->results, 64);

	str_printfa(query, "%c%d", DICT_PROTOCOL_CMD_ITERATE, flags);
	for (i = 0; paths[i] != NULL; i++) {
		str_append_c(query, '\t');
			str_append(query, str_tabescape(paths[i]));
	}

	cmd = client_dict_cmd_init(dict, str_c(query));
	cmd->iter = ctx;
	cmd->callback = client_dict_iter_async_callback;
	cmd->retry_errors = TRUE;

	client_dict_cmd_send(dict, &cmd, NULL);
	return &ctx->ctx;
}

static bool client_dict_iterate(struct dict_iterate_context *_ctx,
				const char **key_r, const char **value_r)
{
	struct client_dict_iterate_context *ctx =
		(struct client_dict_iterate_context *)_ctx;
	const struct client_dict_iter_result *results;
	unsigned int count;

	if (ctx->error != NULL) {
		ctx->ctx.has_more = FALSE;
		return FALSE;
	}

	results = array_get(&ctx->results, &count);
	if (ctx->result_idx < count) {
		*key_r = results[ctx->result_idx].key;
		*value_r = results[ctx->result_idx].value;
		ctx->ctx.has_more = TRUE;
		ctx->result_idx++;
		ctx->seen_results = TRUE;
		return TRUE;
	}
	ctx->ctx.has_more = !ctx->finished;
	ctx->result_idx = 0;
	array_clear(&ctx->results);
	p_clear(ctx->results_pool);

	if (!ctx->async && ctx->ctx.has_more) {
		client_dict_wait(_ctx->dict);
		return client_dict_iterate(_ctx, key_r, value_r);
	}
	return FALSE;
}

static int client_dict_iterate_deinit(struct dict_iterate_context *_ctx,
				      const char **error_r)
{
	struct client_dict *dict = (struct client_dict *)_ctx->dict;
	struct client_dict_iterate_context *ctx =
		(struct client_dict_iterate_context *)_ctx;
	int ret = ctx->error != NULL ? -1 : 0;

	ctx->deinit = TRUE;

	*error_r = t_strdup(ctx->error);
	array_free(&ctx->results);
	pool_unref(&ctx->results_pool);
	client_dict_iterate_free(ctx);

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

static void
client_dict_transaction_free(struct client_dict_transaction_context **_ctx)
{
	struct client_dict_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	i_free(ctx->first_query);
	i_free(ctx->error);
	i_free(ctx);
}

static void
client_dict_transaction_commit_callback(struct client_dict_cmd *cmd,
					const char *line, const char *error,
					bool disconnected)
{
	struct client_dict *dict = cmd->dict;
	struct dict_commit_result result = {
		.ret = DICT_COMMIT_RET_FAILED, .error = NULL
	};

	i_assert(cmd->trans != NULL);

	if (error != NULL) {
		/* failed */
		if (disconnected)
			result.ret = DICT_COMMIT_RET_WRITE_UNCERTAIN;
		result.error = error;
	} else switch (*line) {
	case DICT_PROTOCOL_REPLY_OK:
		result.ret = DICT_COMMIT_RET_OK;
		break;
	case DICT_PROTOCOL_REPLY_NOTFOUND:
		result.ret = DICT_COMMIT_RET_NOTFOUND;
		break;
	case DICT_PROTOCOL_REPLY_WRITE_UNCERTAIN:
		result.ret = DICT_COMMIT_RET_WRITE_UNCERTAIN;
		/* fallthrough */
	case DICT_PROTOCOL_REPLY_FAIL: {
		const char *error = strchr(line+1, '\t');

		result.error = t_strdup_printf("dict-server returned failure: %s",
			error != NULL ? t_str_tabunescape(error) : "");
		break;
	}
	default:
		result.ret = DICT_COMMIT_RET_FAILED;
		result.error = t_strdup_printf(
			"dict-client: Invalid commit reply: %s", line);
		client_dict_disconnect(dict, result.error);
		break;
	}

	int diff = timeval_diff_msecs(&ioloop_timeval, &cmd->start_time);
	if (result.error != NULL) {
		/* include timing info always in error messages */
		result.error = t_strdup_printf("%s (reply took %s)",
			result.error, dict_warnings_sec(cmd, diff));
	} else if (!cmd->background && !cmd->trans->ctx.no_slowness_warning &&
		   diff >= DICT_CLIENT_REQUEST_WARN_TIMEOUT_MSECS) {
		i_warning("read(%s): dict commit took %s: "
			  "%s (%u commands, first: %s)",
			  dict->conn.conn.name, dict_warnings_sec(cmd, diff),
			  cmd->query, cmd->trans->query_count,
			  cmd->trans->first_query);
	}
	client_dict_transaction_free(&cmd->trans);

	dict_pre_api_callback(dict);
	cmd->api_callback.commit(&result, cmd->api_callback.context);
	dict_post_api_callback(dict);
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
	struct client_dict_cmd *cmd;
	const char *query;

	DLLIST_REMOVE(&dict->transactions, ctx);

	if (ctx->sent_begin && ctx->error == NULL) {
		query = t_strdup_printf("%c%u", DICT_PROTOCOL_CMD_COMMIT, ctx->id);
		cmd = client_dict_cmd_init(dict, query);
		cmd->trans = ctx;

		cmd->callback = client_dict_transaction_commit_callback;
		cmd->api_callback.commit = callback;
		cmd->api_callback.context = context;
		if (callback == dict_transaction_commit_async_noop_callback)
			cmd->background = TRUE;
		if (client_dict_cmd_send(dict, &cmd, NULL)) {
			if (!async)
				client_dict_wait(_ctx->dict);
		}
	} else if (ctx->error != NULL) {
		/* already failed */
		struct dict_commit_result result = {
			.ret = DICT_COMMIT_RET_FAILED, .error = ctx->error
		};
		callback(&result, context);
		client_dict_transaction_free(&ctx);
	} else {
		/* nothing changed */
		struct dict_commit_result result = {
			.ret = DICT_COMMIT_RET_OK, .error = NULL
		};
		callback(&result, context);
		client_dict_transaction_free(&ctx);
	}

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

		query = t_strdup_printf("%c%u", DICT_PROTOCOL_CMD_ROLLBACK,
					ctx->id);
		client_dict_send_transaction_query(ctx, query);
	}

	DLLIST_REMOVE(&dict->transactions, ctx);
	client_dict_transaction_free(&ctx);
	client_dict_add_timeout(dict);
}

static void client_dict_set(struct dict_transaction_context *_ctx,
			    const char *key, const char *value)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;
	const char *query;

	query = t_strdup_printf("%c%u\t%s\t%s",
				DICT_PROTOCOL_CMD_SET, ctx->id,
				str_tabescape(key),
				str_tabescape(value));
	client_dict_send_transaction_query(ctx, query);
}

static void client_dict_unset(struct dict_transaction_context *_ctx,
			      const char *key)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;
	const char *query;

	query = t_strdup_printf("%c%u\t%s",
				DICT_PROTOCOL_CMD_UNSET, ctx->id,
				str_tabescape(key));
	client_dict_send_transaction_query(ctx, query);
}

static void client_dict_atomic_inc(struct dict_transaction_context *_ctx,
				   const char *key, long long diff)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;
	const char *query;

	query = t_strdup_printf("%c%u\t%s\t%lld",
				DICT_PROTOCOL_CMD_ATOMIC_INC,
				ctx->id, str_tabescape(key), diff);
	client_dict_send_transaction_query(ctx, query);
}

struct dict dict_driver_client = {
	.name = "proxy",

	{
		.init = client_dict_init,
		.deinit = client_dict_deinit,
		.wait = client_dict_wait,
		.lookup = client_dict_lookup,
		.iterate_init = client_dict_iterate_init,
		.iterate = client_dict_iterate,
		.iterate_deinit = client_dict_iterate_deinit,
		.transaction_init = client_dict_transaction_init,
		.transaction_commit = client_dict_transaction_commit,
		.transaction_rollback = client_dict_transaction_rollback,
		.set = client_dict_set,
		.unset = client_dict_unset,
		.atomic_inc = client_dict_atomic_inc,
		.lookup_async = client_dict_lookup_async,
		.switch_ioloop = client_dict_switch_ioloop
	}
};
