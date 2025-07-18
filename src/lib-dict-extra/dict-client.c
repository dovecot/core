/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "str.h"
#include "strescape.h"
#include "str-parse.h"
#include "file-lock.h"
#include "time-util.h"
#include "connection.h"
#include "ostream.h"
#include "eacces-error.h"
#include "settings.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "dict-private.h"
#include "dict-client.h"

#include <unistd.h>
#include <fcntl.h>

/* Abort dict lookup after this many milliseconds. */
#define DICT_CLIENT_REQUEST_TIMEOUT_MSECS 30000
/* When dict lookup timeout is reached, wait a bit longer if the last dict
   ioloop wait was shorter than this. */
#define DICT_CLIENT_REQUEST_TIMEOUT_MIN_LAST_IOLOOP_WAIT_MSECS 1000

struct client_dict_cmd {
	int refcount;
	struct client_dict *dict;
	struct timeval start_time;
	char *query;
	struct timeout *to_request;
	unsigned int async_id;
	struct timeval async_id_received_time;

	uint64_t start_global_ioloop_usecs;
	uint64_t start_dict_ioloop_usecs;
	uint64_t start_lock_usecs;

	bool reconnected;
	bool retry_errors;
	bool no_replies;
	bool unfinished;
	bool background;

	void (*callback)(struct client_dict_cmd *cmd,
			 enum dict_protocol_reply reply, const char *value,
			 const char *const *extra_args, const char *error,
			 bool disconnected);
        struct client_dict_iterate_context *iter;
	struct client_dict_transaction_context *trans;

	struct {
		dict_lookup_callback_t *lookup;
		dict_transaction_commit_callback_t *commit;
		void *context;
	} api_callback;
};

struct dict_client_connection {
	struct connection conn;
	struct client_dict *dict;
};

struct client_dict {
	struct dict dict;
	struct dict_client_connection conn;
	struct dict_proxy_settings *set;

	time_t last_failed_connect;
	char *last_connect_error;

	struct io_wait_timer *wait_timer;
	uint64_t last_timer_switch_usecs;
	struct timeout *to_idle;

	ARRAY(struct client_dict_cmd *) cmds;
	struct client_dict_transaction_context *transactions;

	unsigned int transaction_id_counter;
};

struct client_dict_iter_result {
	const char *key, *const *values;
};

struct client_dict_iterate_context {
	struct dict_iterate_context ctx;
	char *error;
	char *path;
	enum dict_iterate_flags flags;
	int refcount;

	pool_t results_pool;
	ARRAY(struct client_dict_iter_result) results;
	unsigned int result_idx;

	bool cmd_sent;
	bool seen_results;
	bool iterating;
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

struct dict_proxy_settings {
	pool_t pool;

	unsigned int dict_proxy_idle_timeout;
	unsigned int dict_proxy_slow_warn;
	const char *dict_proxy_socket_path;
	const char *dict_proxy_name;
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct dict_proxy_settings)
static const struct setting_define dict_proxy_setting_defines[] = {
	DEF(TIME_MSECS, dict_proxy_idle_timeout),
	DEF(TIME_MSECS, dict_proxy_slow_warn),
	DEF(STR, dict_proxy_socket_path),
	DEF(STR, dict_proxy_name),

	SETTING_DEFINE_LIST_END
};
static const struct dict_proxy_settings dict_proxy_default_settings = {
	/* Disconnect from dict server after this many milliseconds of idling
	   after sending a command. Because dict server does blocking dict
	   accesses, it can handle only one client at a time. This is why the
	   default timeout is zero, so that there won't be many dict processes
	   just doing nothing. Zero means that the socket is disconnected
	   immediately after returning to ioloop. */
	.dict_proxy_idle_timeout = 0,
	/* Log a warning if dict lookup takes longer than this many milliseconds. */
	.dict_proxy_slow_warn = 5000,
	.dict_proxy_socket_path = "dict",
	.dict_proxy_name = "",
};
const struct setting_parser_info dict_proxy_setting_parser_info = {
	.name = "dict_proxy",

	.defines = dict_proxy_setting_defines,
	.defaults = &dict_proxy_default_settings,

	.struct_size = sizeof(struct dict_proxy_settings),
	.pool_offset1 = 1 + offsetof(struct dict_proxy_settings, pool),
};

static struct connection_list *dict_connections;

static int client_dict_connect(struct client_dict *dict, const char **error_r);
static int client_dict_reconnect(struct client_dict *dict, const char *reason,
				 const char **error_r);
static void client_dict_disconnect(struct client_dict *dict, const char *reason);
static const char *dict_wait_warnings(const struct client_dict_cmd *cmd);

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
	cmd->start_global_ioloop_usecs = ioloop_global_wait_usecs;
	cmd->start_dict_ioloop_usecs = io_wait_timer_get_usecs(dict->wait_timer);
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

static bool
dict_cmd_callback_line(struct client_dict_cmd *cmd, const char *const *args)
{
	const char *value = args[0];
	enum dict_protocol_reply reply;

	if (value == NULL) {
		/* "" is a valid iteration reply */
		reply = DICT_PROTOCOL_REPLY_ITER_FINISHED;
	} else {
		reply = value[0];
		value++;
		args++;
	}

	timeout_remove(&cmd->to_request);
	cmd->unfinished = FALSE;
	cmd->callback(cmd, reply, value, args, NULL, FALSE);
	return !cmd->unfinished;
}

static void
dict_cmd_callback_error(struct client_dict_cmd *cmd, const char *error,
			bool disconnected)
{
	cmd->unfinished = FALSE;
	timeout_remove(&cmd->to_request);
	if (cmd->callback != NULL) {
		cmd->callback(cmd, DICT_PROTOCOL_REPLY_ERROR,
			      "", empty_str_array, error, disconnected);
	}
	i_assert(!cmd->unfinished);
}

static void client_dict_input_timeout(struct client_dict_cmd *cmd)
{
	struct client_dict *dict = cmd->dict;
	const char *error;
	uint64_t msecs_in_last_dict_ioloop_wait;

	/* If we've gotten here because all the time was spent in other ioloops
	   or locks, make sure there's a bit of time waiting for the dict
	   ioloop as well. There's a good chance that the reply can be read. */
	msecs_in_last_dict_ioloop_wait =
		(io_wait_timer_get_usecs(dict->wait_timer) -
		 dict->last_timer_switch_usecs + 999) / 1000;
	if (msecs_in_last_dict_ioloop_wait < DICT_CLIENT_REQUEST_TIMEOUT_MIN_LAST_IOLOOP_WAIT_MSECS) {
		timeout_remove(&cmd->to_request);
		cmd->to_request =
			timeout_add(DICT_CLIENT_REQUEST_TIMEOUT_MIN_LAST_IOLOOP_WAIT_MSECS -
				    msecs_in_last_dict_ioloop_wait,
				    client_dict_input_timeout, cmd);
		return;
	}

	long long cmd_diff = timeval_diff_msecs(&ioloop_timeval,
						&cmd->start_time);
	(void)client_dict_reconnect(dict, t_strdup_printf(
		"Dict server timeout: %s "
		"(%u commands pending, oldest sent %lld.%03lld secs ago: %s, %s)",
		connection_input_timeout_reason(&dict->conn.conn),
		array_count(&dict->cmds),
		cmd_diff/1000, cmd_diff%1000, cmd->query,
		dict_wait_warnings(cmd)), &error);
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
		dict_cmd_callback_error(cmd, error, cmd->reconnected);
		client_dict_cmd_unref(cmd);
		if (error_r != NULL)
			*error_r = error;
		return FALSE;
	} else {
		i_assert(cmd->to_request == NULL);
		if (!cmd->background) {
			cmd->to_request =
				timeout_add(DICT_CLIENT_REQUEST_TIMEOUT_MSECS,
					    client_dict_input_timeout, cmd);
		}
		array_push_back(&dict->cmds, &cmd);
		return TRUE;
	}
}

static bool
client_dict_transaction_send_begin(struct client_dict_transaction_context *ctx,
				   const struct dict_op_settings_private *set)
{
	struct client_dict *dict = (struct client_dict *)ctx->ctx.dict;
	struct client_dict_cmd *cmd;
	const char *query, *error;

	i_assert(ctx->error == NULL);

	ctx->sent_begin = TRUE;

	/* transactions commands don't have replies. only COMMIT has. */
	query = t_strdup_printf("%c%u\t%s\t%u", DICT_PROTOCOL_CMD_BEGIN,
				ctx->id,
				set->username == NULL ? "" : str_tabescape(set->username),
				set->expire_secs);
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
	const struct dict_op_settings_private *set = &ctx->ctx.set;
	struct client_dict_cmd *cmd;
	const char *error;

	if (ctx->error != NULL)
		return;

	if (!ctx->sent_begin) {
		if (!client_dict_transaction_send_begin(ctx, set))
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
	else
		timeout_remove(&dict->to_idle);
}

static void client_dict_add_timeout(struct client_dict *dict)
{
	if (dict->to_idle != NULL) {
		if (dict->set->dict_proxy_idle_timeout > 0)
			timeout_reset(dict->to_idle);
	} else if (client_dict_is_finished(dict)) {
		dict->to_idle = timeout_add(dict->set->dict_proxy_idle_timeout,
					    client_dict_timeout, dict);
	}
}

static int
dict_conn_assign_next_async_id(struct dict_client_connection *conn,
			       const char *line)
{
	struct client_dict_cmd *const *cmds;
	unsigned int i, count, async_id;

	i_assert(line[0] == DICT_PROTOCOL_REPLY_ASYNC_ID);

	if (str_to_uint(line+1, &async_id) < 0 || async_id == 0) {
		e_error(conn->conn.event, "Received invalid async-id line: %s",
			line);
		return -1;
	}
	cmds = array_get(&conn->dict->cmds, &count);
	for (i = 0; i < count; i++) {
		if (cmds[i]->async_id == 0) {
			cmds[i]->async_id = async_id;
			cmds[i]->async_id_received_time = ioloop_timeval;
			return 0;
		}
	}
	e_error(conn->conn.event, "Received async-id line, but all %u "
				  "commands already have it: %s",
		count, line);
	return -1;
}

static int dict_conn_find_async_id(struct dict_client_connection *conn,
				   const char *async_arg,
				   const char *line, unsigned int *idx_r)
{
	struct client_dict_cmd *const *cmds;
	unsigned int i, count, async_id;

	i_assert(async_arg[0] == DICT_PROTOCOL_REPLY_ASYNC_REPLY);

	if (str_to_uint(async_arg+1, &async_id) < 0 || async_id == 0) {
		e_error(conn->conn.event, "Received invalid async-reply line: %s",
			line);
		return -1;
	}

	cmds = array_get(&conn->dict->cmds, &count);
	for (i = 0; i < count; i++) {
		if (cmds[i]->async_id == async_id) {
			*idx_r = i;
			return 0;
		}
	}
	e_error(conn->conn.event, "Received reply for nonexistent async-id %u: %s",
		async_id, line);
	return -1;
}

static int dict_conn_input_line(struct connection *_conn, const char *line)
{
	struct dict_client_connection *conn =
		(struct dict_client_connection *)_conn;
	struct client_dict *dict = conn->dict;
	struct client_dict_cmd *const *cmds;
	const char *const *args;
	unsigned int i, count;
	bool finished;

	if (line[0] == DICT_PROTOCOL_REPLY_ASYNC_ID)
		return dict_conn_assign_next_async_id(conn, line) < 0 ? -1 : 1;

	cmds = array_get(&conn->dict->cmds, &count);
	if (count == 0) {
		e_error(conn->conn.event, "Received reply without pending commands: %s",
			line);
		return -1;
	}

	args = t_strsplit_tabescaped(line);
	if (args[0] != NULL && args[0][0] == DICT_PROTOCOL_REPLY_ASYNC_REPLY) {
		if (dict_conn_find_async_id(conn, args[0], line, &i) < 0)
			return -1;
		args++;
	} else {
		i = 0;
	}
	i_assert(!cmds[i]->no_replies);

	client_dict_cmd_ref(cmds[i]);
	if (cmds[i]->to_request != NULL)
		timeout_reset(cmds[i]->to_request);
	finished = dict_cmd_callback_line(cmds[i], args);
	if (!client_dict_cmd_unref(cmds[i])) {
		/* disconnected during command handling */
		return -1;
	}
	if (!finished) {
		/* more lines needed for this command */
		return 1;
	}
	client_dict_cmd_unref(cmds[i]);
	array_delete(&dict->cmds, i, 1);

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

	query = t_strdup_printf("%c%u\t%u\t0\t\t%s\n",
				DICT_PROTOCOL_CMD_HELLO,
				DICT_CLIENT_PROTOCOL_MAJOR_VERSION,
				DICT_CLIENT_PROTOCOL_MINOR_VERSION,
				str_tabescape(dict->set->dict_proxy_name));
	o_stream_nsend_str(dict->conn.conn.output, query);
	client_dict_add_timeout(dict);
	return 0;
}

static void
client_dict_abort_commands(struct client_dict *dict, const char *reason)
{
	ARRAY(struct client_dict_cmd *) cmds_copy;
	struct client_dict_cmd *cmd;

	/* abort all commands */
	t_array_init(&cmds_copy, array_count(&dict->cmds));
	array_append_array(&cmds_copy, &dict->cmds);
	array_clear(&dict->cmds);

	array_foreach_elem(&cmds_copy, cmd) {
		dict_cmd_callback_error(cmd, reason, TRUE);
		client_dict_cmd_unref(cmd);
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

	timeout_remove(&dict->to_idle);
	connection_disconnect(&dict->conn.conn);
}

static int client_dict_reconnect(struct client_dict *dict, const char *reason,
				 const char **error_r)
{
	ARRAY(struct client_dict_cmd *) retry_cmds;
	struct client_dict_cmd *cmd;
	const char *error;
	int ret;

	t_array_init(&retry_cmds, array_count(&dict->cmds));
	for (unsigned int i = 0; i < array_count(&dict->cmds); ) {
		cmd = array_idx_elem(&dict->cmds, i);
		if (!cmd->retry_errors) {
			i++;
		} else if (cmd->iter != NULL &&
			   cmd->iter->seen_results) {
			/* don't retry iteration that already returned
			   something to the caller. otherwise we'd return
			   duplicates. */
			i++;
		} else {
			array_push_back(&retry_cmds, &cmd);
			/* timeout is added back after reconnecting */
			timeout_remove(&cmd->to_request);
			array_delete(&dict->cmds, i, 1);
		}
	}
	client_dict_disconnect(dict, reason);
	if (client_dict_connect(dict, error_r) < 0) {
		reason = t_strdup_printf("%s - reconnect failed: %s",
					 reason, *error_r);
		array_foreach_elem(&retry_cmds, cmd) {
			dict_cmd_callback_error(cmd, reason, TRUE);
			client_dict_cmd_unref(cmd);
		}
		return -1;
	}
	if (array_count(&retry_cmds) == 0)
		return 0;
	e_warning(dict->conn.conn.event, "%s - reconnected", reason);

	ret = 0; error = "";
	array_foreach_elem(&retry_cmds, cmd) {
		cmd->reconnected = TRUE;
		cmd->async_id = 0;
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
	struct dict_client_connection *conn =
		(struct dict_client_connection *)_conn;

	client_dict_disconnect(conn->dict, connection_disconnect_reason(_conn));
}

static const struct connection_settings dict_conn_set = {
	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX,
	.unix_client_connect_msecs = 1000,
	.client = TRUE
};

static const struct connection_vfuncs dict_conn_vfuncs = {
	.destroy = dict_conn_destroy,
	.input_line = dict_conn_input_line
};

static int
client_dict_init(const struct dict *dict_driver, struct event *event,
		 struct dict **dict_r, const char **error_r)
{
	struct dict_proxy_settings *set;

	if (settings_get(event, &dict_proxy_setting_parser_info,
			 0, &set, error_r) < 0)
		return -1;
	if (set->dict_proxy_name[0] == '\0') {
		*error_r = "dict_proxy_name setting is empty";
		settings_free(set);
		return -1;
	}
	const struct master_service_settings *master_set =
		master_service_get_service_settings(master_service);

	struct ioloop *old_ioloop = current_ioloop;
	struct client_dict *dict;
	const char *path;

	if (dict_connections == NULL) {
		dict_connections = connection_list_init(&dict_conn_set,
							&dict_conn_vfuncs);
	}

	dict = i_new(struct client_dict, 1);
	dict->dict = *dict_driver;
	dict->conn.dict = dict;
	dict->conn.conn.event_parent = event;
	dict->set = set;
	i_array_init(&dict->cmds, 32);

	if (set->dict_proxy_socket_path[0] == '/') {
		/* absolute path */
		path = set->dict_proxy_socket_path;
	} else {
		/* relative path to base_dir */
		path = t_strconcat(master_set->base_dir, "/",
			set->dict_proxy_socket_path, NULL);
	}
	connection_init_client_unix(dict_connections, &dict->conn.conn, path);

	dict->dict.ioloop = io_loop_create();
	dict->wait_timer = io_wait_timer_add();
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
	io_wait_timer_remove(&dict->wait_timer);

	i_assert(dict->transactions == NULL);
	i_assert(array_count(&dict->cmds) == 0);

	io_loop_set_current(dict->dict.ioloop);
	io_loop_destroy(&dict->dict.ioloop);
	io_loop_set_current(old_ioloop);

	array_free(&dict->cmds);
	i_free(dict->last_connect_error);
	settings_free(dict->set);
	i_free(dict);

	if (dict_connections->connections == NULL)
		connection_list_deinit(&dict_connections);
}

static void client_dict_wait(struct dict *_dict)
{
	struct client_dict *dict = (struct client_dict *)_dict;

	if (array_count(&dict->cmds) == 0)
		return;

	i_assert(io_loop_is_empty(dict->dict.ioloop));
	dict->dict.prev_ioloop = current_ioloop;
	io_loop_set_current(dict->dict.ioloop);
	dict_switch_ioloop(_dict);
	while (array_count(&dict->cmds) > 0)
		io_loop_run(dict->dict.ioloop);

	io_loop_set_current(dict->dict.prev_ioloop);
	dict->dict.prev_ioloop = NULL;

	dict_switch_ioloop(_dict);
	i_assert(io_loop_is_empty(dict->dict.ioloop));
}

static bool client_dict_switch_ioloop(struct dict *_dict)
{
	struct client_dict *dict = (struct client_dict *)_dict;

	dict->last_timer_switch_usecs =
		io_wait_timer_get_usecs(dict->wait_timer);
	dict->wait_timer = io_wait_timer_move(&dict->wait_timer);
	if (dict->to_idle != NULL)
		dict->to_idle = io_loop_move_timeout(&dict->to_idle);

	struct client_dict_cmd *cmd;
	array_foreach_elem(&dict->cmds, cmd) {
		if (cmd->to_request != NULL) {
			cmd->to_request =
				io_loop_move_timeout(&cmd->to_request);
		}
	}

	connection_switch_ioloop(&dict->conn.conn);
	return array_count(&dict->cmds) > 0;
}

static const char *dict_wait_warnings(const struct client_dict_cmd *cmd)
{
	int global_ioloop_msecs = (ioloop_global_wait_usecs -
				   cmd->start_global_ioloop_usecs + 999) / 1000;
	int dict_ioloop_msecs = (io_wait_timer_get_usecs(cmd->dict->wait_timer) -
				 cmd->start_dict_ioloop_usecs + 999) / 1000;
	int other_ioloop_msecs = global_ioloop_msecs - dict_ioloop_msecs;
	int lock_msecs = (file_lock_wait_get_total_usecs() -
			  cmd->start_lock_usecs + 999) / 1000;

	return t_strdup_printf(
		"%d.%03d in dict wait, %d.%03d in other ioloops, %d.%03d in locks",
		dict_ioloop_msecs/1000, dict_ioloop_msecs%1000,
		other_ioloop_msecs/1000, other_ioloop_msecs%1000,
		lock_msecs/1000, lock_msecs%1000);
}

static const char *
dict_warnings_sec(const struct client_dict_cmd *cmd, long long msecs,
		  const char *const *extra_args)
{
	string_t *str = t_str_new(64);
	struct timeval tv_start, tv_end;
	unsigned int tv_start_usec, tv_end_usec;

	str_printfa(str, "%lld.%03lld secs (%s", msecs/1000, msecs%1000,
		    dict_wait_warnings(cmd));
	if (cmd->reconnected) {
		long long reconnected_msecs =
			timeval_diff_msecs(&ioloop_timeval,
				&cmd->dict->conn.conn.connect_started);
		str_printfa(str, ", reconnected %lld.%03lld secs ago",
			    reconnected_msecs/1000, reconnected_msecs%1000);
	}
	if (cmd->async_id != 0) {
		long long async_reply_msecs =
			timeval_diff_msecs(&ioloop_timeval, &cmd->async_id_received_time);
		str_printfa(str, ", async-id reply %lld.%03lld secs ago",
			    async_reply_msecs/1000, async_reply_msecs%1000);
	}
	if (extra_args != NULL &&
	    str_array_length(extra_args) >= 4 &&
	    str_to_time(extra_args[0], &tv_start.tv_sec) == 0 &&
	    str_to_uint(extra_args[1], &tv_start_usec) == 0 &&
	    str_to_time(extra_args[2], &tv_end.tv_sec) == 0 &&
	    str_to_uint(extra_args[3], &tv_end_usec) == 0) {
		tv_start.tv_usec = tv_start_usec;
		tv_end.tv_usec = tv_end_usec;

		long long server_msecs_since_start =
			timeval_diff_msecs(&ioloop_timeval, &tv_start);
		long long server_msecs = timeval_diff_msecs(&tv_end, &tv_start);
		str_printfa(str, ", started on dict-server %lld.%03lld secs ago, "
			    "took %lld.%03lld secs",
			    server_msecs_since_start/1000,
			    server_msecs_since_start%1000,
			    server_msecs/1000, server_msecs%1000);
	}
	str_append_c(str, ')');
	return str_c(str);
}

static void
client_dict_lookup_async_callback(struct client_dict_cmd *cmd,
				  enum dict_protocol_reply reply,
				  const char *value,
				  const char *const *extra_args,
				  const char *error,
				  bool disconnected ATTR_UNUSED)
{
	struct client_dict *dict = cmd->dict;
	struct dict_lookup_result result;
	const char *const values[] = { value, NULL };

	i_zero(&result);
	if (error != NULL) {
		result.ret = -1;
		result.error = error;
	} else switch (reply) {
	case DICT_PROTOCOL_REPLY_OK:
		result.value = value;
		result.values = values;
		result.ret = 1;
		break;
	case DICT_PROTOCOL_REPLY_MULTI_OK:
		result.values = t_strsplit_tabescaped(value);
		result.value = result.values[0];
		result.ret = 1;
		break;
	case DICT_PROTOCOL_REPLY_NOTFOUND:
		result.ret = 0;
		break;
	case DICT_PROTOCOL_REPLY_FAIL:
		result.error = value[0] == '\0' ? "dict-server returned failure" :
			t_strdup_printf("dict-server returned failure: %s",
			value);
		result.ret = -1;
		break;
	default:
		result.error = t_strdup_printf(
			"dict-client: Invalid lookup '%s' reply: %c%s",
			cmd->query, reply, value);
		/* This is already the command's callback being called.
		   Make sure it is not called again by
		   dict_cmd_callback_error() */
		cmd->callback = NULL;
		client_dict_disconnect(dict, result.error);
		result.ret = -1;
		break;
	}

	long long diff = timeval_diff_msecs(&ioloop_timeval, &cmd->start_time);
	if (result.error != NULL) {
		/* include timing info always in error messages */
		result.error = t_strdup_printf("%s (reply took %s)",
			result.error, dict_warnings_sec(cmd, diff, extra_args));
	} else if (!cmd->background &&
		   diff >= (int)dict->set->dict_proxy_slow_warn) {
		e_warning(dict->conn.conn.event, "dict lookup took %s: %s",
			  dict_warnings_sec(cmd, diff, extra_args),
			  cmd->query);
	}

	dict_pre_api_callback(&dict->dict);
	cmd->api_callback.lookup(&result, cmd->api_callback.context);
	dict_post_api_callback(&dict->dict);
}

static void
client_dict_lookup_async(struct dict *_dict, const struct dict_op_settings *set,
			 const char *key, dict_lookup_callback_t *callback,
			 void *context)
{
	struct client_dict *dict = (struct client_dict *)_dict;
	struct client_dict_cmd *cmd;
	const char *query;

	query = t_strdup_printf("%c%s\t%s", DICT_PROTOCOL_CMD_LOOKUP,
				str_tabescape(key),
				set->username == NULL ? "" : str_tabescape(set->username));
	cmd = client_dict_cmd_init(dict, query);
	cmd->callback = client_dict_lookup_async_callback;
	cmd->api_callback.lookup = callback;
	cmd->api_callback.context = context;
	cmd->retry_errors = TRUE;

	client_dict_cmd_send(dict, &cmd, NULL);
}

struct client_dict_sync_lookup {
	char *error;
	const char **values;
	int ret;
};

static void client_dict_lookup_callback(const struct dict_lookup_result *result,
					struct client_dict_sync_lookup *lookup)
{
	lookup->ret = result->ret;
	if (result->ret == -1)
		lookup->error = i_strdup(result->error);
	else if (result->ret == 1) {
		/* The caller's pool could point to data stack. We can't
		   allocate from there, since we're in a different data stack
		   frame. */
		lookup->values = p_strarray_dup(default_pool, result->values);
	}
}

static int client_dict_lookup(struct dict *_dict,
			      const struct dict_op_settings *set,
			      pool_t pool, const char *key,
			      const char *const **values_r,
			      const char **error_r)
{
	struct client_dict_sync_lookup lookup;

	i_zero(&lookup);
	lookup.ret = -2;

	dict_lookup_async(_dict, set, key, client_dict_lookup_callback, &lookup);
	if (lookup.ret == -2)
		client_dict_wait(_dict);

	switch (lookup.ret) {
	case -1:
		*error_r = t_strdup(lookup.error);
		i_free(lookup.error);
		return -1;
	case 0:
		i_assert(lookup.values == NULL);
		return 0;
	case 1:
		*values_r = p_strarray_dup(pool, lookup.values);
		i_free(lookup.values);
		return 1;
	}
	i_unreached();
}

static void client_dict_iterate_unref(struct client_dict_iterate_context *ctx)
{
	i_assert(ctx->refcount > 0);
	if (--ctx->refcount > 0)
		return;
	i_free(ctx->error);
	i_free(ctx);
}

static void
client_dict_iter_api_callback(struct client_dict_iterate_context *ctx,
			      struct client_dict_cmd *cmd,
			      const char *const *extra_args)
{
	struct client_dict *dict = cmd->dict;

	if (ctx->deinit) {
		/* Iterator was already deinitialized. Stop if we're in
		   client_dict_wait(). */
		dict_post_api_callback(&dict->dict);
		return;
	}
	if (ctx->finished) {
		long long diff = timeval_diff_msecs(&ioloop_timeval,
						    &cmd->start_time);
		if (ctx->error != NULL) {
			/* include timing info always in error messages */
			char *new_error = i_strdup_printf("%s (reply took %s)",
				ctx->error, dict_warnings_sec(cmd, diff, extra_args));
			i_free(ctx->error);
			ctx->error = new_error;
		} else if (!cmd->background &&
			   diff >= (int)dict->set->dict_proxy_slow_warn) {
			e_warning(dict->conn.conn.event, "dict iteration took %s: %s",
				  dict_warnings_sec(cmd, diff, extra_args),
				  cmd->query);
		}
	}
	if (ctx->ctx.async_callback == NULL) {
		/* synchronous lookup */
		io_loop_stop(dict->dict.ioloop);
	} else if (ctx->iterating) {
		/* We're already in client_dict_iterate(). Don't call the
		   async callback, because it would just recurse and possibly
		   break. */
	} else {
		dict_pre_api_callback(&dict->dict);
		ctx->ctx.async_callback(ctx->ctx.async_context);
		dict_post_api_callback(&dict->dict);
	}
}

static void
client_dict_iter_async_callback(struct client_dict_cmd *cmd,
				enum dict_protocol_reply reply,
				const char *value,
				const char *const *extra_args,
				const char *error,
				bool disconnected ATTR_UNUSED)
{
	struct client_dict_iterate_context *ctx = cmd->iter;
	struct client_dict *dict = cmd->dict;
	struct client_dict_iter_result *result;
	const char *iter_key = NULL, *const *iter_values = NULL;

	if (ctx->deinit)
		cmd->background = TRUE;

	if (error != NULL) {
		/* failed */
	} else switch (reply) {
	case DICT_PROTOCOL_REPLY_ITER_FINISHED:
		/* end of iteration */
		i_assert(!ctx->finished);
		ctx->finished = TRUE;
		client_dict_iter_api_callback(ctx, cmd, extra_args);
		client_dict_iterate_unref(ctx);
		return;
	case DICT_PROTOCOL_REPLY_OK:
		/* key \t value */
		iter_key = value;
		iter_values = extra_args;
		extra_args++;
		break;
	case DICT_PROTOCOL_REPLY_FAIL:
		error = t_strdup_printf("dict-server returned failure: %s", value);
		break;
	default:
		break;
	}
	if ((iter_values == NULL || iter_values[0] == NULL) && error == NULL) {
		/* broken protocol */
		error = t_strdup_printf("dict client (%s) sent broken iterate reply: %c%s",
			dict->conn.conn.name, reply, value);
		/* disconnection finishes the command */
		client_dict_disconnect(dict, error);
		return;
	}

	if (error != NULL) {
		if (ctx->error == NULL)
			ctx->error = i_strdup(error);
		i_assert(!ctx->finished);
		ctx->finished = TRUE;
		client_dict_iter_api_callback(ctx, cmd, extra_args);
		client_dict_iterate_unref(ctx);
		return;
	}
	cmd->unfinished = TRUE;

	if (ctx->deinit) {
		/* iterator was already deinitialized */
		return;
	}

	result = array_append_space(&ctx->results);
	result->key = p_strdup(ctx->results_pool, iter_key);
	result->values = p_strarray_dup(ctx->results_pool, iter_values);

	client_dict_iter_api_callback(ctx, cmd, NULL);
}

static struct dict_iterate_context *
client_dict_iterate_init(struct dict *_dict,
			 const struct dict_op_settings *set ATTR_UNUSED,
			 const char *path, enum dict_iterate_flags flags)
{
        struct client_dict_iterate_context *ctx;

	ctx = i_new(struct client_dict_iterate_context, 1);
	ctx->ctx.dict = _dict;
	ctx->results_pool = pool_alloconly_create("client dict iteration", 512);
	ctx->flags = flags;
	ctx->path = i_strdup(path);
	ctx->refcount = 1;
	i_array_init(&ctx->results, 64);
	return &ctx->ctx;
}

static void
client_dict_iterate_cmd_send(struct client_dict_iterate_context *ctx)
{
	struct client_dict *dict = (struct client_dict *)ctx->ctx.dict;
	const struct dict_op_settings_private *set = &ctx->ctx.set;
	struct client_dict_cmd *cmd;
	string_t *query = t_str_new(256);

	/* we can't do this query in _iterate_init(), because
	   _set_limit() hasn't been called yet at that point. */
	str_printfa(query, "%c%d\t%"PRIu64, DICT_PROTOCOL_CMD_ITERATE,
		    ctx->flags, ctx->ctx.max_rows);
	str_append_c(query, '\t');
	str_append_tabescaped(query, ctx->path);
	str_append_c(query, '\t');
	str_append_tabescaped(query, set->username == NULL ? "" : set->username);

	cmd = client_dict_cmd_init(dict, str_c(query));
	cmd->iter = ctx;
	cmd->callback = client_dict_iter_async_callback;
	cmd->retry_errors = TRUE;

	ctx->refcount++;
	client_dict_cmd_send(dict, &cmd, NULL);
}

static bool client_dict_iterate(struct dict_iterate_context *_ctx,
				const char **key_r, const char *const **values_r)
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
		*values_r = results[ctx->result_idx].values;
		ctx->ctx.has_more = TRUE;
		ctx->result_idx++;
		ctx->seen_results = TRUE;
		return TRUE;
	}
	if (!ctx->cmd_sent) {
		ctx->cmd_sent = TRUE;
		ctx->iterating = TRUE;
		client_dict_iterate_cmd_send(ctx);
		ctx->iterating = FALSE;
		return client_dict_iterate(_ctx, key_r, values_r);
	}
	ctx->ctx.has_more = !ctx->finished;
	ctx->result_idx = 0;
	array_clear(&ctx->results);
	p_clear(ctx->results_pool);

	if ((ctx->flags & DICT_ITERATE_FLAG_ASYNC) == 0 && ctx->ctx.has_more) {
		client_dict_wait(_ctx->dict);
		return client_dict_iterate(_ctx, key_r, values_r);
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

	i_assert(!ctx->deinit);
	ctx->deinit = TRUE;

	*error_r = t_strdup(ctx->error);
	array_free(&ctx->results);
	pool_unref(&ctx->results_pool);
	i_free(ctx->path);
	client_dict_iterate_unref(ctx);

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
					enum dict_protocol_reply reply,
					const char *value,
					const char *const *extra_args,
					const char *error, bool disconnected)
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
	} else switch (reply) {
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
		/* value contains the obsolete trans_id */
		const char *error = extra_args[0];

		result.error = t_strdup_printf("dict-server returned failure: %s",
			error != NULL ? t_str_tabunescape(error) : "");
		if (error != NULL)
			extra_args++;
		break;
	}
	default:
		result.ret = DICT_COMMIT_RET_FAILED;
		result.error = t_strdup_printf(
			"dict-client: Invalid commit reply: %c%s",
			reply, value);
		/* This is already the command's callback being called.
		   Make sure it is not called again by
		   dict_cmd_callback_error() */
		cmd->callback = NULL;
		client_dict_disconnect(dict, result.error);
		break;
	}

	long long diff = timeval_diff_msecs(&ioloop_timeval, &cmd->start_time);
	if (result.error != NULL) {
		/* include timing info always in error messages */
		result.error = t_strdup_printf("%s (reply took %s)",
			result.error, dict_warnings_sec(cmd, diff, extra_args));
	} else if (!cmd->background && !cmd->trans->ctx.set.no_slowness_warning &&
		   diff >= (int)dict->set->dict_proxy_slow_warn) {
		e_warning(dict->conn.conn.event, "dict commit took %s: "
			  "%s (%u commands, first: %s)",
			  dict_warnings_sec(cmd, diff, extra_args),
			  cmd->query, cmd->trans->query_count,
			  cmd->trans->first_query);
	}
	client_dict_transaction_free(&cmd->trans);

	dict_pre_api_callback(&dict->dict);
	cmd->api_callback.commit(&result, cmd->api_callback.context);
	dict_post_api_callback(&dict->dict);
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

static void client_dict_set_timestamp(struct dict_transaction_context *_ctx,
				      const struct timespec *ts)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;
	const char *query;

	query = t_strdup_printf("%c%u\t%s\t%u",
				DICT_PROTOCOL_CMD_TIMESTAMP,
				ctx->id, dec2str(ts->tv_sec),
				(unsigned int)ts->tv_nsec);
	client_dict_send_transaction_query(ctx, query);
}

static void client_dict_set_hide_log_values(struct dict_transaction_context *_ctx,
					    bool hide_log_values)
{
       struct client_dict_transaction_context *ctx =
               container_of(_ctx, struct client_dict_transaction_context, ctx);
       const char *query;

       query = t_strdup_printf("%c%u\t%s",
                               DICT_PROTOCOL_CMD_HIDE_LOG_VALUES,
                               ctx->id,
                               hide_log_values ? "yes" : "no");

        client_dict_send_transaction_query(ctx, query);
}

struct dict dict_driver_client = {
	.name = "proxy",
	.flags = DICT_DRIVER_FLAG_SUPPORT_EXPIRE_SECS,
	.v = {
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
		.switch_ioloop = client_dict_switch_ioloop,
		.set_timestamp = client_dict_set_timestamp,
		.set_hide_log_values = client_dict_set_hide_log_values,
	}
};
