/* Copyright (c) 2005-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "timing.h"
#include "time-util.h"
#include "dict-client.h"
#include "dict-settings.h"
#include "dict-connection.h"
#include "dict-commands.h"
#include "main.h"

#define DICT_OUTPUT_OPTIMAL_SIZE 1024

struct dict_cmd_func {
	enum dict_protocol_cmd cmd;
	int (*func)(struct dict_connection_cmd *cmd, const char *line);
};

struct dict_connection_cmd {
	const struct dict_cmd_func *cmd;
	struct dict_connection *conn;
	struct timeval start_timeval;
	char *reply;

	struct dict_iterate_context *iter;
	enum dict_iterate_flags iter_flags;

	unsigned int trans_id;
};

struct dict_command_stats cmd_stats;

static int cmd_iterate_flush(struct dict_connection_cmd *cmd);

static void dict_connection_cmd_output_more(struct dict_connection_cmd *cmd);

static void dict_connection_cmd_free(struct dict_connection_cmd *cmd)
{
	if (cmd->iter != NULL)
		(void)dict_iterate_deinit(&cmd->iter);
	i_free(cmd->reply);

	if (dict_connection_unref(cmd->conn))
		dict_connection_continue_input(cmd->conn);
	i_free(cmd);
}

static void dict_connection_cmd_remove(struct dict_connection_cmd *cmd)
{
	struct dict_connection_cmd *const *cmds;
	unsigned int i, count;

	cmds = array_get(&cmd->conn->cmds, &count);
	for (i = 0; i < count; i++) {
		if (cmds[i] == cmd) {
			array_delete(&cmd->conn->cmds, i, 1);
			dict_connection_cmd_free(cmd);
			return;
		}
	}
	i_unreached();
}

static void dict_connection_cmds_flush(struct dict_connection *conn)
{
	struct dict_connection_cmd *cmd, *const *first_cmdp;

	dict_connection_ref(conn);
	while (array_count(&conn->cmds) > 0) {
		first_cmdp = array_idx(&conn->cmds, 0);
		cmd = *first_cmdp;

		/* we may be able to start outputting iterations now. */
		if (cmd->iter != NULL)
			(void)cmd_iterate_flush(cmd);

		if (cmd->reply == NULL) {
			/* command not finished yet */
			break;
		}

		o_stream_nsend_str(conn->output, cmd->reply);
		dict_connection_cmd_remove(cmd);
	}
	dict_connection_unref_safe(conn);
}

static void
cmd_stats_update(struct dict_connection_cmd *cmd, struct timing *timing)
{
	long long diff;

	if (!dict_settings->verbose_proctitle)
		return;

	io_loop_time_refresh();
	diff = timeval_diff_usecs(&ioloop_timeval, &cmd->start_timeval);
	if (diff < 0)
		diff = 0;
	timing_add_usecs(timing, diff);
	dict_proctitle_update_later();
}

static void
cmd_lookup_callback(const struct dict_lookup_result *result, void *context)
{
	struct dict_connection_cmd *cmd = context;

	cmd_stats_update(cmd, cmd_stats.lookups);

	if (result->ret > 0) {
		cmd->reply = i_strdup_printf("%c%s\n",
			DICT_PROTOCOL_REPLY_OK, str_tabescape(result->value));
	} else if (result->ret == 0) {
		cmd->reply = i_strdup_printf("%c\n", DICT_PROTOCOL_REPLY_NOTFOUND);
	} else {
		i_error("%s", result->error);
		cmd->reply = i_strdup_printf("%c\n", DICT_PROTOCOL_REPLY_FAIL);
	}
	dict_connection_cmds_flush(cmd->conn);
}

static int cmd_lookup(struct dict_connection_cmd *cmd, const char *line)
{
	/* <key> */
	dict_lookup_async(cmd->conn->dict, line, cmd_lookup_callback, cmd);
	return 1;
}

static int cmd_iterate_flush(struct dict_connection_cmd *cmd)
{
	string_t *str;
	const char *key, *value;

	str = t_str_new(256);
	o_stream_cork(cmd->conn->output);
	while (dict_iterate(cmd->iter, &key, &value)) {
		str_truncate(str, 0);
		str_append_c(str, DICT_PROTOCOL_REPLY_OK);
		str_append_tabescaped(str, key);
		str_append_c(str, '\t');
		if ((cmd->iter_flags & DICT_ITERATE_FLAG_NO_VALUE) == 0)
			str_append_tabescaped(str, value);
		str_append_c(str, '\n');
		o_stream_nsend(cmd->conn->output, str_data(str), str_len(str));

		if (o_stream_get_buffer_used_size(cmd->conn->output) >
		    DICT_OUTPUT_OPTIMAL_SIZE) {
			if (o_stream_flush(cmd->conn->output) <= 0) {
				/* continue later when there's more space
				   in output buffer */
				o_stream_uncork(cmd->conn->output);
				o_stream_set_flush_pending(cmd->conn->output, TRUE);
				return 0;
			}
			/* flushed everything, continue */
		}
	}
	if (dict_iterate_has_more(cmd->iter)) {
		/* wait for the next iteration callback */
		return 0;
	}

	str_truncate(str, 0);
	if (dict_iterate_deinit(&cmd->iter) < 0)
		str_append_c(str, DICT_PROTOCOL_REPLY_FAIL);
	str_append_c(str, '\n');
	o_stream_uncork(cmd->conn->output);

	cmd_stats_update(cmd, cmd_stats.iterations);
	cmd->reply = i_strdup(str_c(str));
	return 1;
}

static void cmd_iterate_callback(void *context)
{
	struct dict_connection_cmd *cmd = context;

	dict_connection_cmd_output_more(cmd);
}

static int cmd_iterate(struct dict_connection_cmd *cmd, const char *line)
{
	const char *const *args;
	unsigned int flags;

	args = t_strsplit_tabescaped(line);
	if (str_array_length(args) < 2 ||
	    str_to_uint(args[0], &flags) < 0) {
		i_error("dict client: ITERATE: broken input");
		return -1;
	}

	/* <flags> <path> */
	flags |= DICT_ITERATE_FLAG_ASYNC;
	cmd->iter = dict_iterate_init_multiple(cmd->conn->dict, args+1, flags);
	cmd->iter_flags = flags;
	dict_iterate_set_async_callback(cmd->iter, cmd_iterate_callback, cmd);
	dict_connection_cmd_output_more(cmd);
	return 1;
}

static struct dict_connection_transaction *
dict_connection_transaction_lookup(struct dict_connection *conn,
				   unsigned int id)
{
	struct dict_connection_transaction *transaction;

	if (!array_is_created(&conn->transactions))
		return NULL;

	array_foreach_modifiable(&conn->transactions, transaction) {
		if (transaction->id == id)
			return transaction;
	}
	return NULL;
}

static void
dict_connection_transaction_array_remove(struct dict_connection *conn,
					 unsigned int id)
{
	const struct dict_connection_transaction *transactions;
	unsigned int i, count;

	transactions = array_get(&conn->transactions, &count);
	for (i = 0; i < count; i++) {
		if (transactions[i].id == id) {
			i_assert(transactions[i].ctx == NULL);
			array_delete(&conn->transactions, i, 1);
			return;
		}
	}
	i_unreached();
}

static int cmd_begin(struct dict_connection_cmd *cmd, const char *line)
{
	struct dict_connection_transaction *trans;
	unsigned int id;

	if (str_to_uint(line, &id) < 0) {
		i_error("dict client: Invalid transaction ID %s", line);
		return -1;
	}
	if (dict_connection_transaction_lookup(cmd->conn, id) != NULL) {
		i_error("dict client: Transaction ID %u already exists", id);
		return -1;
	}

	if (!array_is_created(&cmd->conn->transactions))
		i_array_init(&cmd->conn->transactions, 4);

	/* <id> */
	trans = array_append_space(&cmd->conn->transactions);
	trans->id = id;
	trans->conn = cmd->conn;
	trans->ctx = dict_transaction_begin(cmd->conn->dict);
	return 0;
}

static int
dict_connection_transaction_lookup_parse(struct dict_connection *conn,
					 const char *line,
					 struct dict_connection_transaction **trans_r)
{
	unsigned int id;

	if (str_to_uint(line, &id) < 0) {
		i_error("dict client: Invalid transaction ID %s", line);
		return -1;
	}
	*trans_r = dict_connection_transaction_lookup(conn, id);
	if (*trans_r == NULL) {
		i_error("dict client: Transaction ID %u doesn't exist", id);
		return -1;
	}
	return 0;
}

static void
cmd_commit_finish(struct dict_connection_cmd *cmd, int ret, bool async)
{
	char chr;

	cmd_stats_update(cmd, cmd_stats.commits);

	switch (ret) {
	case 1:
		chr = DICT_PROTOCOL_REPLY_OK;
		break;
	case 0:
		chr = DICT_PROTOCOL_REPLY_NOTFOUND;
		break;
	default:
		chr = DICT_PROTOCOL_REPLY_FAIL;
		break;
	}
	if (async) {
		cmd->reply = i_strdup_printf("%c%c%u\n",
			DICT_PROTOCOL_REPLY_ASYNC_COMMIT, chr, cmd->trans_id);
	} else {
		cmd->reply = i_strdup_printf("%c%u\n", chr, cmd->trans_id);
	}
	dict_connection_transaction_array_remove(cmd->conn, cmd->trans_id);
	dict_connection_cmds_flush(cmd->conn);
}

static void cmd_commit_callback(int ret, void *context)
{
	struct dict_connection_cmd *cmd = context;

	cmd_commit_finish(cmd, ret, FALSE);
}

static void cmd_commit_callback_async(int ret, void *context)
{
	struct dict_connection_cmd *cmd = context;

	cmd_commit_finish(cmd, ret, TRUE);
}

static int
cmd_commit(struct dict_connection_cmd *cmd, const char *line)
{
	struct dict_connection_transaction *trans;

	if (dict_connection_transaction_lookup_parse(cmd->conn, line, &trans) < 0)
		return -1;
	cmd->trans_id = trans->id;

	dict_transaction_commit_async(&trans->ctx, cmd_commit_callback, cmd);
	return 1;
}

static int
cmd_commit_async(struct dict_connection_cmd *cmd, const char *line)
{
	struct dict_connection_transaction *trans;

	if (dict_connection_transaction_lookup_parse(cmd->conn, line, &trans) < 0)
		return -1;
	cmd->trans_id = trans->id;

	dict_transaction_commit_async(&trans->ctx, cmd_commit_callback_async, cmd);
	return 1;
}

static int cmd_rollback(struct dict_connection_cmd *cmd, const char *line)
{
	struct dict_connection_transaction *trans;

	if (dict_connection_transaction_lookup_parse(cmd->conn, line, &trans) < 0)
		return -1;

	dict_transaction_rollback(&trans->ctx);
	dict_connection_transaction_array_remove(cmd->conn, trans->id);
	return 0;
}

static int cmd_set(struct dict_connection_cmd *cmd, const char *line)
{
	struct dict_connection_transaction *trans;
	const char *const *args;

	/* <id> <key> <value> */
	args = t_strsplit_tabescaped(line);
	if (str_array_length(args) != 3) {
		i_error("dict client: SET: broken input");
		return -1;
	}

	if (dict_connection_transaction_lookup_parse(cmd->conn, args[0], &trans) < 0)
		return -1;
        dict_set(trans->ctx, args[1], args[2]);
	return 0;
}

static int cmd_unset(struct dict_connection_cmd *cmd, const char *line)
{
	struct dict_connection_transaction *trans;
	const char *const *args;

	/* <id> <key> */
	args = t_strsplit_tabescaped(line);
	if (str_array_length(args) != 2) {
		i_error("dict client: UNSET: broken input");
		return -1;
	}

	if (dict_connection_transaction_lookup_parse(cmd->conn, args[0], &trans) < 0)
		return -1;
        dict_unset(trans->ctx, args[1]);
	return 0;
}

static int cmd_append(struct dict_connection_cmd *cmd, const char *line)
{
	struct dict_connection_transaction *trans;
	const char *const *args;

	/* <id> <key> <value> */
	args = t_strsplit_tabescaped(line);
	if (str_array_length(args) != 3) {
		i_error("dict client: APPEND: broken input");
		return -1;
	}

	if (dict_connection_transaction_lookup_parse(cmd->conn, args[0], &trans) < 0)
		return -1;

        dict_append(trans->ctx, args[1], args[2]);
	return 0;
}

static int cmd_atomic_inc(struct dict_connection_cmd *cmd, const char *line)
{
	struct dict_connection_transaction *trans;
	const char *const *args;
	long long diff;

	/* <id> <key> <diff> */
	args = t_strsplit_tabescaped(line);
	if (str_array_length(args) != 3 ||
	    str_to_llong(args[2], &diff) < 0) {
		i_error("dict client: ATOMIC_INC: broken input");
		return -1;
	}

	if (dict_connection_transaction_lookup_parse(cmd->conn, args[0], &trans) < 0)
		return -1;

        dict_atomic_inc(trans->ctx, args[1], diff);
	return 0;
}

static const struct dict_cmd_func cmds[] = {
	{ DICT_PROTOCOL_CMD_LOOKUP, cmd_lookup },
	{ DICT_PROTOCOL_CMD_ITERATE, cmd_iterate },
	{ DICT_PROTOCOL_CMD_BEGIN, cmd_begin },
	{ DICT_PROTOCOL_CMD_COMMIT, cmd_commit },
	{ DICT_PROTOCOL_CMD_COMMIT_ASYNC, cmd_commit_async },
	{ DICT_PROTOCOL_CMD_ROLLBACK, cmd_rollback },
	{ DICT_PROTOCOL_CMD_SET, cmd_set },
	{ DICT_PROTOCOL_CMD_UNSET, cmd_unset },
	{ DICT_PROTOCOL_CMD_APPEND, cmd_append },
	{ DICT_PROTOCOL_CMD_ATOMIC_INC, cmd_atomic_inc },

	{ 0, NULL }
};

static const struct dict_cmd_func *dict_command_find(enum dict_protocol_cmd cmd)
{
	unsigned int i;

	for (i = 0; cmds[i].cmd != '\0'; i++) {
		if (cmds[i].cmd == cmd)
			return &cmds[i];
	}
	return NULL;
}

int dict_command_input(struct dict_connection *conn, const char *line)
{
	const struct dict_cmd_func *cmd_func;
	struct dict_connection_cmd *cmd;
	int ret;

	cmd_func = dict_command_find((enum dict_protocol_cmd)*line);
	if (cmd_func == NULL) {
		i_error("dict client: Unknown command %c", *line);
		return -1;
	}

	cmd = i_new(struct dict_connection_cmd, 1);
	cmd->conn = conn;
	cmd->cmd = cmd_func;
	cmd->start_timeval = ioloop_timeval;
	array_append(&conn->cmds, &cmd, 1);
	dict_connection_ref(conn);
	if ((ret = cmd_func->func(cmd, line + 1)) <= 0) {
		dict_connection_cmd_remove(cmd);
		return ret;
	}
	return 0;
}

static void dict_connection_cmd_output_more(struct dict_connection_cmd *cmd)
{
	struct dict_connection_cmd *const *first_cmdp;
	
	first_cmdp = array_idx(&cmd->conn->cmds, 0);
	if (*first_cmdp == cmd) {
		if (cmd_iterate_flush(cmd) > 0)
			dict_connection_cmds_flush(cmd->conn);
	}
}

void dict_connection_cmds_output_more(struct dict_connection *conn)
{
	struct dict_connection_cmd *cmd, *const *first_cmdp;

	/* only iterators may be returning a lot of data */
	while (array_count(&conn->cmds) > 0) {
		first_cmdp = array_idx(&conn->cmds, 0);
		cmd = *first_cmdp;

		if (cmd->iter == NULL)
			break;

		if (cmd_iterate_flush(cmd) == 0) {
			/* unfinished */
			break;
		}
		dict_connection_cmds_flush(cmd->conn);
		/* cmd should be freed now */
	}
}

void dict_commands_init(void)
{
	cmd_stats.lookups = timing_init();
	cmd_stats.iterations = timing_init();
	cmd_stats.commits = timing_init();
}

void dict_commands_deinit(void)
{
	timing_deinit(&cmd_stats.lookups);
	timing_deinit(&cmd_stats.iterations);
	timing_deinit(&cmd_stats.commits);
}
