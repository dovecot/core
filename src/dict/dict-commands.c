/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ostream.h"
#include "str.h"
#include "dict-client.h"
#include "dict-settings.h"
#include "dict-connection.h"
#include "dict-commands.h"

#include <stdlib.h>

#define DICT_OUTPUT_OPTIMAL_SIZE 1024

struct dict_client_cmd {
	int cmd;
	int (*func)(struct dict_connection *conn, const char *line);
};

static int cmd_lookup(struct dict_connection *conn, const char *line)
{
	const char *reply;
	const char *value;
	int ret;

	if (conn->iter_ctx != NULL) {
		i_error("dict client: LOOKUP: Can't lookup while iterating");
		return -1;
	}

	/* <key> */
	ret = dict_lookup(conn->dict, pool_datastack_create(), line, &value);
	if (ret > 0) {
		reply = t_strdup_printf("%c%s\n",
					DICT_PROTOCOL_REPLY_OK, value);
		o_stream_send_str(conn->output, reply);
	} else {
		reply = t_strdup_printf("%c\n", ret == 0 ?
					DICT_PROTOCOL_REPLY_NOTFOUND :
					DICT_PROTOCOL_REPLY_FAIL);
		o_stream_send_str(conn->output, reply);
	}
	return 0;
}

static int cmd_iterate_flush(struct dict_connection *conn)
{
	string_t *str;
	const char *key, *value;

	str = t_str_new(256);
	o_stream_cork(conn->output);
	while (dict_iterate(conn->iter_ctx, &key, &value)) {
		str_truncate(str, 0);
		str_printfa(str, "%c%s\t%s\n", DICT_PROTOCOL_REPLY_OK,
			    key, value);
		o_stream_send(conn->output, str_data(str), str_len(str));

		if (o_stream_get_buffer_used_size(conn->output) >
		    DICT_OUTPUT_OPTIMAL_SIZE) {
			if (o_stream_flush(conn->output) <= 0) {
				/* continue later */
				o_stream_uncork(conn->output);
				return 0;
			}
			/* flushed everything, continue */
		}
	}

	/* finished iterating */
	o_stream_unset_flush_callback(conn->output);

	str_truncate(str, 0);
	if (dict_iterate_deinit(&conn->iter_ctx) < 0)
		str_append_c(str, DICT_PROTOCOL_REPLY_FAIL);
	str_append_c(str, '\n');
	o_stream_send(conn->output, str_data(str), str_len(str));
	o_stream_uncork(conn->output);
	return 1;
}

static int cmd_iterate(struct dict_connection *conn, const char *line)
{
	const char *const *args;
	unsigned int flags;

	if (conn->iter_ctx != NULL) {
		i_error("dict client: ITERATE: Already iterating");
		return -1;
	}

	args = t_strsplit(line, "\t");
	if (str_array_length(args) < 2 ||
	    str_to_uint(args[0], &flags) < 0) {
		i_error("dict client: ITERATE: broken input");
		return -1;
	}

	/* <flags> <path> */
	conn->iter_ctx = dict_iterate_init_multiple(conn->dict, args+1, flags);

	o_stream_set_flush_callback(conn->output, cmd_iterate_flush, conn);
	cmd_iterate_flush(conn);
	return 0;
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
					 struct dict_connection_transaction *trans)
{
	const struct dict_connection_transaction *transactions;
	unsigned int i, count;

	transactions = array_get(&conn->transactions, &count);
	for (i = 0; i < count; i++) {
		if (&transactions[i] == trans) {
			array_delete(&conn->transactions, i, 1);
			break;
		}
	}
}

static int cmd_begin(struct dict_connection *conn, const char *line)
{
	struct dict_connection_transaction *trans;
	unsigned int id;

	if (str_to_uint(line, &id) < 0) {
		i_error("dict client: Invalid transaction ID %s", line);
		return -1;
	}
	if (dict_connection_transaction_lookup(conn, id) != NULL) {
		i_error("dict client: Transaction ID %u already exists", id);
		return -1;
	}

	if (!array_is_created(&conn->transactions))
		i_array_init(&conn->transactions, 4);

	/* <id> */
	trans = array_append_space(&conn->transactions);
	trans->id = id;
	trans->conn = conn;
	trans->ctx = dict_transaction_begin(conn->dict);
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

static int cmd_commit(struct dict_connection *conn, const char *line)
{
	struct dict_connection_transaction *trans;
	char chr;
	int ret;

	if (conn->iter_ctx != NULL) {
		i_error("dict client: COMMIT: Can't commit while iterating");
		return -1;
	}

	if (dict_connection_transaction_lookup_parse(conn, line, &trans) < 0)
		return -1;

	ret = dict_transaction_commit(&trans->ctx);
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
	o_stream_send_str(conn->output, t_strdup_printf("%c\n", chr));
	dict_connection_transaction_array_remove(conn, trans);
	return 0;
}

static void cmd_commit_async_callback(int ret, void *context)
{
	struct dict_connection_transaction *trans = context;
	const char *reply;
	char chr;

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
	reply = t_strdup_printf("%c%c%u\n", DICT_PROTOCOL_REPLY_ASYNC_COMMIT,
				chr, trans->id);
	o_stream_send_str(trans->conn->output, reply);

	dict_connection_transaction_array_remove(trans->conn, trans);
}

static int
cmd_commit_async(struct dict_connection *conn, const char *line)
{
	struct dict_connection_transaction *trans;

	if (conn->iter_ctx != NULL) {
		i_error("dict client: COMMIT: Can't commit while iterating");
		return -1;
	}

	if (dict_connection_transaction_lookup_parse(conn, line, &trans) < 0)
		return -1;

	dict_transaction_commit_async(&trans->ctx, cmd_commit_async_callback,
				      trans);
	return 0;
}

static int cmd_rollback(struct dict_connection *conn, const char *line)
{
	struct dict_connection_transaction *trans;

	if (dict_connection_transaction_lookup_parse(conn, line, &trans) < 0)
		return -1;

	dict_transaction_rollback(&trans->ctx);
	dict_connection_transaction_array_remove(conn, trans);
	return 0;
}

static int cmd_set(struct dict_connection *conn, const char *line)
{
	struct dict_connection_transaction *trans;
	const char *const *args;

	/* <id> <key> <value> */
	args = t_strsplit(line, "\t");
	if (str_array_length(args) != 3) {
		i_error("dict client: SET: broken input");
		return -1;
	}

	if (dict_connection_transaction_lookup_parse(conn, args[0], &trans) < 0)
		return -1;

        dict_set(trans->ctx, args[1], args[2]);
	return 0;
}

static int cmd_unset(struct dict_connection *conn, const char *line)
{
	struct dict_connection_transaction *trans;
	const char *const *args;

	/* <id> <key> */
	args = t_strsplit(line, "\t");
	if (str_array_length(args) != 2) {
		i_error("dict client: UNSET: broken input");
		return -1;
	}

	if (dict_connection_transaction_lookup_parse(conn, args[0], &trans) < 0)
		return -1;

        dict_unset(trans->ctx, args[1]);
	return 0;
}

static int cmd_atomic_inc(struct dict_connection *conn, const char *line)
{
	struct dict_connection_transaction *trans;
	const char *const *args;
	long long diff;

	/* <id> <key> <diff> */
	args = t_strsplit(line, "\t");
	if (str_array_length(args) != 3 ||
	    str_to_llong(args[2], &diff) < 0) {
		i_error("dict client: ATOMIC_INC: broken input");
		return -1;
	}

	if (dict_connection_transaction_lookup_parse(conn, args[0], &trans) < 0)
		return -1;

        dict_atomic_inc(trans->ctx, args[1], diff);
	return 0;
}

static struct dict_client_cmd cmds[] = {
	{ DICT_PROTOCOL_CMD_LOOKUP, cmd_lookup },
	{ DICT_PROTOCOL_CMD_ITERATE, cmd_iterate },
	{ DICT_PROTOCOL_CMD_BEGIN, cmd_begin },
	{ DICT_PROTOCOL_CMD_COMMIT, cmd_commit },
	{ DICT_PROTOCOL_CMD_COMMIT_ASYNC, cmd_commit_async },
	{ DICT_PROTOCOL_CMD_ROLLBACK, cmd_rollback },
	{ DICT_PROTOCOL_CMD_SET, cmd_set },
	{ DICT_PROTOCOL_CMD_UNSET, cmd_unset },
	{ DICT_PROTOCOL_CMD_ATOMIC_INC, cmd_atomic_inc },

	{ 0, NULL }
};

static struct dict_client_cmd *dict_command_find(char cmd)
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
	struct dict_client_cmd *cmd;

	cmd = dict_command_find(*line);
	if (cmd == NULL) {
		i_error("dict client: Unknown command %c", *line);
		return -1;
	}

	return cmd->func(conn, line + 1);
}
