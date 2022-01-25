/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "connection.h"
#include "istream.h"
#include "ostream.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <unistd.h>

#define INDEXER_SOCKET_NAME "indexer"

static struct istream *indexer_send_cmd(const char *cmd)
{
	const char *path = t_strconcat(doveadm_settings->base_dir,
				       "/"INDEXER_SOCKET_NAME, NULL);
	const struct connection_settings set = {
		.service_name_out = "indexer-client",
		.service_name_in = "indexer-server",
		.major_version = 1,
		.minor_version = 0,
	};
	const char *error;
	struct istream *input;
	struct ostream *output;
	if (doveadm_blocking_connect(path, &set, &input, &output, &error) < 0)
		i_fatal("%s", error);
	o_stream_nsend_str(output, t_strconcat(cmd, "\r\n", NULL));
	if (o_stream_flush(output) < 0)
		i_fatal("write(indexer) failed: %s", o_stream_get_error(output));
	o_stream_unref(&output);
	return input;
}

static struct istream *
indexer_send_cmd_with_args(const char *cmd, const char *const *args)
{
	string_t *str = t_str_new(128);

	str_append(str, cmd);
	if (args != NULL) {
		for (unsigned int i = 0; args[i] != NULL; i++) {
			str_append_c(str, '\t');
			str_append_tabescaped(str, args[i]);
		}
	}
	return indexer_send_cmd(str_c(str));
}

static void cmd_indexer_add(struct doveadm_cmd_context *cctx)
{
	const char *user, *mailbox, *line;
	int64_t max_recent;
	bool head;

	if (!doveadm_cmd_param_bool(cctx, "head", &head))
		head = FALSE;
	if (!doveadm_cmd_param_int64(cctx, "max-recent", &max_recent))
		max_recent = 0;
	if (!doveadm_cmd_param_str(cctx, "user", &user) ||
	    !doveadm_cmd_param_str(cctx, "mailbox", &mailbox))
		help_ver2(&doveadm_cmd_indexer_add);

	const char *cmd = head ? "PREPEND" : "APPEND";
	const char *const args[] = {
		"0", user, mailbox, dec2str(max_recent),
		NULL
	};
	struct istream *input = indexer_send_cmd_with_args(cmd, args);

	alarm(5);
	if ((line = i_stream_read_next_line(input)) == NULL)
		i_fatal("read(indexer) failed: %s", i_stream_get_error(input));
	if (strcmp(line, "0\tOK") != 0)
		i_fatal("indexer: %s returned unexpected reply: %s", cmd, line);
	alarm(0);
	i_stream_destroy(&input);
}

static void cmd_indexer_remove(struct doveadm_cmd_context *cctx)
{
	const char *line, *user_mask, *mailbox_mask;

	if (!doveadm_cmd_param_str(cctx, "user-mask", &user_mask))
		help_ver2(&doveadm_cmd_indexer_remove);
	if (!doveadm_cmd_param_str(cctx, "mailbox-mask", &mailbox_mask))
		mailbox_mask = NULL;

	const char *const args[] = { "0", user_mask, mailbox_mask, NULL };
	struct istream *input = indexer_send_cmd_with_args("REMOVE", args);

	alarm(5);
	if ((line = i_stream_read_next_line(input)) == NULL)
		i_fatal("read(indexer) failed: %s", i_stream_get_error(input));
	if (strcmp(line, "0\tOK") != 0)
		i_fatal("indexer: REMOVE returned unexpected reply: %s", line);
	alarm(0);
	i_stream_destroy(&input);
}

static int cmd_indexer_list_print(const char *const *args)
{
	if (str_array_length(args) < 7)
		return -1;

	/* <tag> <username> <mailbox> <session-id> <max-recent-msgs> <type>
	   <flags> */
	doveadm_print(args[1]);
	doveadm_print(args[2]);
	doveadm_print(args[3]);
	doveadm_print(args[4]);
	switch (args[5][0]) {
	case 'i':
		doveadm_print("index");
		break;
	case 'o':
		doveadm_print("optimize");
		break;
	default:
		doveadm_print(args[5]);
		break;
	}
	if (args[6][0] != 'w')
		doveadm_print("queued");
	else if (args[6][1] == 'h')
		doveadm_print("working/head-queued");
	else if (args[6][1] == 't')
		doveadm_print("working/tail-queued");
	else
		doveadm_print("working");
	return 0;
}

static void cmd_indexer_list(struct doveadm_cmd_context *cctx)
{
	const char *line, *user_mask;

	if (!doveadm_cmd_param_str(cctx, "user-mask", &user_mask))
		user_mask = NULL;

	const char *const args[] = { "0", "all", user_mask, NULL };
	struct istream *input = indexer_send_cmd_with_args("LIST", args);

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header_simple("username");
	doveadm_print_header_simple("mailbox");
	doveadm_print_header_simple("session_id");
	doveadm_print_header_simple("max_recent");
	doveadm_print_header_simple("type");
	doveadm_print_header_simple("status");

	alarm(30);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		if (strcmp(line, "0") == 0)
			break;
		T_BEGIN {
			const char *const *args = t_strsplit_tabescaped(line);
			if (cmd_indexer_list_print(args) < 0)
				i_fatal("Unexpected input: %s", line);
		} T_END;
	}
	if (line == NULL)
		i_fatal("read(indexer) failed: %s", i_stream_get_error(input));
	alarm(0);
	i_stream_destroy(&input);
}

struct doveadm_cmd_ver2 doveadm_cmd_indexer_add = {
	.cmd = cmd_indexer_add,
	.name = "indexer add",
	.usage = "[-h] [-n <max recent>] <user> <mailbox>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('h', "head", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('n', "max-recent", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "user", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_indexer_remove = {
	.cmd = cmd_indexer_remove,
	.name = "indexer remove",
	.usage = "<user mask> [<mailbox mask>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('\0', "user-mask", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "mailbox-mask", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_indexer_list = {
	.cmd = cmd_indexer_list,
	.name = "indexer list",
	.usage = "[<user mask>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('\0', "user-mask", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
