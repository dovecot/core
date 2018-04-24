/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "istream.h"
#include "str.h"
#include "strescape.h"
#include "write-full.h"
#include "master-service.h"
#include "doveadm.h"
#include "doveadm-print.h"

#define DOVEADM_DUMP_DEFAULT_FIELDS \
	"count sum min max avg median %95"

static void dump_timing(const char *const **args, unsigned int fields_count)
{
	unsigned int i, args_count = str_array_length(*args);

	if (args_count > fields_count)
		args_count = fields_count;
	for (i = 0; i < args_count; i++)
		doveadm_print((*args)[i]);
	*args += args_count;
}

static void stats_dump(const char *path, const char *const *fields, bool reset)
{
	struct istream *input;
	string_t *cmd = t_str_new(128);
	unsigned int i, fields_count = str_array_length(fields);
	char *line;
	int fd;

	fd = doveadm_connect(path);
	net_set_nonblock(fd, FALSE);
	str_append(cmd, "VERSION\tstats-reader-client\t2\t0\n");
	str_append(cmd, reset ? "DUMP-RESET" : "DUMP");
	for (i = 0; i < fields_count; i++) {
		str_append_c(cmd, '\t');
		str_append_tabescaped(cmd, fields[i]);
	}
	str_append_c(cmd, '\n');
	if (write_full(fd, str_data(cmd), str_len(cmd)) < 0)
		i_fatal("write(%s) failed: %m", path);

	input = i_stream_create_fd_autoclose(&fd, (size_t)-1);
	if ((line = i_stream_read_next_line(input)) == NULL)
		i_fatal("%s: Failed to read VERSION line", path);
	else if (!version_string_verify(line, "stats-reader-server", 2)) {
		i_fatal_status(EX_PROTOCOL,
			"%s is not a compatible stats-reader socket", path);
	}

	doveadm_print_header_simple("metric_name");
	doveadm_print_header_simple("field");
	for (i = 0; i < fields_count; i++)
		doveadm_print_header_simple(fields[i]);

	while ((line = i_stream_read_next_line(input)) != NULL) {
		if (line[0] == '\0')
			break;
		T_BEGIN {
			const char *const *args =
				t_strsplit_tabescaped_inplace(line);

			const char *metric_name = args[0];
			doveadm_print(metric_name); args++;
			doveadm_print("duration");
			dump_timing(&args, fields_count);
			while (*args != NULL) {
				doveadm_print(metric_name);
				doveadm_print(*args); args++;
				dump_timing(&args, fields_count);
			}
		} T_END;
	}

	if (input->stream_errno != 0)
		i_fatal("read(%s) failed: %s", path, i_stream_get_error(input));
	i_stream_destroy(&input);
}

static void
doveadm_cmd_stats_dump(struct doveadm_cmd_context *cctx)
{
	const char *path, *fields;
	bool reset;

	if (!doveadm_cmd_param_str(cctx, "socket-path", &path))
		path = t_strconcat(doveadm_settings->base_dir, "/stats-reader", NULL);
	if (!doveadm_cmd_param_bool(cctx, "reset", &reset))
		reset = FALSE;

	if (!doveadm_cmd_param_str(cctx, "fields", &fields))
		fields = DOVEADM_DUMP_DEFAULT_FIELDS;

	doveadm_print_init(DOVEADM_PRINT_TYPE_TAB);
	stats_dump(path, t_strsplit_spaces(fields, ", "), reset);
	return;
}

struct doveadm_cmd_ver2 doveadm_cmd_stats_dump_ver2 = {
	.cmd = doveadm_cmd_stats_dump,
	.name = "stats dump",
	.usage = "[-s <stats socket path>] [-r] [-f <fields>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('s', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('r', "reset", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('f', "fields", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAMS_END
};
