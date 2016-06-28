/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "write-full.h"
#include "istream.h"
#include "doveadm.h"

#include <unistd.h>

static void cmd_service_stop(int argc, char *argv[])
{
	const char *path, *line;
	int fd;

	if (argc == 1)
		help_ver2(&doveadm_cmd_service_stop_ver2);

	path = t_strconcat(doveadm_settings->base_dir, "/master", NULL);
	fd = net_connect_unix(path);
	if (fd == -1)
		i_fatal("net_connect_unix(%s) failed: %m", path);
	net_set_nonblock(fd, FALSE);

	string_t *cmd = t_str_new(128);
	str_append(cmd, "VERSION\tmaster-client\t1\t0\nSTOP");
	for (int i = 1; i < argc; i++) {
		str_append_c(cmd, '\t');
		str_append(cmd, argv[i]);
	}
	str_append_c(cmd, '\n');
	if (write_full(fd, str_data(cmd), str_len(cmd)) < 0)
		i_error("write(%s) failed: %m", path);

	alarm(5);
	struct istream *input = i_stream_create_fd(fd, IO_BLOCK_SIZE);
	if (i_stream_read_next_line(input) == NULL ||
	    (line = i_stream_read_next_line(input)) == NULL) {
		i_error("read(%s) failed: %s", path, i_stream_get_error(input));
		doveadm_exit_code = EX_TEMPFAIL;
	} else if (line[0] == '-') {
		doveadm_exit_code = DOVEADM_EX_NOTFOUND;
		i_error("%s", line+1);
	} else if (line[0] != '+') {
		i_error("Unexpected input from %s: %s", path, line);
		doveadm_exit_code = EX_TEMPFAIL;
	}
	alarm(0);
	i_stream_destroy(&input);
	i_close_fd(&fd);
}

struct doveadm_cmd_ver2 doveadm_cmd_service_stop_ver2 = {
	.old_cmd = cmd_service_stop,
	.name = "service stop",
	.usage = "<service> [<service> [...]]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('\0', "service", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
