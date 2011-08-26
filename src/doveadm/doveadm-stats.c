/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "network.h"
#include "istream.h"
#include "str.h"
#include "strescape.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <unistd.h>

static const char *const*
read_next_line(struct istream *input)
{
	const char *line;
	char **args;
	unsigned int i;

	line = i_stream_read_next_line(input);
	if (line == NULL)
		return NULL;

	args = p_strsplit(pool_datastack_create(), line, "\t");
	for (i = 0; args[i] != NULL; i++)
		args[i] = str_tabunescape(args[i]);
	return (void *)args;
}

static void stats_lookup(const char *path)
{
#define TOP_CMD "EXPORT\tsession\tconnected\n"
	struct istream *input;
	const char *const *args;
	unsigned int i;
	int fd;

	fd = doveadm_connect(path);
	net_set_nonblock(fd, FALSE);

	input = i_stream_create_fd(fd, (size_t)-1, TRUE);
	if (write(fd, TOP_CMD, strlen(TOP_CMD)) < 0)
		i_fatal("write(%s) failed: %m", path);

	/* read header */
	args = read_next_line(input);
	if (args == NULL)
		i_fatal("read(%s) unexpectedly disconnected", path);
	for (; *args != NULL; args++)
		doveadm_print_header_simple(*args);

	/* read lines */
	do {
		T_BEGIN {
			args = read_next_line(input);
			if (args[0] == NULL)
				args = NULL;
			if (args != NULL) {
				for (i = 0; args[i] != NULL; i++)
					doveadm_print(args[i]);
			}
		} T_END;
	} while (args != NULL);
	if (input->stream_errno != 0)
		i_fatal("read(%s) failed: %m", path);
	i_stream_destroy(&input);
}

static void cmd_stats_top(int argc, char *argv[])
{
	const char *path;
	int c;

	path = t_strconcat(doveadm_settings->base_dir, "/stats", NULL);

	while ((c = getopt(argc, argv, "s:")) > 0) {
		switch (c) {
		case 's':
			path = optarg;
			break;
		default:
			help(&doveadm_cmd_stats);
		}
	}
	argv += optind - 1;
	if (argv[1] != NULL)
		help(&doveadm_cmd_stats);

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	stats_lookup(path);
}

struct doveadm_cmd doveadm_cmd_stats = {
	cmd_stats_top, "stats top", "[-s <stats socket path>]"
};
