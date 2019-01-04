/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "net.h"
#include "ioloop.h"
#include "istream.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "strescape.h"
#include "write-full.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <termios.h>

struct top_line {
	char *id;
	/* [headers_count] */
	const char **prev_values, **cur_values;

	bool flip:1;
};

struct top_context {
	const char *path;
	int fd;
	struct istream *input;
	const char *sort_type;

	char **headers;
	unsigned int headers_count;

	pool_t prev_pool, cur_pool;
	/* id => struct top_line. */
	HASH_TABLE(char *, struct top_line *) sessions;
	ARRAY(struct top_line *) lines;
	int (*lines_sort)(struct top_line *const *, struct top_line *const *);

	unsigned int last_update_idx, user_idx;
	unsigned int sort_idx1, sort_idx2;

	bool flip:1;
};

static struct top_context *sort_ctx = NULL;
static const char *disk_input_field = "disk_input";
static const char *disk_output_field = "disk_output";

static char **
p_read_next_line(pool_t pool, struct istream *input)
{
	const char *line;

	line = i_stream_read_next_line(input);
	if (line == NULL)
		return NULL;

	return p_strsplit_tabescaped(pool, line);
}

static const char *const*
read_next_line(struct istream *input)
{
	return (const void *)p_read_next_line(pool_datastack_create(), input);
}

static void stats_dump(const char *path, const char *cmd)
{
	struct istream *input;
	const char *const *args;
	unsigned int i;
	int fd;

	fd = doveadm_connect(path);
	net_set_nonblock(fd, FALSE);
	if (write_full(fd, cmd, strlen(cmd)) < 0)
		i_fatal("write(%s) failed: %m", path);

	input = i_stream_create_fd_autoclose(&fd, (size_t)-1);

	/* read header */
	args = read_next_line(input);
	if (args == NULL)
		i_fatal("read(%s) unexpectedly disconnected", path);
	if (*args == NULL)
		i_info("no statistics available");
	else {
		for (; *args != NULL; args++)
			doveadm_print_header_simple(*args);

		/* read lines */
		do {
			T_BEGIN {
				args = read_next_line(input);
				if (args != NULL && args[0] == NULL)
					args = NULL;
				if (args != NULL) {
					for (i = 0; args[i] != NULL; i++)
						doveadm_print(args[i]);
				}
			} T_END;
		} while (args != NULL);
	}
	if (input->stream_errno != 0)
		i_fatal("read(%s) failed: %s", path, i_stream_get_error(input));
	i_stream_destroy(&input);
}

static void
doveadm_cmd_stats_dump(struct doveadm_cmd_context* cctx)
{
	const char *path, *cmd;
	const char *args[3] = {0};

	if (!doveadm_cmd_param_str(cctx, "socket-path", &path))
		path = t_strconcat(doveadm_settings->base_dir, "/old-stats", NULL);

	if (!doveadm_cmd_param_str(cctx, "type", &args[0])) {
		i_error("Missing type parameter");
		doveadm_exit_code = EX_USAGE;
		return;
	}

	/* purely optional */
	if (!doveadm_cmd_param_str(cctx, "filter", &args[1]))
		args[1] = NULL;

	cmd = t_strdup_printf("EXPORT\t%s\n", t_strarray_join(args, "\t"));

	doveadm_print_init(DOVEADM_PRINT_TYPE_TAB);
	stats_dump(path, cmd);
	return;
}

static void
stats_line_set_prev_values(struct top_context *ctx,
			   const struct top_line *old_line,
			   struct top_line *line)
{
	const char **values;
	unsigned int i;

	if (old_line->prev_values == NULL ||
	    strcmp(old_line->cur_values[ctx->last_update_idx],
		   line->cur_values[ctx->last_update_idx]) != 0) {
		values = old_line->cur_values;
	} else {
		values = old_line->prev_values;
	}

	/* line hasn't been updated, keep old values */
	line->prev_values =
		p_new(ctx->cur_pool, const char *, ctx->headers_count);
	for (i = 0; i < ctx->headers_count; i++)
		line->prev_values[i] = p_strdup(ctx->cur_pool, values[i]);
}

static void stats_read(struct top_context *ctx)
{
	struct top_line *old_line, *line;
	unsigned int i;
	char **args;

	/* read lines */
	while ((args = p_read_next_line(ctx->cur_pool, ctx->input)) != NULL) {
		if (args[0] == NULL) {
			/* end of stats */
			return;
		}
		if (str_array_length((void *)args) != ctx->headers_count)
			i_fatal("read(%s): invalid stats line", ctx->path);

		line = p_new(ctx->cur_pool, struct top_line, 1);
		line->id = args[0];
		line->flip = ctx->flip;
		line->cur_values = p_new(ctx->cur_pool, const char *, ctx->headers_count);
		for (i = 0; i < ctx->headers_count; i++)
			line->cur_values[i] = args[i];

		old_line = hash_table_lookup(ctx->sessions, line->id);
		if (old_line != NULL) {
			stats_line_set_prev_values(ctx, old_line, line);
			array_push_back(&ctx->lines, &line);
		}
		hash_table_update(ctx->sessions, line->id, line);
	}

	if (ctx->input->stream_errno != 0) {
		i_fatal("read(%s) failed: %s", ctx->path,
			i_stream_get_error(ctx->input));
	}
	i_fatal("read(%s): unexpected EOF", ctx->path);
}

static void stats_drop_stale(struct top_context *ctx)
{
	struct hash_iterate_context *iter;
	char *id;
	struct top_line *line;

	iter = hash_table_iterate_init(ctx->sessions);
	while (hash_table_iterate(iter, ctx->sessions, &id, &line)) {
		if (line->flip != ctx->flip)
			hash_table_remove(ctx->sessions, id);
	}
	hash_table_iterate_deinit(&iter);
}

static int get_double(const char *str, double *num_r)
{
	char *p;

	*num_r = strtod(str, &p);
	return *p == '\0' ? 0 : -1;
}

static double sort_cpu_diff(const struct top_line *line)
{
	double prev, cur, diff, prev_time, cur_time, time_multiplier;

	if (get_double(line->prev_values[sort_ctx->last_update_idx], &prev_time) < 0 ||
	    get_double(line->cur_values[sort_ctx->last_update_idx], &cur_time) < 0)
		i_fatal("sorting: invalid last_update value");
	time_multiplier = (cur_time - prev_time) * 100;

	if (get_double(line->prev_values[sort_ctx->sort_idx1], &prev) < 0 ||
	    get_double(line->cur_values[sort_ctx->sort_idx1], &cur) < 0)
		i_fatal("sorting: not a double");

	diff = cur - prev;

	if (sort_ctx->sort_idx2 != 0) {
		if (get_double(line->prev_values[sort_ctx->sort_idx2], &prev) < 0 ||
		    get_double(line->cur_values[sort_ctx->sort_idx2], &cur) < 0)
			i_fatal("sorting: not a double");
		diff += cur - prev;
	}
	return diff * time_multiplier;
}

static int sort_cpu(struct top_line *const *l1, struct top_line *const *l2)
{
	double d1, d2;

	d1 = sort_cpu_diff(*l1);
	d2 = sort_cpu_diff(*l2);
	if (d1 < d2)
		return -1;
	if (d1 > d2)
		return 1;
	return strcmp((*l1)->cur_values[sort_ctx->user_idx],
		      (*l2)->cur_values[sort_ctx->user_idx]);
}

static double sort_num_diff(const struct top_line *line)
{
	uint64_t prev, cur, diff;

	if (str_to_uint64(line->prev_values[sort_ctx->sort_idx1], &prev) < 0 ||
	    str_to_uint64(line->cur_values[sort_ctx->sort_idx1], &cur) < 0)
		i_fatal("sorting: not a number");
	diff = cur - prev;

	if (sort_ctx->sort_idx2 != 0) {
		if (str_to_uint64(line->prev_values[sort_ctx->sort_idx2], &prev) < 0 ||
		    str_to_uint64(line->cur_values[sort_ctx->sort_idx2], &cur) < 0)
			i_fatal("sorting: not a number");
		diff += cur - prev;
	}
	return diff;
}

static int sort_num(struct top_line *const *l1, struct top_line *const *l2)
{
	uint64_t n1, n2;

	n1 = sort_num_diff(*l1);
	n2 = sort_num_diff(*l2);
	if (n1 < n2)
		return -1;
	if (n1 > n2)
		return 1;
	return strcmp((*l1)->cur_values[sort_ctx->user_idx],
		      (*l2)->cur_values[sort_ctx->user_idx]);
}

static bool
stats_header_find(struct top_context *ctx, const char *name,
		  unsigned int *idx_r)
{
	unsigned int i;

	for (i = 0; ctx->headers[i] != NULL; i++) {
		if (strcmp(ctx->headers[i], name) == 0) {
			*idx_r = i;
			return TRUE;
		}
	}
	return FALSE;
}

static void stats_top_get_sorting(struct top_context *ctx)
{
	if (stats_header_find(ctx, ctx->sort_type, &ctx->sort_idx1))
		return;

	if (strcmp(ctx->sort_type, "cpu") == 0) {
		if (!stats_header_find(ctx, "user_cpu", &ctx->sort_idx1) ||
		    !stats_header_find(ctx, "sys_cpu", &ctx->sort_idx2))
			i_fatal("cpu sort type is missing fields");
		return;
	}
	if (strcmp(ctx->sort_type, "disk") == 0) {
		if (!stats_header_find(ctx, disk_input_field, &ctx->sort_idx1) ||
		    !stats_header_find(ctx, disk_output_field, &ctx->sort_idx2))
			i_fatal("disk sort type is missing fields");
		return;
	}
	i_fatal("unknown sort type: %s", ctx->sort_type);
}

static bool stats_top_round(struct top_context *ctx)
{
#define TOP_CMD "EXPORT\tsession\tconnected\n"
	const char *const *args;
	pool_t tmp_pool;

	if (write_full(ctx->fd, TOP_CMD, strlen(TOP_CMD)) < 0)
		i_fatal("write(%s) failed: %m", ctx->path);

	/* read header */
	if (ctx->headers != NULL) {
		args = read_next_line(ctx->input);
		if (args == NULL)
			i_fatal("read(%s) unexpectedly disconnected", ctx->path);
		if (*args == NULL)
			return TRUE;
		if (str_array_length(args) != ctx->headers_count)
			i_fatal("headers changed");
	} else {
		ctx->headers = p_read_next_line(default_pool, ctx->input);
		if (ctx->headers == NULL)
			i_fatal("read(%s) unexpectedly disconnected", ctx->path);
		if (*ctx->headers == NULL) {
			i_free_and_null(ctx->headers);
			return FALSE;
		}
		ctx->headers_count = str_array_length((void *)ctx->headers);
		if (!stats_header_find(ctx, "last_update", &ctx->last_update_idx))
			i_fatal("last_update header missing");
		if (!stats_header_find(ctx, "user", &ctx->user_idx))
			i_fatal("user header missing");
		stats_top_get_sorting(ctx);
	}

	array_clear(&ctx->lines);
	p_clear(ctx->prev_pool);
	tmp_pool = ctx->prev_pool;
	ctx->prev_pool = ctx->cur_pool;
	ctx->cur_pool = tmp_pool;

	ctx->flip = !ctx->flip;
	stats_read(ctx);
	stats_drop_stale(ctx);

	sort_ctx = ctx;
	array_sort(&ctx->lines, *ctx->lines_sort);
	sort_ctx = NULL;
	return TRUE;
}

static void
stats_top_output_diff(struct top_context *ctx,
		      const struct top_line *line, unsigned int i)
{
	uint64_t prev_num, cur_num;
	double prev_double, cur_double, prev_time, cur_time;
	char numstr[MAX_INT_STRLEN];

	if (str_to_uint64(line->prev_values[i], &prev_num) == 0 &&
	    str_to_uint64(line->cur_values[i], &cur_num) == 0) {
		if (i_snprintf(numstr, sizeof(numstr), "%"PRIu64,
			       (cur_num - prev_num)) < 0)
			i_unreached();
		doveadm_print(numstr);
	} else if (get_double(line->prev_values[i], &prev_double) == 0 &&
		   get_double(line->cur_values[i], &cur_double) == 0 &&
		   get_double(line->prev_values[ctx->last_update_idx], &prev_time) == 0 &&
		   get_double(line->cur_values[ctx->last_update_idx], &cur_time) == 0) {
		/* %CPU */
		if (i_snprintf(numstr, sizeof(numstr), "%d",
			       (int)((cur_double - prev_double) *
				     (cur_time - prev_time) * 100)) < 0)
			i_unreached();
		doveadm_print(numstr);
	} else {
		doveadm_print(line->cur_values[i]);
	}
}

static void stats_top_output(struct top_context *ctx)
{
	static const char *names[] = {
		"user", "service", "user_cpu", "sys_cpu",
		"", ""
	};
	struct winsize ws;
	struct top_line *const *lines;
	unsigned int i, j, row, maxrow, count, indexes[N_ELEMENTS(names)];

	names[4] = disk_input_field;
	names[5] = disk_output_field;

	/* ANSI clear screen and move cursor to top of screen */
	printf("\x1b[2J\x1b[1;1H"); fflush(stdout);
	doveadm_print_deinit();
	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);

	doveadm_print_header("USER", "USER", DOVEADM_PRINT_HEADER_FLAG_EXPAND);
	doveadm_print_header_simple("SERVICE");
	doveadm_print_header_simple("%CPU");
	doveadm_print_header_simple("%SYS");
	doveadm_print_header_simple("DISKIN");
	doveadm_print_header_simple("DISKOUT");

	if (!stats_top_round(ctx)) {
		/* no connections yet */
		return;
	}

	for (i = 0; i < N_ELEMENTS(names); i++) {
		if (!stats_header_find(ctx, names[i], &indexes[i]))
			indexes[i] = UINT_MAX;
	}

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) < 0)
		ws.ws_row = 24;
	maxrow = ws.ws_row-1;

	lines = array_get(&ctx->lines, &count);
	for (i = 0, row = 1; row < maxrow && i < count; i++, row++) {
		for (j = 0; j < N_ELEMENTS(names); j++) {
			if (indexes[j] == UINT_MAX)
				doveadm_print("?");
			else
				stats_top_output_diff(ctx, lines[i], indexes[j]);
		}
	}
}

static void stats_top_start(struct top_context *ctx)
{
	struct timeout *to;

	stats_top_output(ctx);
	to = timeout_add(1000, stats_top_output, ctx);
	io_loop_run(current_ioloop);
	timeout_remove(&to);
}

static void stats_top(const char *path, const char *sort_type)
{
	struct top_context ctx;

	i_zero(&ctx);
	ctx.path = path;
	ctx.fd = doveadm_connect(path);
	ctx.prev_pool = pool_alloconly_create("stats top", 1024*16);
	ctx.cur_pool = pool_alloconly_create("stats top", 1024*16);
	i_array_init(&ctx.lines, 128);
	hash_table_create(&ctx.sessions, default_pool, 0, str_hash, strcmp);
	net_set_nonblock(ctx.fd, FALSE);

	ctx.input = i_stream_create_fd(ctx.fd, (size_t)-1);

	if (strstr(sort_type, "cpu") != NULL)
		ctx.lines_sort = sort_cpu;
	else
		ctx.lines_sort = sort_num;
	ctx.sort_type = sort_type;

	stats_top_start(&ctx);
	i_stream_destroy(&ctx.input);
	hash_table_destroy(&ctx.sessions);
	array_free(&ctx.lines);
	pool_unref(&ctx.prev_pool);
	pool_unref(&ctx.cur_pool);
	i_close_fd(&ctx.fd);
}

static void stats_reset(const char *path, const char **items ATTR_UNUSED)
{
	const char **ptr ATTR_UNUSED;
	int fd,ret;
	string_t *cmd;
	struct istream *input;
	const char *line;

	fd = doveadm_connect(path);
	net_set_nonblock(fd, FALSE);
	input = i_stream_create_fd(fd, (size_t)-1);

	cmd = t_str_new(10);
	str_append(cmd, "RESET");
/* XXX: Not supported yet.
	for(ptr = items; *ptr; ptr++)
	{
		str_append_c(cmd, '\t');
		str_append(cmd, *ptr);
	}
*/
	str_append_c(cmd, '\n');

	/* send command */
	ret = write_full(fd, str_c(cmd), str_len(cmd));

	if (ret < 0) {
		i_close_fd(&fd);
		i_error("write(%s) failed: %m", path);
		return;
	}

	line = i_stream_read_next_line(input);

	if (line == NULL) {
		i_error("read(%s) failed: %s", path, i_stream_get_error(input));
	} else if (!str_begins(line, "OK")) {
		i_error("%s",line);
	} else {
		i_info("Stats reset");
	}

	i_stream_destroy(&input);
	i_close_fd(&fd);
}

static void cmd_stats_top(int argc, char *argv[])
{
	const char *path, *sort_type;
	int c;

	path = t_strconcat(doveadm_settings->base_dir, "/old-stats", NULL);

	while ((c = getopt(argc, argv, "bs:")) > 0) {
		switch (c) {
		case 'b':
			disk_input_field = "read_bytes";
			disk_output_field = "write_bytes";
			break;
		case 's':
			path = optarg;
			break;
		default:
			help_ver2(&doveadm_cmd_oldstats_top_ver2);
		}
	}
	argv += optind - 1;
	if (argv[1] == NULL)
		sort_type = "disk";
	else if (argv[2] != NULL)
		help_ver2(&doveadm_cmd_oldstats_top_ver2);
	else
		sort_type = argv[1];

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	stats_top(path, sort_type);
}

static void cmd_stats_reset(int argc, char *argv[])
{
	const char *path;
	int c;

	path = t_strconcat(doveadm_settings->base_dir, "/old-stats", NULL);
	while((c = getopt(argc, argv, "s:")) > 0) {
		switch (c) {
		case 's':
			path = optarg;
			break;
		default:
			help_ver2(&doveadm_cmd_oldstats_reset_ver2);
		}
	}
	argv += optind - 1;
	/* items is now argv */
/*	if (optind >= argc) {
		i_fatal("missing item(s) to reset");
	}
*/
	stats_reset(path, (const char**)argv);
}

struct doveadm_cmd_ver2 doveadm_cmd_oldstats_dump_ver2 = {
	.cmd = doveadm_cmd_stats_dump,
	.name = "oldstats dump",
	.usage = "[-s <stats socket path>] <type> [<filter>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('s', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "type", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "filter", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_oldstats_top_ver2 = {
	.old_cmd = cmd_stats_top,
	.name = "oldstats top",
	.usage = "[-s <stats socket path>] [-b] [<sort field>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('s', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('b', "show-disk-io", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "field", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};


struct doveadm_cmd_ver2 doveadm_cmd_oldstats_reset_ver2 = {
	.old_cmd = cmd_stats_reset,
	.name = "oldstats reset",
	.usage = "[-s <stats socket path>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('s', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAMS_END
};
