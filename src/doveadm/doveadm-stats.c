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
#include "stats-settings.h"

#include <math.h>

#define DOVEADM_DUMP_DEFAULT_FIELDS \
	"count sum min max avg median stddev %95"

#define ADD_NAME_PARAM "name"
#define ADD_DESCR_PARAM "description"
#define ADD_FIELDS_PARAM "fields"
#define ADD_GROUPBY_PARAM "group-by"
#define ADD_FILTER_PARAM "filter"
#define ADD_EXPORTER_PARAM "exporter"
#define ADD_EXPORTERINCL_PARAM "exporter-include"

enum doveadm_dump_field_type {
	DOVEADM_DUMP_FIELD_TYPE_PASSTHROUGH = 0,
	DOVEADM_DUMP_FIELD_TYPE_STDDEV,
};

struct stats_cmd_context {
	string_t *cmd;
	struct doveadm_cmd_context *cctx;
	struct istream *input;
	const char *path;
	void *data;
};

struct dump_data {
	const char **fields;
	unsigned int field_count;
	enum doveadm_dump_field_type *field_types;
};

struct stats_cmd_vfuncs {
	int (*build_cmd)(struct stats_cmd_context *ctx, const char **error_r);
	void (*process_response)(struct stats_cmd_context *ctx);
};

static int build_stats_dump_cmd(struct stats_cmd_context *ctx, const char **error_r);
static int build_stats_add_cmd(struct stats_cmd_context *ctx, const char **error_r);
static int build_stats_remove_cmd(struct stats_cmd_context *ctx, const char **error_r);

static void stats_dump_process_response(struct stats_cmd_context *ctx);
static void stats_modify_process_response(struct stats_cmd_context *ctx);

static void stats_send_cmd(struct stats_cmd_context *ctx);

static struct stats_cmd_vfuncs dump_vfuncs = {
	.build_cmd = build_stats_dump_cmd,
	.process_response = stats_dump_process_response
};

static struct stats_cmd_vfuncs add_vfuncs = {
	.build_cmd = build_stats_add_cmd,
	.process_response = stats_modify_process_response
};

static struct stats_cmd_vfuncs remove_vfuncs = {
	.build_cmd = build_stats_remove_cmd,
	.process_response = stats_modify_process_response
};

static string_t *init_stats_cmd(void)
{
	string_t *cmd = t_str_new(128);
	str_append(cmd, "VERSION\tstats-reader-client\t2\t0\n");
	return cmd;
}

static void stats_exec_cmd(struct doveadm_cmd_context *cctx,
			   struct stats_cmd_vfuncs *vfuncs)
{
	struct stats_cmd_context ctx;
	const char *build_cmd_error;
	ctx.cctx = cctx;
	if (vfuncs->build_cmd(&ctx, &build_cmd_error) < 0) {
		i_error("%s", build_cmd_error);
		return;
	}
	stats_send_cmd(&ctx);
	vfuncs->process_response(&ctx);
	i_stream_destroy(&ctx.input);
}

static void handle_disconnection(struct stats_cmd_context *ctx)
{
	i_error("read(%s) failed: %s", ctx->path,
		i_stream_get_disconnect_reason(ctx->input));
}

static void stats_send_cmd(struct stats_cmd_context *ctx)
{
	int fd;
	const char *line;
	if (!doveadm_cmd_param_str(ctx->cctx, "socket-path", &ctx->path))
		ctx->path = t_strconcat(doveadm_settings->base_dir,
					"/stats-reader", NULL);

	fd = doveadm_connect(ctx->path);
	net_set_nonblock(fd, FALSE);
	if (write_full(fd, str_data(ctx->cmd), str_len(ctx->cmd)) < 0)
		i_fatal("write(%s) failed %m", ctx->path);
	ctx->input = i_stream_create_fd_autoclose(&fd, SIZE_MAX);

	if ((line = i_stream_read_next_line(ctx->input)) == NULL)
		i_fatal("%s: Failed to read VERSION line", ctx->path);
	else if (!version_string_verify(line, "stats-reader-server", 2)) {
		i_fatal_status(EX_PROTOCOL,
			"%s is not a compatible stats-reader socket", ctx->path);
	}
}

static void dump_timing(const char *const **args,
			const enum doveadm_dump_field_type field_types[],
			unsigned int fields_count)
{
	unsigned int i, args_count = str_array_length(*args);

	if (args_count > fields_count)
		args_count = fields_count;
	for (i = 0; i < args_count; i++) {
		const char *value = (*args)[i];

		switch (field_types[i]) {
		case DOVEADM_DUMP_FIELD_TYPE_PASSTHROUGH:
			break;
		case DOVEADM_DUMP_FIELD_TYPE_STDDEV: {
			double variance = strtod(value, NULL);
			value = t_strdup_printf("%.02f", sqrt(variance));
			break;
		}
		}
		doveadm_print(value);
	}
	*args += args_count;
}

static int build_stats_dump_cmd(struct stats_cmd_context *ctx,
				const char **error_r ATTR_UNUSED)
{
	bool reset;
	struct dump_data *data = t_new(struct dump_data, 1);
	const char *fields_raw;
	const char **fields;
	if (!doveadm_cmd_param_bool(ctx->cctx, "reset", &reset))
		reset = FALSE;
	if (!doveadm_cmd_param_str(ctx->cctx, "fields", &fields_raw))
		fields_raw = DOVEADM_DUMP_DEFAULT_FIELDS;

	fields = t_strsplit_spaces(fields_raw, ", ");
	data->fields = fields;
	data->field_count = str_array_length(fields);
	data->field_types =
		t_malloc0(sizeof(enum doveadm_dump_field_type) * data->field_count);
	ctx->data = data;
	ctx->cmd = init_stats_cmd();
	str_append(ctx->cmd, reset ? "DUMP-RESET" : "DUMP");
	unsigned int i;
	for (i = 0; i < data->field_count; i++) {
		str_append_c(ctx->cmd, '\t');
		if (strcmp(fields[i], "stddev") == 0) {
			data->field_types[i] = DOVEADM_DUMP_FIELD_TYPE_STDDEV;
			str_append(ctx->cmd, "variance");
		} else {
			str_append_tabescaped(ctx->cmd, fields[i]);
		}
	}
	str_append_c(ctx->cmd, '\n');
	return 0;
}

static void stats_dump_process_response(struct stats_cmd_context *ctx)
{
	unsigned int i;
	char *line;
	struct dump_data *data = ctx->data;

	doveadm_print_init(DOVEADM_PRINT_TYPE_TAB);
	doveadm_print_header_simple("metric_name");
	doveadm_print_header_simple("field");
	for (i = 0; i < data->field_count; i++)
		doveadm_print_header(data->fields[i], data->fields[i],
				     DOVEADM_PRINT_HEADER_FLAG_NUMBER);

	while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
		if (line[0] == '\0')
			break;
		T_BEGIN {
			const char *const *args =
				t_strsplit_tabescaped_inplace(line);

			const char *metric_name = args[0];
			doveadm_print(metric_name); args++;
			doveadm_print("duration");
			dump_timing(&args, data->field_types, data->field_count);
			while (*args != NULL) {
				doveadm_print(metric_name);
				doveadm_print(*args); args++;
				dump_timing(&args, data->field_types, data->field_count);
			}
		} T_END;
	}
	if (line == NULL)
		handle_disconnection(ctx);
}

static int build_stats_add_cmd(struct stats_cmd_context *ctx,
			       const char **error_r)
{
	unsigned int i;
	const char *parameter;
	struct {
		const char *name;
		const char *default_val;
	} params[] = {
		{ ADD_NAME_PARAM, "" },
		{ ADD_DESCR_PARAM, "" },
		{ ADD_FIELDS_PARAM, "" },
		{ ADD_GROUPBY_PARAM, "" },
		{ ADD_FILTER_PARAM, "" },
		{ ADD_EXPORTER_PARAM, "" },
		/* Default exporter-include is to be modified
		   together with stats-settings */
		{ ADD_EXPORTERINCL_PARAM,
		  STATS_METRIC_SETTINGS_DEFAULT_EXPORTER_INCLUDE },
	};

	ctx->cmd = init_stats_cmd();
	str_append(ctx->cmd, "METRICS-ADD");

	for (i = 0; i < N_ELEMENTS(params); i++) {
		if (!doveadm_cmd_param_str(ctx->cctx, params[i].name, &parameter))
			parameter = params[i].default_val;
		if (parameter[0] == '\0' &&
		    (strcmp(params[i].name, "name") == 0 ||
		     strcmp(params[i].name, "filter") == 0)) {
			*error_r =
				t_strdup_printf("stats add: missing %s parameter",
						params[i].name);
			return -1;
		}
		str_append_c(ctx->cmd, '\t');
		str_append_tabescaped(ctx->cmd, parameter);
	}

	str_append_c(ctx->cmd, '\n');
	return 0;
}

static void stats_modify_process_response(struct stats_cmd_context *ctx)
{
	const char *line = i_stream_read_next_line(ctx->input);
	if (line == NULL) {
		handle_disconnection(ctx);
		return;
	}
	if (line[0] == '-')
		i_error("%s", ++line);
	else if (line[0] != '+')
		i_error("Invalid response: %s", line);
}

static int build_stats_remove_cmd(struct stats_cmd_context *ctx,
				  const char **error_r)
{
	const char *name;

	ctx->cmd = init_stats_cmd();
	str_append(ctx->cmd, "METRICS-REMOVE\t");

	if (!doveadm_cmd_param_str(ctx->cctx, "name", &name)) {
		*error_r = "stats remove: missing name parameter";
		return -1;
	}
	str_append_tabescaped(ctx->cmd, name);
	str_append_c(ctx->cmd, '\n');
	return 0;
}

static void doveadm_cmd_stats_dump(struct doveadm_cmd_context *cctx)
{
	stats_exec_cmd(cctx, &dump_vfuncs);
}

static void doveadm_cmd_stats_add(struct doveadm_cmd_context *cctx)
{
	stats_exec_cmd(cctx, &add_vfuncs);
}

static void doveadm_cmd_stats_remove(struct doveadm_cmd_context *cctx)
{
	stats_exec_cmd(cctx, &remove_vfuncs);
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

struct doveadm_cmd_ver2 doveadm_cmd_stats_add_ver2 = {
	.cmd = doveadm_cmd_stats_add,
	.name = "stats add",
	.usage = "[--"ADD_DESCR_PARAM" <string>] "
	"[--"ADD_EXPORTER_PARAM" <name> [--"ADD_EXPORTERINCL_PARAM" <fields>]] "
	"[--"ADD_FIELDS_PARAM" <fields>] "
	"[--"ADD_GROUPBY_PARAM" <fields>] <name> <filter>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('\0', ADD_NAME_PARAM, CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', ADD_FILTER_PARAM, CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', ADD_EXPORTER_PARAM, CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', ADD_EXPORTERINCL_PARAM, CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', ADD_DESCR_PARAM, CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', ADD_FIELDS_PARAM, CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', ADD_GROUPBY_PARAM, CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_stats_remove_ver2 = {
	.cmd = doveadm_cmd_stats_remove,
	.name = "stats remove",
	.usage = "<name>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('\0', "name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
