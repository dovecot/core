/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "ostream.h"
#include "config-parser.h"
#include "config-request.h"
#include "config-dump-full.h"

#include <stdio.h>
#include <unistd.h>

struct dump_context {
	struct ostream *output;
	string_t *delayed_output;
};

static void config_dump_full_callback(const char *key, const char *value,
				      enum config_key_type type ATTR_UNUSED,
				      void *context)
{
	struct dump_context *ctx = context;
	const char *suffix;

	if (ctx->delayed_output != NULL &&
	    ((str_begins(key, "passdb", &suffix) &&
	      (suffix[0] == '\0' || suffix[0] == '/')) ||
	     (str_begins(key, "userdb", &suffix) &&
	      (suffix[0] == '\0' || suffix[0] == '/')))) {
		/* For backwards compatibility: global passdbs and userdbs are
		   added after per-protocol ones, not before. */
		str_printfa(ctx->delayed_output, "%s=%s\n", key, value);
	} else T_BEGIN {
		o_stream_nsend_str(ctx->output, t_strdup_printf(
			"%s=%s\n", key, str_tabescape(value)));
	} T_END;
}

static void
config_dump_full_write_filter(struct ostream *output,
			      const struct config_filter *filter)
{
	string_t *str = t_str_new(128);
	str_append(str, ":FILTER ");
	unsigned int prefix_len = str_len(str);

	if (filter->service != NULL) {
		if (filter->service[0] != '!')
			str_printfa(str, "protocol=\"%s\" AND ", str_escape(filter->service));
		else
			str_printfa(str, "NOT protocol=\"%s\" AND ", str_escape(filter->service + 1));
	}
	if (filter->local_name != NULL)
		str_printfa(str, "local_name=\"%s\" AND ", str_escape(filter->local_name));
	if (filter->local_bits > 0) {
		str_printfa(str, "local_ip=\"%s/%u\" AND ",
			    net_ip2addr(&filter->local_net),
			    filter->local_bits);
	}
	if (filter->remote_bits > 0) {
		str_printfa(str, "remote_ip=\"%s/%u\" AND ",
			    net_ip2addr(&filter->remote_net),
			    filter->remote_bits);
	}

	i_assert(str_len(str) > prefix_len);
	str_delete(str, str_len(str) - 4, 4);
	str_append_c(str, '\n');
	o_stream_nsend(output, str_data(str), str_len(str));
}

static int
config_dump_full_sections(struct ostream *output, unsigned int section_idx)
{
	struct config_filter_parser *const *filters;
	struct config_export_context *export_ctx;
	int ret = 0;

	struct config_filter empty_filter;
	i_zero(&empty_filter);
	filters = config_filter_find_subset(config_filter, &empty_filter);

	/* first filter should be the global one */
	i_assert(filters[0] != NULL && filters[0]->filter.service == NULL);
	filters++;

	struct dump_context dump_ctx = {
		.output = output,
	};

	for (; *filters != NULL && ret == 0; filters++) T_BEGIN {
		config_dump_full_write_filter(output, &(*filters)->filter);
		export_ctx = config_export_init(
			CONFIG_DUMP_SCOPE_SET,
			CONFIG_DUMP_FLAG_HIDE_LIST_DEFAULTS,
			config_dump_full_callback, &dump_ctx);
		config_export_parsers(export_ctx, (*filters)->parsers);
		ret = config_export_finish(&export_ctx, &section_idx);
	} T_END;
	return 0;
}

int config_dump_full(struct ostream *output, const char **import_environment_r)
{
	struct config_export_context *export_ctx;
	struct config_filter empty_filter;
	enum config_dump_flags flags;
	unsigned int section_idx = 0;
	int ret;

	i_zero(&empty_filter);
	o_stream_cork(output);

	struct dump_context dump_ctx = {
		.output = output,
		.delayed_output = str_new(default_pool, 256),
	};

	flags = CONFIG_DUMP_FLAG_CHECK_SETTINGS;
	export_ctx = config_export_init(CONFIG_DUMP_SCOPE_CHANGED, flags,
					config_dump_full_callback, &dump_ctx);
	i_zero(&empty_filter);
	config_export_by_filter(export_ctx, &empty_filter);

	*import_environment_r =
		t_strdup(config_export_get_import_environment(export_ctx));
	if (config_export_finish(&export_ctx, &section_idx) < 0)
		ret = -1;
	else
		ret = config_dump_full_sections(output, section_idx);

	if (dump_ctx.delayed_output != NULL &&
	    str_len(dump_ctx.delayed_output) > 0) {
		o_stream_nsend_str(output, ":FILTER \n");
		o_stream_nsend(output, str_data(dump_ctx.delayed_output),
			       str_len(dump_ctx.delayed_output));
	}
	str_free(&dump_ctx.delayed_output);

	o_stream_nsend_str(output, "\n");
	o_stream_uncork(output);
	return ret;
}
