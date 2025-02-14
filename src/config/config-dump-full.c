/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "wildcard-match.h"
#include "safe-mkstemp.h"
#include "ostream.h"
#include "settings.h"
#include "config-parser.h"
#include "config-request.h"
#include "config-filter.h"
#include "config-dump-full.h"

#include <stdio.h>
#include <unistd.h>

/*
   Config binary file format:

   The settings size numbers do not include the size integer itself.

   "DOVECOT-CONFIG\t1.0\n"
   <64bit big-endian: settings full size>

   <32bit big-endian: event filter strings count>
   Repeat for "event filter strings count":
     <NUL-terminated string: event filter string>
     <NUL-terminated string: override event filter string>

   Repeat until "settings full size" is reached:
     <64bit big-endian: settings block size>
     <NUL-terminated string: setting block name>

     <32bit big-endian: settings count>
     <NUL-terminated string: key>[settings count]

     <32bit big-endian: filter count>
     Repeat for "filter count":
       <64bit big-endian: filter settings size>
       <NUL-terminated string: error string - if client attempts to access this
			       settings block, it must fail with this error.
			       NUL = no error, followed by settings>
       <32bit big-endian: include group count>
       Repeat for "include group count":
         <NUL-terminated string: group label>
         <NUL-terminated string: group name>
       Repeat until "filter settings size" is reached:
         <32bit big-endian: key index number>
	 [+|$ <strlist/boollist key>]
	 <NUL-terminated string: value>
     Repeat for "filter count":
       <32bit big-endian: event filter string index number>
     Repeat for "filter count":
       <64bit big-endian: filter settings offset>
     <trailing safety NUL>

   The order of filters is important in the output. lib-settings applies the
   settings in the same order. The applying is done in reverse order, so last
   filter is applied first. Note that lib-settings uses the value from the
   first matching filter and won't change it afterwards. (This is especially
   important because we want to avoid expanding %variables multiple times for
   the same setting. And what to do then if the expansion fails? A later value
   expansion could still work. This is avoided by doing the expansion always
   just once.)

   The filters are written in the same order as they are defined in the config
   file. This automatically causes the more specific filters to be written
   after the less specific ones.

   Groups
   ------

   The group definition order is different from group include order. They can't
   be the same, because the same groups can be included from different places,
   and also the groups can be changed by -o / userdb overrides.

   The group definitions are placed all at the end of the written filters. When
   the parsing code sees a filter that includes groups, it immediately
   processes all the group filters and applies any matches. This is needed,
   because group includes can exist hierarchically so that the most specific
   (innermost filter) includes are fully applied before the less specific
   (outermost filter / global) includes. So if there is e.g. a global
   @group=foo and namespace { @group=bar } which both modify the same setting,
   the @group=bar must be applied first to get the expected value. If the same
   filter has multiple group includes, their include order doesn't matter much,
   but the behavior should be consistent.
*/

struct dump_context {
	struct ostream *output;
	string_t *delayed_output;

	const struct setting_parser_info *info;

	const ARRAY_TYPE(config_include_group) *include_groups;
	const struct config_filter *filter;
	unsigned int filter_idx;
	bool filter_written;
};

static int output_blob_size(struct ostream *output, uoff_t blob_size_offset)
{
	i_assert(output->offset >= blob_size_offset + sizeof(uint64_t));
	uint64_t blob_size = cpu64_to_be(output->offset -
					 (blob_size_offset + sizeof(uint64_t)));
	if (o_stream_pwrite(output, &blob_size, sizeof(blob_size),
			    blob_size_offset) < 0) {
		i_error("o_stream_pwrite(%s) failed: %s",
			o_stream_get_name(output),
			o_stream_get_error(output));
		return -1;
	}
	return 0;
}

static void
config_dump_full_append_filter_query(string_t *str,
				     const struct config_filter *filter,
				     bool write_named_filters)
{
	if (filter->protocol != NULL) {
		if (filter->protocol[0] != '!') {
			str_printfa(str, "protocol=\"%s\" AND ",
				    wildcard_str_escape(filter->protocol));
		} else {
			str_printfa(str, "NOT protocol=\"%s\" AND ",
				    wildcard_str_escape(filter->protocol + 1));
		}
	}
	if (filter->local_name != NULL) {
		str_printfa(str, "local_name=\"%s\" AND ",
			    wildcard_str_escape(filter->local_name));
	}
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

	if (filter->filter_name_array) {
		const char *p = strchr(filter->filter_name, '/');
		i_assert(p != NULL);
		const char *filter_key = t_strdup_until(filter->filter_name, p);
		/* the filter_name is used by settings_get_filter() for
		   finding a specific filter without wildcards messing
		   up the lookups. */
		str_printfa(str, SETTINGS_EVENT_FILTER_NAME
			    "=\"%s/%s\"", filter_key,
			    wildcard_str_escape(settings_section_escape(p + 1)));
		str_append(str, " AND ");
	} else if (filter->filter_name != NULL) {
		const char *filter_name = filter->filter_name;

		if (write_named_filters) {
			str_printfa(str, SETTINGS_EVENT_FILTER_NAME"=\"%s\" AND ",
				    wildcard_str_escape(filter_name));
		}
	}
}

static void
config_dump_full_append_filter(string_t *str,
			       const struct config_filter *filter,
			       bool write_named_filters)
{
	do {
		config_dump_full_append_filter_query(str, filter,
						     write_named_filters);
		filter = filter->parent;
	} while (filter != NULL);

	if (str_len(str) > 0)
		str_truncate(str, str_len(str) - 5);
}

static void
config_dump_full_write_filters(struct ostream *output,
			       struct config_parsed *config)
{
	struct config_filter_parser *const *filters =
		config_parsed_get_filter_parsers(config);
	unsigned int i, filter_count = 0;

	while (filters[filter_count] != NULL) filter_count++;

	uint32_t filter_count_be32 = cpu32_to_be(filter_count);
	o_stream_nsend(output, &filter_count_be32, sizeof(filter_count_be32));

	/* the first filter is the global empty filter */
	o_stream_nsend(output, "", 1);
	o_stream_nsend(output, "", 1);
	string_t *str = str_new(default_pool, 128);
	for (i = 1; i < filter_count; i++) T_BEGIN {
		str_truncate(str, 0);
		config_dump_full_append_filter(str, &filters[i]->filter, TRUE);
		str_append_c(str, '\0');
		o_stream_nsend(output, str_data(str), str_len(str));

		str_truncate(str, 0);
		config_dump_full_append_filter(str, &filters[i]->filter, FALSE);
		str_append_c(str, '\0');
		o_stream_nsend(output, str_data(str), str_len(str));
	} T_END;
	str_free(&str);
}

static void
config_dump_full_write_keys(struct ostream *output,
			    const struct setting_parser_info *info)
{
	unsigned int count = setting_parser_info_get_define_count(info);

	uint32_t count_be32 = cpu32_to_be(count);
	o_stream_nsend(output, &count_be32, sizeof(count_be32));

	for (unsigned int i = 0; i < count; i++) {
		const char *key = info->defines[i].key;
		o_stream_nsend(output, key, strlen(key)+1);
	}
}

static void config_dump_full_stdout_write_filter(struct dump_context *ctx)
{
	if (ctx->filter_written)
		return;
	ctx->filter_written = TRUE;

	string_t *str = t_str_new(128);
	if (ctx->filter != NULL)
		config_dump_full_append_filter(str, ctx->filter, TRUE);
	str_insert(str, 0, ":FILTER ");
	str_append_c(str, '\n');

	if (ctx->include_groups != NULL) {
		const struct config_include_group *group;
		array_foreach(ctx->include_groups, group) {
			str_printfa(str, ":INCLUDE @%s %s\n",
				    group->label, group->name);
		}
	}
	o_stream_nsend(ctx->output, str_data(str), str_len(str));
}

static void
config_dump_full_stdout_callback(const struct config_export_setting *set,
				 struct dump_context *ctx)
{
	if (set->type != CONFIG_KEY_LIST)
		;
	else if (set->list_count == 0 && set->value_stop_list &&
		 (set->def_type == SET_BOOLLIST ||
		  set->def_type == SET_STRLIST)) {
		/* filter empties a boollist/strlist setting */
	} else {
		/* these aren't needed */
		return;
	}

	config_dump_full_stdout_write_filter(ctx);
	T_BEGIN {
		const struct setting_define *def =
			&ctx->info->defines[set->key_define_idx];
		if (def->type == SET_STRLIST || def->type == SET_BOOLLIST) {
			const char *suffix;
			if (!str_begins(set->key, def->key, &suffix))
				i_unreached();
			else if (suffix[0] == '/') {
				suffix++;
				o_stream_nsend_str(ctx->output,
					t_strdup_until(set->key, suffix));
				o_stream_nsend_str(ctx->output,
					settings_section_escape(suffix));
			} else {
				/* emptying boollist */
				i_assert(suffix[0] == '\0');
				i_assert(set->type == CONFIG_KEY_LIST);
				o_stream_nsend_str(ctx->output, set->key);
			}
		} else {
			o_stream_nsend_str(ctx->output, set->key);
		}
		o_stream_nsend_str(ctx->output, "=");
		o_stream_nsend_str(ctx->output, str_tabescape(set->value));
		if (set->value_stop_list)
			o_stream_nsend_str(ctx->output, " # stop list");
		o_stream_nsend_str(ctx->output, "\n");
	} T_END;
}

static void config_include_groups_dump(struct dump_context *ctx)
{
	uint32_t include_count_be32 = 0;
	if (ctx->include_groups == NULL) {
		o_stream_nsend(ctx->output, &include_count_be32,
			       sizeof(include_count_be32));
	} else {
		include_count_be32 = cpu32_to_be(array_count(ctx->include_groups));
		o_stream_nsend(ctx->output, &include_count_be32,
			       sizeof(include_count_be32));

		const struct config_include_group *group;
		array_foreach(ctx->include_groups, group) {
			o_stream_nsend(ctx->output, group->label,
				       strlen(group->label) + 1);
			o_stream_nsend(ctx->output, group->name,
				       strlen(group->name) + 1);
		}
	}
}

static void config_dump_full_write_filter(struct dump_context *ctx)
{
	if (ctx->filter_written)
		return;
	ctx->filter_written = TRUE;

	uint64_t blob_size = UINT64_MAX;
	o_stream_nsend(ctx->output, &blob_size, sizeof(blob_size));
	/* Start by assuming there is no error. If there is, the error
	   handling code path truncates the file and writes the error. */
	o_stream_nsend(ctx->output, "", 1);

	config_include_groups_dump(ctx);
}

static void config_dump_full_callback(const struct config_export_setting *set,
				      struct dump_context *ctx)
{
	const char *suffix;

	if (set->type != CONFIG_KEY_LIST)
		;
	else if (set->list_count == 0 && set->value_stop_list &&
		 (set->def_type == SET_BOOLLIST ||
		  set->def_type == SET_STRLIST)) {
		/* filter empties a boollist/strlist setting */
	} else {
		/* these aren't needed */
		return;
	}

	config_dump_full_write_filter(ctx);

	uint32_t key_be32 = cpu32_to_be(set->key_define_idx);
	if (ctx->delayed_output != NULL &&
	    ((str_begins(set->key, "passdb", &suffix) &&
	      (suffix[0] == '\0' || suffix[0] == '/')) ||
	     (str_begins(set->key, "userdb", &suffix) &&
	      (suffix[0] == '\0' || suffix[0] == '/')))) {
		/* For backwards compatibility: global passdbs and userdbs are
		   added after per-protocol ones, not before. */
		str_append_data(ctx->delayed_output, &key_be32,
				sizeof(key_be32));
		str_append_data(ctx->delayed_output, set->value,
				strlen(set->value)+1);
	} else {
		o_stream_nsend(ctx->output, &key_be32, sizeof(key_be32));
		const struct setting_define *def =
			&ctx->info->defines[set->key_define_idx];
		if (def->type == SET_STRLIST || def->type == SET_BOOLLIST) {
			const char *suffix;
			if (!str_begins(set->key, def->key, &suffix))
				i_unreached();
			else if (suffix[0] == '/') {
				suffix = settings_section_escape(suffix + 1);
				o_stream_nsend(ctx->output,
					       set->value_stop_list ?
					       SET_LIST_REPLACE :
					       SET_LIST_APPEND, 1);
				o_stream_nsend(ctx->output, suffix,
					       strlen(suffix) + 1);
			} else {
				/* emptying boollist */
				i_assert(suffix[0] == '\0');
				i_assert(set->type == CONFIG_KEY_LIST);
				o_stream_nsend(ctx->output,
					       SET_LIST_CLEAR, 1 + 1);
			}
		}
		const char *var_value = set->value;
		if (set->def_type == SET_FILE) {
			const char *ptr = strchr(var_value, '\n');
			if (ptr != NULL)
				var_value = t_strdup_until(var_value, ptr);
		}

		if (*var_value == '\1' || strstr(var_value, "%{") != NULL) {
			struct var_expand_program *program;
			const char *error;
			int ret = var_expand_program_create(var_value, &program,
							    &error);
			if (ret < 0)
				i_panic("%s: %s", var_value, error);
			const char *export = var_expand_program_export(program);
			var_expand_program_free(&program);
			o_stream_nsend_str(ctx->output, "\1");
			o_stream_nsend(ctx->output, export, strlen(export));
			o_stream_nsend_str(ctx->output, "\n");
		}
		o_stream_nsend(ctx->output, set->value, strlen(set->value)+1);
	}
}

static int
config_dump_full_handle_error(struct dump_context *dump_ctx,
			      enum config_dump_full_dest dest,
			      uoff_t start_offset, const char *error)
{
	struct ostream *output = dump_ctx->output;

	if (dest == CONFIG_DUMP_FULL_DEST_STDOUT) {
		i_error("%s", error);
		return -1;
	}

	if (o_stream_flush(output) < 0) {
		i_error("o_stream_flush(%s) failed: %s",
			o_stream_get_name(output), o_stream_get_error(output));
		return -1;
	}
	if (ftruncate(o_stream_get_fd(output), start_offset) < 0) {
		i_error("ftruncate(%s) failed: %m", o_stream_get_name(output));
		return -1;
	}
	if (o_stream_seek(output, start_offset) < 0) {
		i_error("o_stream_seek(%s) failed: %s",
			o_stream_get_name(output), o_stream_get_error(output));
		return -1;
	}

	size_t error_len = strlen(error) + 1;
	uint64_t blob_size = cpu64_to_be(error_len + 4);
	o_stream_nsend(output, &blob_size, sizeof(blob_size));
	o_stream_nsend(output, error, error_len);
	uint32_t include_group_count = 0;
	o_stream_nsend(output, &include_group_count,
		       sizeof(include_group_count));
	dump_ctx->filter_written = TRUE;
	return 0;
}

struct config_dump_full_context {
	struct config_parsed *config;
	struct ostream *output;
	enum config_dump_full_dest dest;

	struct config_filter_parser *const *filters;
	uint32_t filter_output_count;

	uint32_t *filter_indexes_be32;
	uint64_t *filter_offsets_be64;
};

enum config_dump_type {
	CONFIG_DUMP_TYPE_DEFAULTS,
	CONFIG_DUMP_TYPE_EXPLICIT,
	CONFIG_DUMP_TYPE_GROUPS,
};

static bool filter_is_group(const struct config_filter *filter)
{
	for (; filter != NULL; filter = filter->parent) {
		if (filter->filter_name_array &&
		    filter->filter_name[0] == SETTINGS_INCLUDE_GROUP_PREFIX)
			return TRUE;
	}
	return FALSE;
}

static int
config_dump_full_sections(struct config_dump_full_context *ctx,
			  unsigned int parser_idx,
			  const struct setting_parser_info *info,
			  const string_t *delayed_filter,
			  enum config_dump_type dump_type)
{
	struct ostream *output = ctx->output;
	enum config_dump_full_dest dest = ctx->dest;
	struct config_export_context *export_ctx;
	int ret = 0;

	struct dump_context dump_ctx = {
		.output = output,
		.info = info,
	};
	ARRAY_TYPE(config_include_group) groups;
	t_array_init(&groups, 8);

	for (unsigned int i = 1; ctx->filters[i] != NULL && ret == 0; i++) {
		const struct config_filter_parser *filter = ctx->filters[i];
		uoff_t start_offset = output->offset;

		if (filter_is_group(&filter->filter)) {
			/* This is a group filter. Are we dumping groups?
			   Handle default groups the same as non-default
			   groups. */
			if (dump_type != CONFIG_DUMP_TYPE_GROUPS)
				continue;
		} else {
			/* This is not a group filter. */
			switch (dump_type) {
			case CONFIG_DUMP_TYPE_DEFAULTS:
				if (!filter->filter.default_settings)
					continue;
				break;
			case CONFIG_DUMP_TYPE_EXPLICIT:
				if (filter->filter.default_settings)
					continue;
				break;
			case CONFIG_DUMP_TYPE_GROUPS:
				continue;
			}
		}

		if (config_parsed_get_includes(ctx->config, filter,
					       parser_idx, &groups)) {
			dump_ctx.include_groups = &groups;
		} else if (filter->module_parsers[parser_idx].settings == NULL &&
			   filter->module_parsers[parser_idx].delayed_error == NULL) {
			/* nothing to export in this filter */
			continue;
		} else {
			dump_ctx.include_groups = NULL;
		}

		dump_ctx.filter = &filter->filter;
		dump_ctx.filter_idx = i;
		dump_ctx.filter_written = FALSE;
		if (dest == CONFIG_DUMP_FULL_DEST_STDOUT) {
			export_ctx = config_export_init(
				CONFIG_DUMP_SCOPE_SET_AND_DEFAULT_OVERRIDES,
				0,
				config_dump_full_stdout_callback, &dump_ctx);
		} else {
			export_ctx = config_export_init(
				CONFIG_DUMP_SCOPE_SET_AND_DEFAULT_OVERRIDES,
				0,
				config_dump_full_callback, &dump_ctx);
		}
		config_export_set_module_parsers(export_ctx,
						 filter->module_parsers);

		const struct setting_parser_info *filter_info =
			config_export_parser_get_info(export_ctx, parser_idx);
		i_assert(filter_info == info);

		const char *error;
		ret = config_export_parser(export_ctx, parser_idx, &error);
		if (ret == 0 && dump_ctx.include_groups != NULL) {
			if (dest == CONFIG_DUMP_FULL_DEST_STDOUT)
				config_dump_full_stdout_write_filter(&dump_ctx);
			else
				config_dump_full_write_filter(&dump_ctx);
		}
		if (ret < 0) {
			/* Delay the failure until the filter is accessed by
			   the config client. The error is written to the
			   filter's error string. */
			ret = config_dump_full_handle_error(&dump_ctx, dest, start_offset, error);
		} else if (dest != CONFIG_DUMP_FULL_DEST_STDOUT &&
			   output->offset > start_offset) {
			/* We know the filter's blob size now - write it */
			if (output_blob_size(output, start_offset) < 0)
				ret = -1;
		}
		config_export_free(&export_ctx);
		if (dump_ctx.filter_written) {
			ctx->filter_indexes_be32[ctx->filter_output_count] =
				cpu32_to_be(i);
			ctx->filter_offsets_be64[ctx->filter_output_count] =
				cpu64_to_be(start_offset);
			ctx->filter_output_count++;
		}
	}

	if (delayed_filter != NULL && str_len(delayed_filter) > 0) {
		ctx->filter_indexes_be32[ctx->filter_output_count] =
			0; /* empty/global filter */
		ctx->filter_offsets_be64[ctx->filter_output_count] =
			cpu64_to_be(output->offset);

		uint64_t blob_size = cpu64_to_be(5 + str_len(delayed_filter));
		o_stream_nsend(output, &blob_size, sizeof(blob_size));
		o_stream_nsend(output, "", 1); /* no error */
		uint32_t include_group_count = 0;
		o_stream_nsend(output, &include_group_count,
			       sizeof(include_group_count));
		o_stream_nsend(output, str_data(delayed_filter),
			       str_len(delayed_filter));
		ctx->filter_output_count++;
	}

	return ret;
}

int config_dump_full(struct config_parsed *config,
		     enum config_dump_full_dest dest,
		     enum config_dump_flags flags,
		     const char **import_environment_r)
{
	struct config_export_context *export_ctx;
	const char *error;
	int fd = -1;

	struct dump_context dump_ctx = {
		.delayed_output = str_new(default_pool, 256),
	};

	if (dest == CONFIG_DUMP_FULL_DEST_STDOUT) {
		export_ctx = config_export_init(
				CONFIG_DUMP_SCOPE_SET_AND_DEFAULT_OVERRIDES,
				flags, config_dump_full_stdout_callback,
				&dump_ctx);
	} else {
		export_ctx = config_export_init(
				CONFIG_DUMP_SCOPE_SET_AND_DEFAULT_OVERRIDES,
				flags, config_dump_full_callback, &dump_ctx);
	}
	struct config_filter_parser *filter_parser =
		config_parsed_get_global_filter_parser(config);
	config_export_set_module_parsers(export_ctx, filter_parser->module_parsers);

	string_t *path = t_str_new(128);
	const char *final_path = NULL;
	switch (dest) {
	case CONFIG_DUMP_FULL_DEST_RUNDIR: {
		const char *base_dir =
			config_parsed_get_setting(config,
				"master_service", "base_dir");
		final_path = t_strdup_printf("%s/dovecot.conf.binary", base_dir);
		str_append(path, final_path);
		str_append_c(path, '.');
		break;
	}
	case CONFIG_DUMP_FULL_DEST_TEMPDIR:
		/* create an unlinked file to /tmp */
		str_append(path, "/tmp/doveconf.");
		break;
	case CONFIG_DUMP_FULL_DEST_STDOUT:
		dump_ctx.output = o_stream_create_fd(STDOUT_FILENO, IO_BLOCK_SIZE);
		o_stream_set_name(dump_ctx.output, "<stdout>");
		fd = 0;
		break;
	}

	if (dump_ctx.output == NULL) {
		fd = safe_mkstemp(path, 0700, (uid_t)-1, (gid_t)-1);
		if (fd == -1) {
			i_error("safe_mkstemp(%s) failed: %m", str_c(path));
			config_export_free(&export_ctx);
			str_free(&dump_ctx.delayed_output);
			return -1;
		}
		if (dest == CONFIG_DUMP_FULL_DEST_TEMPDIR)
			i_unlink(str_c(path));
		dump_ctx.output = o_stream_create_fd(fd, IO_BLOCK_SIZE);
		o_stream_set_name(dump_ctx.output, str_c(path));
	}
	struct ostream *output = dump_ctx.output;

	o_stream_cork(output);

	if (import_environment_r != NULL) {
		const char *value =
			config_parsed_get_setting(config,
				"master_service", "import_environment");
		*import_environment_r = t_strdup(value);
	}

	uint64_t blob_size = UINT64_MAX;
	uoff_t settings_full_size_offset = 0;
	if (dest != CONFIG_DUMP_FULL_DEST_STDOUT) {
		o_stream_nsend_str(output, "DOVECOT-CONFIG\t1.0\n");
		settings_full_size_offset = output->offset;
		o_stream_nsend(output, &blob_size, sizeof(blob_size));

		config_dump_full_write_filters(output, config);
	}

	struct config_dump_full_context ctx = {
		.config = config,
		.output = output,
		.dest = dest,
		.filters = config_parsed_get_filter_parsers(config),
	};

	/* first filter should be the global one */
	i_assert(ctx.filters[0] != NULL &&
		 ctx.filters[0]->filter.protocol == NULL);

	uint32_t max_filter_count = 0;
	while (ctx.filters[max_filter_count] != NULL) max_filter_count++;

	ctx.filter_indexes_be32 = t_new(uint32_t, max_filter_count);
	ctx.filter_offsets_be64 = t_new(uint64_t, max_filter_count);

	ARRAY_TYPE(config_include_group) groups;
	t_array_init(&groups, 8);

	unsigned int i, parser_count =
		config_export_get_parser_count(export_ctx);
	for (i = 0; i < parser_count; i++) {
		const struct setting_parser_info *info =
			config_export_parser_get_info(export_ctx, i);
		if (info->name == NULL || info->name[0] == '\0')
			i_panic("Setting parser info is missing name");

		uoff_t settings_block_size_offset = output->offset;
		if (dest != CONFIG_DUMP_FULL_DEST_STDOUT) {
			o_stream_nsend(output, &blob_size, sizeof(blob_size));
			o_stream_nsend(output, info->name, strlen(info->name)+1);

			config_dump_full_write_keys(output, info);
		} else {
			o_stream_nsend_str(output,
				t_strdup_printf("# %s\n", info->name));
		}
		ctx.filter_output_count = 0;

		uoff_t filter_count_offset = output->offset;
		uint32_t filter_count = 0;
		if (dest != CONFIG_DUMP_FULL_DEST_STDOUT) {
			o_stream_nsend(output, &filter_count,
				       sizeof(filter_count));
		}

		/* 1. Write built-in default settings */
		int ret;
		T_BEGIN {
			ret = config_dump_full_sections(&ctx, i, info, NULL,
					CONFIG_DUMP_TYPE_DEFAULTS);
		} T_END;
		if (ret < 0)
			break;

		uoff_t blob_size_offset = output->offset;
		/* 2. Write global settings in config - use an empty filter */
		ctx.filter_indexes_be32[ctx.filter_output_count] = 0;
		ctx.filter_offsets_be64[ctx.filter_output_count] =
			cpu64_to_be(blob_size_offset);
		ctx.filter_output_count++;

		if (config_parsed_get_includes(config, filter_parser,
					       i, &groups))
			dump_ctx.include_groups = &groups;
		else
			dump_ctx.include_groups = NULL;

		if (dest != CONFIG_DUMP_FULL_DEST_STDOUT) {
			/* Write a filter for the global settings, even if there
			   are no settings. This allows lib-settings to apply
			   setting overrides at the proper position before
			   defaults. */
			o_stream_nsend(output, &blob_size, sizeof(blob_size));
			/* Start by assuming there is no error. If there is,
			   the error handling code path truncates the file
			   and writes the error. */
			o_stream_nsend(output, "", 1);
			config_include_groups_dump(&dump_ctx);
			dump_ctx.filter_written = TRUE;
		} else {
			/* Make :FILTER visible */
			dump_ctx.filter_written = FALSE;
		}
		dump_ctx.info = info;
		if (config_export_parser(export_ctx, i, &error) < 0) {
			if (config_dump_full_handle_error(&dump_ctx, dest,
					blob_size_offset, error) < 0)
				break;
		}
		if (dump_ctx.include_groups != NULL) {
			if (dest == CONFIG_DUMP_FULL_DEST_STDOUT)
				config_dump_full_stdout_write_filter(&dump_ctx);
			else
				config_dump_full_write_filter(&dump_ctx);
		}
		if (dest != CONFIG_DUMP_FULL_DEST_STDOUT) {
			if (output_blob_size(output, blob_size_offset) < 0)
				break;
		}

		/* 3. Write filter settings in config */
		T_BEGIN {
			ret = config_dump_full_sections(&ctx, i, info,
					dump_ctx.delayed_output,
					CONFIG_DUMP_TYPE_EXPLICIT);
		} T_END;
		if (ret < 0)
			break;

		/* 4. Write group filters */
		T_BEGIN {
			ret = config_dump_full_sections(&ctx, i, info,
					dump_ctx.delayed_output,
					CONFIG_DUMP_TYPE_GROUPS);
		} T_END;
		if (ret < 0)
			break;

		if (dest != CONFIG_DUMP_FULL_DEST_STDOUT) {
			o_stream_nsend(output, ctx.filter_indexes_be32,
				       sizeof(ctx.filter_indexes_be32[0]) *
				       ctx.filter_output_count);
			o_stream_nsend(output, ctx.filter_offsets_be64,
				       sizeof(ctx.filter_offsets_be64[0]) *
				       ctx.filter_output_count);
			/* safety NUL at the end of the block */
			o_stream_nsend(output, "", 1);
		}

		if (dest != CONFIG_DUMP_FULL_DEST_STDOUT) {
			filter_count = cpu32_to_be(ctx.filter_output_count);
			if (o_stream_pwrite(output, &filter_count,
					    sizeof(filter_count),
					    filter_count_offset) < 0) {
				i_error("o_stream_pwrite(%s) failed: %s",
					o_stream_get_name(output),
					o_stream_get_error(output));
				break;
			}
			if (output_blob_size(output, settings_block_size_offset) < 0)
				break;
		}
		str_truncate(dump_ctx.delayed_output, 0);
	}
	bool failed = i < parser_count;
	config_export_free(&export_ctx);
	str_free(&dump_ctx.delayed_output);

	if (dest != CONFIG_DUMP_FULL_DEST_STDOUT) {
		if (output_blob_size(output, settings_full_size_offset) < 0)
			failed = TRUE;
	}
	if (o_stream_finish(output) < 0 && !failed) {
		i_error("write(%s) failed: %s",
			o_stream_get_name(output), o_stream_get_error(output));
		failed = TRUE;
	}

	if (final_path == NULL) {
		/* There is no temporary file. We're either writing to stdout
		   or the temporary file was already unlinked. */
	} else if (failed) {
		i_unlink(str_c(path));
	} else {
		if (rename(str_c(path), final_path) < 0) {
			i_error("rename(%s, %s) failed: %m",
				str_c(path), final_path);
			/* the fd is still readable, so don't return failure */
		}
	}

	if (!failed && dest != CONFIG_DUMP_FULL_DEST_STDOUT &&
	    lseek(fd, 0, SEEK_SET) < 0) {
		i_error("lseek(%s, 0) failed: %m", o_stream_get_name(output));
		failed = TRUE;
	}
	if (failed) {
		if (dest == CONFIG_DUMP_FULL_DEST_STDOUT)
			fd = -1;
		else
			i_close_fd(&fd);
	}
	o_stream_destroy(&output);
	return fd;
}
