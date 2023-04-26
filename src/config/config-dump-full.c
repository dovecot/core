/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "safe-mkstemp.h"
#include "ostream.h"
#include "config-parser.h"
#include "config-request.h"
#include "config-dump-full.h"

#include <stdio.h>
#include <unistd.h>

/*
   Config binary file format:

   The settings size numbers do not include the size integer itself.

   "DOVECOT-CONFIG\t1.0\n"
   <64bit big-endian: settings full size>
   Repeat until "settings full size" is reached:
     <64bit big-endian: settings block size>
     <NUL-terminated string: setting block name>

     <64bit big-endian: base settings size>
     <NUL-terminated string: error string - if client attempts to access this
                             settings block, it must fail with this error.
			     NUL = no error, followed by settings>
     Repeat until "base settings size" is reached:
       <NUL-terminated string: key>
       <NUL-terminated string: value>

     Repeat until "settings block size" is reached:
       <64bit big-endian: filter settings size>
       <NUL-terminated string: event filter>
       <NUL-terminated string: error string>
       Repeat until "filter settings size" is reached:
	 <NUL-terminated string: key>
	 <NUL-terminated string: value>
*/

struct dump_context {
	struct ostream *output;
	string_t *delayed_output;

	const struct config_filter *filter;
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
config_dump_full_append_filter(string_t *str,
			       const struct config_filter *filter,
			       enum config_dump_full_dest dest)
{
	if (dest == CONFIG_DUMP_FULL_DEST_STDOUT)
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
	if (dest == CONFIG_DUMP_FULL_DEST_STDOUT)
		str_append_c(str, '\n');
	else
		str_append_c(str, '\0');
}

static void
config_dump_full_write_filter(struct ostream *output,
			      const struct config_filter *filter,
			      enum config_dump_full_dest dest)
{
	string_t *str = t_str_new(128);
	config_dump_full_append_filter(str, filter, dest);
	o_stream_nsend(output, str_data(str), str_len(str));
}

static void
config_dump_full_stdout_callback(const char *key, const char *value,
				 enum config_key_type type ATTR_UNUSED,
				 void *context)
{
	struct dump_context *ctx = context;

	if (!ctx->filter_written) {
		config_dump_full_write_filter(ctx->output, ctx->filter,
					      CONFIG_DUMP_FULL_DEST_STDOUT);
		ctx->filter_written = TRUE;
	}
	T_BEGIN {
		o_stream_nsend_str(ctx->output, t_strdup_printf(
			"%s=%s\n", key, str_tabescape(value)));
	} T_END;
}

static void config_dump_full_callback(const char *key, const char *value,
				      enum config_key_type type ATTR_UNUSED,
				      void *context)
{
	struct dump_context *ctx = context;
	const char *suffix;

	if (!ctx->filter_written) {
		uint64_t blob_size = UINT64_MAX;
		o_stream_nsend(ctx->output, &blob_size, sizeof(blob_size));
		config_dump_full_write_filter(ctx->output, ctx->filter,
					      CONFIG_DUMP_FULL_DEST_RUNDIR);
		o_stream_nsend(ctx->output, "", 1); /* no error */
		ctx->filter_written = TRUE;
	}
	if (ctx->delayed_output != NULL &&
	    ((str_begins(key, "passdb", &suffix) &&
	      (suffix[0] == '\0' || suffix[0] == '/')) ||
	     (str_begins(key, "userdb", &suffix) &&
	      (suffix[0] == '\0' || suffix[0] == '/')))) {
		/* For backwards compatibility: global passdbs and userdbs are
		   added after per-protocol ones, not before. */
		str_append_data(ctx->delayed_output, key, strlen(key)+1);
		str_append_data(ctx->delayed_output, value, strlen(value)+1);
	} else {
		o_stream_nsend(ctx->output, key, strlen(key)+1);
		o_stream_nsend(ctx->output, value, strlen(value)+1);
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

	string_t *str = t_str_new(256);
	if (dump_ctx->filter != NULL)
		config_dump_full_append_filter(str, dump_ctx->filter, dest);
	str_append(str, error);
	str_append_c(str, '\0');

	uint64_t blob_size = cpu64_to_be(str_len(str));
	o_stream_nsend(output, &blob_size, sizeof(blob_size));
	o_stream_nsend(output, str_data(str), str_len(str));
	return 0;
}

static int
config_dump_full_sections(struct ostream *output,
			  enum config_dump_full_dest dest,
			  unsigned int parser_idx,
			  const struct setting_parser_info *info,
			  unsigned int section_idx)
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
		uoff_t start_offset = output->offset;

		dump_ctx.filter = &(*filters)->filter;
		dump_ctx.filter_written = FALSE;
		if (dest == CONFIG_DUMP_FULL_DEST_STDOUT) {
			export_ctx = config_export_init(
				CONFIG_DUMP_SCOPE_SET,
				CONFIG_DUMP_FLAG_HIDE_LIST_DEFAULTS,
				config_dump_full_stdout_callback, &dump_ctx);
		} else {
			export_ctx = config_export_init(
				CONFIG_DUMP_SCOPE_SET,
				CONFIG_DUMP_FLAG_HIDE_LIST_DEFAULTS,
				config_dump_full_callback, &dump_ctx);
		}
		config_export_set_parsers(export_ctx, (*filters)->parsers);

		const struct setting_parser_info *filter_info =
			config_export_parser_get_info(export_ctx, parser_idx);
		i_assert(filter_info == info);

		const char *error;
		ret = config_export_parser(export_ctx, parser_idx,
					   &section_idx, &error);
		if (ret < 0) {
			ret = config_dump_full_handle_error(&dump_ctx, dest, start_offset, error);
		} else if (dest != CONFIG_DUMP_FULL_DEST_STDOUT &&
			   output->offset > start_offset) {
			/* write the filter blob size */
			if (output_blob_size(output, start_offset) < 0)
				ret = -1;
		}
		config_export_free(&export_ctx);
	} T_END;
	return ret;
}

int config_dump_full(enum config_dump_full_dest dest,
		     enum config_dump_flags flags,
		     const char **import_environment_r)
{
	struct config_export_context *export_ctx;
	struct config_filter empty_filter;
	const char *error;
	unsigned int section_idx = 0;
	int fd = -1;

	struct dump_context dump_ctx = {
		.delayed_output = str_new(default_pool, 256),
		.filter_written = TRUE,
	};

	if (dest == CONFIG_DUMP_FULL_DEST_STDOUT) {
		export_ctx = config_export_init(
				CONFIG_DUMP_SCOPE_CHANGED, flags,
				config_dump_full_stdout_callback, &dump_ctx);
	} else {
		export_ctx = config_export_init(
				CONFIG_DUMP_SCOPE_CHANGED, flags,
				config_dump_full_callback, &dump_ctx);
	}
	i_zero(&empty_filter);
	if (config_export_by_filter(export_ctx, config_filter, &empty_filter) < 0) {
		config_export_free(&export_ctx);
		str_free(&dump_ctx.delayed_output);
		return -1;
	}

	string_t *path = t_str_new(128);
	const char *final_path = NULL;
	switch (dest) {
	case CONFIG_DUMP_FULL_DEST_RUNDIR: {
		const char *base_dir = config_export_get_base_dir(export_ctx);
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

	i_zero(&empty_filter);
	o_stream_cork(output);

	*import_environment_r =
		t_strdup(config_export_get_import_environment(export_ctx));

	uint64_t blob_size = UINT64_MAX;
	uoff_t settings_full_size_offset = 0;
	if (dest != CONFIG_DUMP_FULL_DEST_STDOUT) {
		o_stream_nsend_str(output, "DOVECOT-CONFIG\t1.0\n");
		settings_full_size_offset = output->offset;
		o_stream_nsend(output, &blob_size, sizeof(blob_size));
	}

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
		} else {
			o_stream_nsend_str(output,
				t_strdup_printf("# %s\n", info->name));
		}

		uoff_t blob_size_offset = output->offset;
		if (dest != CONFIG_DUMP_FULL_DEST_STDOUT) {
			o_stream_nsend(output, &blob_size, sizeof(blob_size));
			o_stream_nsend(output, "", 1); /* no error */
		}
		if (config_export_parser(export_ctx, i, &section_idx,
					 &error) < 0) {
			if (config_dump_full_handle_error(&dump_ctx, dest,
					blob_size_offset, error) < 0)
				break;
		}
		if (dest != CONFIG_DUMP_FULL_DEST_STDOUT) {
			if (output_blob_size(output, blob_size_offset) < 0)
				break;
		}
		int ret;
		T_BEGIN {
			ret = config_dump_full_sections(output, dest, i, info,
							section_idx);
		} T_END;
		if (ret < 0)
			break;
		if (dump_ctx.delayed_output != NULL &&
		    str_len(dump_ctx.delayed_output) > 0) {
			uint64_t blob_size =
				cpu64_to_be(2 + str_len(dump_ctx.delayed_output));
			o_stream_nsend(output, &blob_size, sizeof(blob_size));
			o_stream_nsend(output, "", 1); /* empty filter */
			o_stream_nsend(output, "", 1); /* no error */
			o_stream_nsend(output, str_data(dump_ctx.delayed_output),
				       str_len(dump_ctx.delayed_output));
			str_truncate(dump_ctx.delayed_output, 0);
		}
		if (dest != CONFIG_DUMP_FULL_DEST_STDOUT) {
			if (output_blob_size(output, settings_block_size_offset) < 0)
				break;
		}
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
