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

struct dump_context {
	struct ostream *output;
	string_t *delayed_output;
};

static void
config_dump_full_stdout_callback(const char *key, const char *value,
				 enum config_key_type type ATTR_UNUSED,
				 void *context)
{
	struct dump_context *ctx = context;

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

static void
config_dump_full_write_filter(struct ostream *output,
			      const struct config_filter *filter,
			      enum config_dump_full_dest dest)
{
	string_t *str = t_str_new(128);
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
	o_stream_nsend(output, str_data(str), str_len(str));
}

static bool
config_dump_full_sections(struct ostream *output,
			  enum config_dump_full_dest dest,
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
		uint64_t blob_size = 0;
		uoff_t start_offset = output->offset;
		if (dest != CONFIG_DUMP_FULL_DEST_STDOUT)
			o_stream_nsend(output, &blob_size, sizeof(blob_size));

		config_dump_full_write_filter(output, &(*filters)->filter, dest);
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
		config_export_parsers(export_ctx, (*filters)->parsers);
		ret = config_export_finish(&export_ctx, &section_idx);
		if (ret == 0 && dest != CONFIG_DUMP_FULL_DEST_STDOUT) {
			/* write the filter blob size */
			blob_size = cpu64_to_be(output->offset - start_offset);
			if (o_stream_pwrite(output, &blob_size,
					    sizeof(blob_size),
					    start_offset) < 0) {
				i_error("o_stream_pwrite(%s) failed: %s",
					o_stream_get_name(output),
					o_stream_get_error(output));
				ret = -1;
			}
		}
	} T_END;
	return ret == 0;
}

int config_dump_full(enum config_dump_full_dest dest,
		     enum config_dump_flags flags,
		     const char **import_environment_r)
{
	struct config_export_context *export_ctx;
	struct config_filter empty_filter;
	unsigned int section_idx = 0;
	int fd = -1;
	bool failed = FALSE;

	struct dump_context dump_ctx = {
		.delayed_output = str_new(default_pool, 256),
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
	config_export_by_filter(export_ctx, &empty_filter);

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
			(void)config_export_finish(&export_ctx, &section_idx);
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

	uint64_t blob_size = 0;
	uoff_t blob_size_offset = 0;
	if (dest != CONFIG_DUMP_FULL_DEST_STDOUT) {
		o_stream_nsend_str(output, "DOVECOT-CONFIG\t1.0\n");
		blob_size_offset = output->offset;
		o_stream_nsend(output, &blob_size, sizeof(blob_size));
	}

	if (config_export_finish(&export_ctx, &section_idx) < 0)
		failed = TRUE;
	else if (dest != CONFIG_DUMP_FULL_DEST_STDOUT) {
		blob_size = cpu64_to_be(output->offset - blob_size_offset);
		if (o_stream_pwrite(output, &blob_size, sizeof(blob_size),
				    blob_size_offset) < 0) {
			i_error("o_stream_pwrite(%s) failed: %s",
				o_stream_get_name(output),
				o_stream_get_error(output));
			failed = TRUE;
		}
	}
	if (!failed)
		failed = !config_dump_full_sections(output, dest, section_idx);

	if (dump_ctx.delayed_output != NULL &&
	    str_len(dump_ctx.delayed_output) > 0) {
		uint64_t blob_size =
			cpu64_to_be(sizeof(blob_size) + 1 + str_len(dump_ctx.delayed_output));
		o_stream_nsend(output, &blob_size, sizeof(blob_size));
		o_stream_nsend(output, "", 1);
		o_stream_nsend(output, str_data(dump_ctx.delayed_output),
			       str_len(dump_ctx.delayed_output));
	}
	str_free(&dump_ctx.delayed_output);

	if (o_stream_finish(output) < 0) {
		i_error("write(%s) failed: %s",
			o_stream_get_name(output), o_stream_get_error(output));
		failed = TRUE;
	}

	if (final_path != NULL && !failed) {
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
