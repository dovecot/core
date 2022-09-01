/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "istream-multiplex.h"
#include "doveadm.h"
#include "doveadm-dump.h"

#include <stdio.h>
#include <unistd.h>

static ARRAY(const struct doveadm_cmd_dump *) dumps;

void doveadm_dump_register(const struct doveadm_cmd_dump *dump)
{
	array_push_back(&dumps, &dump);
}

static const struct doveadm_cmd_dump *
dump_find_name(const char *name)
{
	const struct doveadm_cmd_dump *dump;

	array_foreach_elem(&dumps, dump) {
		if (strcmp(dump->name, name) == 0)
			return dump;
	}
	return NULL;
}

static const struct doveadm_cmd_dump *
dump_find_test(struct doveadm_cmd_context *cctx, const char *path)
{
	const struct doveadm_cmd_dump *dump;

	array_foreach_elem(&dumps, dump) {
		if (dump->test != NULL && dump->test(cctx, path))
			return dump;
	}
	return NULL;
}

static void cmd_dump(struct doveadm_cmd_context *cctx)
{
	const struct doveadm_cmd_dump *dump;
	const char *path, *type = NULL, *const *args = NULL;
	const char *no_args = NULL;

	if (!doveadm_cmd_param_str(cctx, "path", &path))
		help_ver2(&doveadm_cmd_dump);
	(void)doveadm_cmd_param_str(cctx, "type", &type);
	(void)doveadm_cmd_param_array(cctx, "args", &args);

	dump = type != NULL ? dump_find_name(type) : dump_find_test(cctx, path);
	if (dump == NULL) {
		if (type != NULL) {
			print_dump_types();
			i_fatal_status(EX_USAGE, "Unknown type: %s", type);
		} else {
			i_fatal_status(EX_DATAERR,
				"Can't autodetect file type: %s", path);
		}
	} else {
		if (type == NULL)
			printf("Detected file type: %s\n", dump->name);
	}
	dump->cmd(cctx, path, args != NULL ? args : &no_args);
}

struct doveadm_cmd_ver2 doveadm_cmd_dump = {
	.name = "dump",
	.cmd = cmd_dump,
	.usage = "[-t <type>] <path> [<type-specific args>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('t', "type", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "path", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "args", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

static void
cmd_dump_multiplex(struct doveadm_cmd_context *cctx,
		   const char *path, const char *const *args ATTR_UNUSED)
{
	const unsigned int channels_count = 256;
	struct istream *file_input, *channels[channels_count];
	const unsigned char *data;
	size_t size;
	unsigned int i;

	file_input = i_stream_create_file(path, IO_BLOCK_SIZE);
	/* A bit kludgy: istream-multiplex returns 0 if a wrong channel is
	   being read from. This causes a panic with blocking istreams.
	   Work around this by assuming that the file istream isn't blocking. */
	file_input->blocking = FALSE;
	channels[0] = i_stream_create_multiplex(file_input, IO_BLOCK_SIZE);
	i_stream_unref(&file_input);

	for (i = 1; i < channels_count; i++)
		channels[i] = i_stream_multiplex_add_channel(channels[0], i);

	bool have_input;
	do {
		have_input = FALSE;
		for (i = 0; i < channels_count; i++) {
			if (i_stream_read_more(channels[i], &data, &size) > 0) {
				printf("CHANNEL %u: %zu bytes:\n", i, size);
				fwrite(data, 1, size, stdout);
				printf("\n");
				have_input = TRUE;
				i_stream_skip(channels[i], size);
			}
		}
	} while (have_input);

	if (channels[0]->stream_errno != 0)
		e_error(cctx->event, "read() failed: %s", i_stream_get_error(channels[0]));
	for (i = 0; i < channels_count; i++)
		i_stream_unref(&channels[i]);
}

struct doveadm_cmd_dump doveadm_cmd_dump_multiplex = {
	"multiplex",
	NULL,
	cmd_dump_multiplex
};

static const struct doveadm_cmd_dump *dumps_builtin[] = {
	&doveadm_cmd_dump_dbox,
	&doveadm_cmd_dump_index,
	&doveadm_cmd_dump_log,
	&doveadm_cmd_dump_mailboxlog,
	&doveadm_cmd_dump_thread,
	&doveadm_cmd_dump_imap_compress,
	&doveadm_cmd_dump_dcrypt_file,
	&doveadm_cmd_dump_dcrypt_key,
	&doveadm_cmd_dump_multiplex,
};

void print_dump_types(void)
{
	unsigned int i;

	fprintf(stderr, "Available dump types: %s", dumps_builtin[0]->name);
	for (i = 1; i < N_ELEMENTS(dumps_builtin); i++)
		fprintf(stderr, " %s", dumps_builtin[i]->name);
	fprintf(stderr, "\n");
}

void doveadm_dump_init(void)
{
	unsigned int i;

	i_array_init(&dumps, N_ELEMENTS(dumps_builtin) + 8);
	for (i = 0; i < N_ELEMENTS(dumps_builtin); i++)
		doveadm_dump_register(dumps_builtin[i]);
}

void doveadm_dump_deinit(void)
{
	array_free(&dumps);
}
