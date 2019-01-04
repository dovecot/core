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
	const struct doveadm_cmd_dump *const *dumpp;

	array_foreach(&dumps, dumpp) {
		if (strcmp((*dumpp)->name, name) == 0)
			return *dumpp;
	}
	return NULL;
}

static const struct doveadm_cmd_dump *
dump_find_test(const char *path)
{
	const struct doveadm_cmd_dump *const *dumpp;

	array_foreach(&dumps, dumpp) {
		if ((*dumpp)->test != NULL && (*dumpp)->test(path))
			return *dumpp;
	}
	return NULL;
}

static void cmd_dump(int argc, char *argv[])
{
	const struct doveadm_cmd_dump *dump;
	const char *type = NULL;
	int c;

	while ((c = getopt(argc, argv, "t:")) > 0) {
		switch (c) {
		case 't':
			type = optarg;
			break;
		default:
			help(&doveadm_cmd_dump);
		}
	}
	if (optind == argc)
		help(&doveadm_cmd_dump);

	optind--;
	argc -= optind;
	argv += optind;

	dump = type != NULL ? dump_find_name(type) : dump_find_test(argv[1]);
	if (dump == NULL) {
		if (type != NULL) {
			print_dump_types();
			i_fatal_status(EX_USAGE, "Unknown type: %s", type);
		} else {
			i_fatal_status(EX_DATAERR,
				"Can't autodetect file type: %s", argv[1]);
		}
	} else {
		if (type == NULL)
			printf("Detected file type: %s\n", dump->name);
	}
	dump->cmd(argc, argv);
}

struct doveadm_cmd doveadm_cmd_dump = {
	cmd_dump, "dump", "[-t <type>] <path>"
};

static void cmd_dump_multiplex(int argc ATTR_UNUSED, char *argv[])
{
	const unsigned int channels_count = 256;
	struct istream *file_input, *channels[channels_count];
	const unsigned char *data;
	size_t size;
	unsigned int i;

	file_input = i_stream_create_file(argv[1], IO_BLOCK_SIZE);
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
		i_error("read() failed: %s", i_stream_get_error(channels[0]));
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
	&doveadm_cmd_dump_zlib,
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
