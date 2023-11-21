/* Copyright (c) 2023 Dovecot Oy, see the included COPYING file */

#include "lib.h"
#include "randgen.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-temp.h"

#include "json-istream.h"
#include "json-ostream.h"

#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

static bool debug = FALSE;

/*
 * File I/O
 */

static void
json_format_file_io_run(struct istream *input, struct ostream *output,
			const struct json_format *json_format)
{
	struct json_istream *jinput;
	struct json_ostream *joutput;
	struct json_node jnode;
	struct json_limits json_limits;
	const char *error;
	int rret, wret;

	i_zero(&json_limits);
	json_limits.max_name_size = SIZE_MAX;
	json_limits.max_string_size = SIZE_MAX;
	json_limits.max_nesting = UINT_MAX;
	json_limits.max_list_items = UINT_MAX;

	jinput = json_istream_create(input, 0, &json_limits, 0);
	joutput = json_ostream_create(output, 0);
	json_ostream_set_format(joutput, json_format);

	rret = 0; wret = 1;
	i_zero(&jnode);
	for (;;) {
		if (wret > 0 && rret == 0) {
			rret = json_istream_walk_stream(jinput,
							16 * IO_BLOCK_SIZE,
							IO_BLOCK_SIZE,
							NULL, &jnode);
			i_assert(rret != 0);
			if (rret < 0)
				break;
		}
		if (json_node_is_none(&jnode))
			wret = 1;
		else
			wret = json_ostream_write_node(joutput, &jnode, TRUE);
		i_assert(wret != 0);
		if (wret < 0)
			break;
		i_zero(&jnode);
		rret = 0;
	}
	wret = json_ostream_flush(joutput);

	if (json_istream_finish(&jinput, &error) < 0)
		i_error("Failed to read JSON: %s", error);
	if (wret < 0) {
		i_error("Failed to write JSON: %s",
			json_ostream_get_error(joutput));
	}
	json_ostream_destroy(&joutput);
}

static void
json_format_file_io(const char *file, const struct json_format *json_format)
{
	struct istream *input;
	struct ostream *output;
	int fd_in, fd_out;

	if ((fd_in = open(file, O_RDONLY)) < 0)
		i_fatal("Failed to open for reading: %m");
	fd_out = 1;

	input = i_stream_create_fd_autoclose(&fd_in, 1024);
	output = o_stream_create_fd_autoclose(&fd_out, 1024);
	json_format_file_io_run(input, output, json_format);
	i_stream_unref(&input);
	o_stream_unref(&output);
}

int main(int argc, char *argv[])
{
	struct json_format json_format;
	int c;

	lib_init();

	i_zero(&json_format);
	json_format.indent_chars = 2;
	json_format.new_line = TRUE;
	json_format.whitespace = TRUE;

	while ((c = getopt(argc, argv, "Di:n")) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		case 'i':
			if (str_to_uint(optarg,
					&json_format.indent_chars) < 0) {
				i_fatal("Invalid number of indent characters.");
			}
			break;
		case 'n':
			json_format.new_line = FALSE;
			break;
		default:
			i_fatal("Usage: %s [-D] [-i <indent-chars>] [-n] "
				"<json-file>", argv[0]);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 1 ) {
		i_fatal("Usage: %s [-D] [-i <indent>] [-n] "
			"<json-file>", argv[0]);
	}

	json_format_file_io(argv[0], &json_format);

	lib_deinit();
	return 0;
}
