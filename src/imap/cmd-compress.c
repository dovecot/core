/* Copyright (c) 2010-2022 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-commands.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "compression.h"

static void client_skip_line(struct client *client)
{
	const unsigned char *data;
	size_t data_size;

	data = i_stream_get_data(client->input, &data_size);
	i_assert(data_size > 0);
	if (data[0] == '\n')
		i_stream_skip(client->input, 1);
	else if (data[0] == '\r' && data_size > 1 && data[1] == '\n')
		i_stream_skip(client->input, 2);
	else
		i_unreached();
	client->input_skip_line = FALSE;
}

static void client_update_imap_parser_streams(struct client *client)
{
	struct client_command_context *cmd;

	if (client->free_parser != NULL) {
		imap_parser_set_streams(client->free_parser,
					client->input, client->output);
	}

	for (cmd = client->command_queue; cmd != NULL; cmd = cmd->next) {
		imap_parser_set_streams(cmd->parser,
					client->input, client->output);
	}
}

bool cmd_compress(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	const struct compression_handler *handler;
	const struct imap_arg *args;
	struct istream *old_input;
	struct ostream *old_output;
	const char *mechanism;
	int level;

	/* <mechanism> */
	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	if (!imap_arg_get_atom(args, &mechanism) ||
	    !IMAP_ARG_IS_EOL(&args[1])) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}

	int ret = compression_lookup_handler(t_str_lcase(mechanism), &handler);
	if (ret <= 0) {
		const char * tagline =
			t_strdup_printf("NO %s compression mechanism",
					ret == 0 ? "Unsupported" : "Unknown");
		client_send_tagline(cmd, tagline);
		return TRUE;
	}

	client_skip_line(client);
	client_send_tagline(cmd, "OK Begin compression.");

	level = handler->get_default_level();
	old_input = client->input;
	old_output = client->output;
	client->input = handler->create_istream(old_input);
	client->output = handler->create_ostream(old_output, level);
	/* preserve output offset so that the bytes out counter in logout
	   message doesn't get reset here */
	client->output->offset = old_output->offset;
	i_stream_unref(&old_input);
	o_stream_unref(&old_output);

	client_update_imap_parser_streams(client);
	return TRUE;
}
