/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "istream.h"
#include "imap-parser.h"
#include "imap-client-input.h"

static const struct {
	const char *name;
	enum imap_client_input_cmd cmd;
} imap_client_input_cmds[] = {
	{ "IDLE", IMAP_CLIENT_INPUT_CMD_IDLE },
	{ "NOOP", IMAP_CLIENT_INPUT_CMD_NOOP },
	{ "CHECK", IMAP_CLIENT_INPUT_CMD_CHECK },
	{ "LOGOUT", IMAP_CLIENT_INPUT_CMD_LOGOUT },
};

static bool
imap_client_input_word_equals(const unsigned char *data, size_t size,
			      const char *word)
{
	return size == strlen(word) &&
		strncasecmp((const char *)data, word, size) == 0;
}

static enum imap_client_input_cmd
imap_client_input_parse_cmd(struct istream *input, struct imap_parser *parser,
			    const char **tag_r)
{
	const unsigned char *name;
	const char *tag;
	size_t name_size;
	unsigned int i;

	/* the tag must be followed by a space, so this fails also if there
	   is no command name */
	if (imap_parser_read_tag(parser, &tag) <= 0)
		return IMAP_CLIENT_INPUT_CMD_OTHER;
	/* None of the recognized commands have parameters, so the rest of
	   the line must be exactly the command name. */
	name = i_stream_get_data(input, &name_size);
	for (i = 0; i < N_ELEMENTS(imap_client_input_cmds); i++) {
		if (imap_client_input_word_equals(name, name_size,
						  imap_client_input_cmds[i].name)) {
			*tag_r = t_strdup(tag);
			return imap_client_input_cmds[i].cmd;
		}
	}
	return IMAP_CLIENT_INPUT_CMD_OTHER;
}

enum imap_client_input_cmd
imap_client_input_parse_line(const unsigned char *line, size_t size,
			     const char **tag_r)
{
	enum imap_client_input_cmd cmd;

	*tag_r = NULL;
	if (size > 0 && line[size-1] == '\r')
		size--;
	if (imap_client_input_word_equals(line, size, "DONE"))
		return IMAP_CLIENT_INPUT_CMD_DONE;

	struct istream *input = i_stream_create_from_data(line, size);
	struct imap_parser *parser =
		imap_parser_create(input, NULL, size, NULL);
	cmd = imap_client_input_parse_cmd(input, parser, tag_r);
	imap_parser_unref(&parser);
	i_stream_unref(&input);
	return cmd;
}
