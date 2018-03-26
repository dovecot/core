#ifndef SMTP_COMMAND_PARSER_H
#define SMTP_COMMAND_PARSER_H

#include "smtp-command.h"

/* FIXME: drop unused */
enum smtp_command_parse_error {
	SMTP_COMMAND_PARSE_ERROR_NONE = 0,           /* no error */
	SMTP_COMMAND_PARSE_ERROR_BROKEN_STREAM,      /* stream error */
	SMTP_COMMAND_PARSE_ERROR_BROKEN_COMMAND,     /* unrecoverable generic error */
	SMTP_COMMAND_PARSE_ERROR_BAD_COMMAND,        /* recoverable generic error */
	SMTP_COMMAND_PARSE_ERROR_LINE_TOO_LONG,      /* stream error */
	SMTP_COMMAND_PARSE_ERROR_DATA_TOO_LARGE      /* data too large (fatal) */
};

struct smtp_command_parser *
smtp_command_parser_init(struct istream *input,
			 const struct smtp_command_limits *limits)
	ATTR_NULL(2);
void smtp_command_parser_deinit(struct smtp_command_parser **_parser);

void smtp_command_parser_set_stream(struct smtp_command_parser *parser,
	struct istream *input);

/* Returns 1 if a command was returned, 0 if more data is needed, -1 on error,
   -2 if disconnected in SMTP_COMMAND_PARSE_STATE_INIT state. -2 is mainly for
   unit tests - it can normally be treated the same as -1. */
int smtp_command_parse_next(struct smtp_command_parser *parser,
			    const char **cmd_name_r, const char **cmd_params_r,
			    enum smtp_command_parse_error *error_code_r, const char **error_r);

struct istream *
smtp_command_parse_data_with_size(struct smtp_command_parser *parser,
	uoff_t size);
struct istream *
smtp_command_parse_data_with_dot(struct smtp_command_parser *parser);
bool smtp_command_parser_pending_data(struct smtp_command_parser *parser);

/* Returns the same as smtp_command_parse_next() */
int smtp_command_parse_auth_response(struct smtp_command_parser *parser,
			    const char **line_r, enum smtp_command_parse_error *error_code_r,
			    const char **error_r);

#endif
