#ifndef IMAP_CLIENT_INPUT_H
#define IMAP_CLIENT_INPUT_H

enum imap_client_input_cmd {
	/* Anything that needs to be forwarded to an imap process */
	IMAP_CLIENT_INPUT_CMD_OTHER,
	IMAP_CLIENT_INPUT_CMD_DONE,
	IMAP_CLIENT_INPUT_CMD_IDLE,
	IMAP_CLIENT_INPUT_CMD_NOOP,
	IMAP_CLIENT_INPUT_CMD_CHECK,
	IMAP_CLIENT_INPUT_CMD_LOGOUT,
};

/* Parse a single line of client input. The line excludes the LF, a trailing
   CR is ignored. Only exact "DONE" and "<tag> <command>" lines without any
   extra characters are recognized. tag_r is set for the tagged commands and
   to NULL for DONE and OTHER. */
enum imap_client_input_cmd
imap_client_input_parse_line(const unsigned char *line, size_t size,
			     const char **tag_r);

#endif
