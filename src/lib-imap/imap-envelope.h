#ifndef IMAP_ENVELOPE_H
#define IMAP_ENVELOPE_H

struct imap_arg;
struct message_header_line;
struct message_part_envelope_data;

extern const char *imap_envelope_headers[];

/* Update envelope data based from given header field */
void imap_envelope_parse_header(pool_t pool,
				struct message_part_envelope_data **data,
				struct message_header_line *hdr);

/* Write envelope to given string */
void imap_envelope_write_part_data(struct message_part_envelope_data *data,
				   string_t *str);

/* Parse envelope from arguments */
bool imap_envelope_parse_args(const struct imap_arg *args,
	pool_t pool, struct message_part_envelope_data **envlp_r,
	const char **error_r);

#endif
