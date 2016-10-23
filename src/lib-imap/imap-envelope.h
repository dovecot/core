#ifndef IMAP_ENVELOPE_H
#define IMAP_ENVELOPE_H

struct imap_arg;
struct message_part_envelope;

/* Write envelope to given string */
void imap_envelope_write(struct message_part_envelope *data,
				   string_t *str);

/* Parse envelope from arguments */
bool imap_envelope_parse_args(const struct imap_arg *args,
	pool_t pool, struct message_part_envelope **envlp_r,
	const char **error_r);

#endif
