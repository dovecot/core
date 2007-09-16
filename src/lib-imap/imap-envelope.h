#ifndef IMAP_ENVELOPE_H
#define IMAP_ENVELOPE_H

struct message_header_line;

enum imap_envelope_field {
	/* NOTE: in the same order as listed in ENVELOPE */
	IMAP_ENVELOPE_DATE = 0,
	IMAP_ENVELOPE_SUBJECT,
	IMAP_ENVELOPE_FROM,
	IMAP_ENVELOPE_SENDER,
	IMAP_ENVELOPE_REPLY_TO,
	IMAP_ENVELOPE_TO,
	IMAP_ENVELOPE_CC,
	IMAP_ENVELOPE_BCC,
	IMAP_ENVELOPE_IN_REPLY_TO,
	IMAP_ENVELOPE_MESSAGE_ID,

	IMAP_ENVELOPE_FIELDS
};

enum imap_envelope_result_type {
	IMAP_ENVELOPE_RESULT_TYPE_STRING,
	IMAP_ENVELOPE_RESULT_TYPE_FIRST_MAILBOX
};

struct message_part_envelope_data;

extern const char *imap_envelope_headers[];

bool imap_envelope_get_field(const char *name, enum imap_envelope_field *ret);

/* Update envelope data based from given header field */
void imap_envelope_parse_header(pool_t pool,
				struct message_part_envelope_data **data,
				struct message_header_line *hdr);

/* Write envelope to given string */
void imap_envelope_write_part_data(struct message_part_envelope_data *data,
				   string_t *str);

/* Parse envelope and store specified field to result. NIL is stored as NULL.
   Returns TRUE if successful. */
bool imap_envelope_parse(const char *envelope, enum imap_envelope_field field,
			 enum imap_envelope_result_type result_type,
			 const char **result);

#endif
