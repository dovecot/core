#ifndef __IMAP_ENVELOPE_H
#define __IMAP_ENVELOPE_H

typedef struct _MessagePartEnvelopeData MessagePartEnvelopeData;

typedef enum {
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
} ImapEnvelopeField;

/* Update envelope data based from given header field */
void imap_envelope_parse_header(Pool pool, MessagePartEnvelopeData **data,
				const char *name,
				const char *value, size_t value_len);

/* Write envelope to given string */
void imap_envelope_write_part_data(MessagePartEnvelopeData *data,
				   TempString *str);
/* Return envelope. */
const char *imap_envelope_get_part_data(MessagePartEnvelopeData *data);

/* Parse envelope and return specified field unquoted, or NULL if error
   occured. NILs are returned as "". */
const char *imap_envelope_parse(const char *envelope, ImapEnvelopeField field);

#endif
