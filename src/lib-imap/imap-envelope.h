#ifndef __IMAP_ENVELOPE_H
#define __IMAP_ENVELOPE_H

typedef struct _MessagePartEnvelopeData MessagePartEnvelopeData;

void imap_envelope_parse_header(Pool pool, MessagePartEnvelopeData **data,
				const char *name,
				const char *value, size_t value_len);

void imap_envelope_write_part_data(MessagePartEnvelopeData *data,
				   TempString *str);
const char *imap_envelope_get_part_data(MessagePartEnvelopeData *data);

#endif
