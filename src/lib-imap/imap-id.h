#ifndef IMAP_ID_H
#define IMAP_ID_H

struct imap_arg;

/* RFC 2971 says keys are max. 30 octets */
#define IMAP_ID_KEY_MAX_LEN 30

/* Return ID reply based on given settings. */
const char *imap_id_reply_generate(const char *settings);
/* Return a line that should be logged based on given args and settings.
   Returns NULL if nothing should be logged. */
const char *imap_id_args_get_log_reply(const struct imap_arg *args,
				       const char *settings);
/* Append [, ]key=value to the reply sanitized. */
void imap_id_log_reply_append(string_t *reply, const char *key,
			      const char *value);

#endif
