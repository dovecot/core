#ifndef IMAP_ID_H
#define IMAP_ID_H

struct imap_arg;

struct imap_id_log_entry {
	struct event *event;
	string_t *reply;
	/* Enumerator variable that increments per ID parameter with invalid
	   characters. For convenience reasons the value is pre-incremented,
	   under the assumption that the value is initialized to 0, it will
	   start enumerating the value with 1. */
	unsigned int invalid_key_id_counter;
};

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
/* Format the IMAP ID parameters into string-fields of the given event, and
   into a printable log message. */
void imap_id_add_log_entry(struct imap_id_log_entry *log_entry,
			   const char *key, const char *value);

#endif
