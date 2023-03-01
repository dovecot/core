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
/* Truncate excessively large IMAP ID parameters in log lines. */
#define IMAP_ID_PARAMS_LOG_MAX_LEN 1024

/* Return ID reply based on given settings. */
const char *imap_id_reply_generate(const char *settings);
/* Format the IMAP ID parameters into string-fields of the given event, and
   into a printable log message. */
void imap_id_add_log_entry(struct imap_id_log_entry *log_entry,
			   const char *key, const char *value);

#endif
