#ifndef IMAP_ID_H
#define IMAP_ID_H

/* Return ID reply based on given settings. */
const char *imap_id_reply_generate(const char *settings);
/* Return a line that should be logged based on given args and settings.
   Returns NULL if nothing should be logged. */
const char *imap_id_args_get_log_reply(const struct imap_arg *args,
				       const char *settings);

#endif
