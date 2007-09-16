#ifndef MESSAGE_ID_H
#define MESSAGE_ID_H

/* Returns the next valid message ID from a given Message-ID header.
   The return value is allocated from data stack. */
const char *message_id_get_next(const char **msgid_p);

#endif
