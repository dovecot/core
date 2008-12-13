#ifndef MESSAGE_SEND_H
#define MESSAGE_SEND_H

struct message_size;

/* Skip number of virtual bytes from putfer. msg_size is updated if it's not
   NULL. If cr_skipped is TRUE and first character is \n, it's not treated as
   \r\n. last_cr is set to TRUE if last character we skipped was \r, meaning
   that next character should be \n and you shouldn't treat it as \r\n. */
int message_skip_virtual(struct istream *input, uoff_t virtual_skip,
			 struct message_size *msg_size,
			 bool cr_skipped, bool *last_cr);

#endif
