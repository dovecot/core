#ifndef __MESSAGE_SEND_H
#define __MESSAGE_SEND_H

struct message_size;

/* Send message to client inserting CRs if needed. Only max_virtual_size
   bytes are sent. If cr_skipped is FALSE and input begins with LF, it's
   treated as CRLF. last_cr is set to 1, 0 or -1 if not known. Returns number
   of bytes sent, or -1 if error. */
off_t message_send(struct ostream *output, struct istream *input,
		   const struct message_size *msg_size,
		   int cr_skipped, uoff_t max_virtual_size, int *last_cr,
		   int fix_nuls);

/* Skip number of virtual bytes from putfer. msg_size is updated if it's not
   NULL. If cr_skipped is TRUE and first character is \n, it's not treated as
   \r\n. last_cr is set to TRUE if last character we skipped was \r, meaning
   that next character should be \n and you shouldn't treat it as \r\n. */
void message_skip_virtual(struct istream *input, uoff_t virtual_skip,
			  struct message_size *msg_size,
			  int cr_skipped, int *last_cr);

#endif
