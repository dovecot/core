#ifndef MESSAGE_SIZE_H
#define MESSAGE_SIZE_H

struct message_size {
	uoff_t physical_size;
	uoff_t virtual_size;
	unsigned int lines;
};

/* Calculate size of message header. Leave the input point to first
   character in body. */
int message_get_header_size(struct istream *input, struct message_size *hdr,
			    bool *has_nuls_r);
/* Calculate size of message body. */
int message_get_body_size(struct istream *input, struct message_size *body,
			  bool *has_nuls_r);

/* Sum contents of src into dest. */
void message_size_add(struct message_size *dest,
		      const struct message_size *src);

/* Skip a number of bytes in the input stream, counting LFs as CRLFs.
   last_virtual_cr_r is set to TRUE if the last character we skipped was a
   virtual (nonexistent in istream) '\r', meaning that the next character in
   the input stream is "\n", which means be treated as plain "\n",
   not "\r\n". */
int message_skip_virtual(struct istream *input, uoff_t virtual_skip,
			 bool *last_virtual_cr_r);

#endif
