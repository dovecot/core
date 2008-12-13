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
			    bool *has_nuls);
/* Calculate size of message body. */
int message_get_body_size(struct istream *input, struct message_size *body,
			  bool *has_nuls);

/* Sum contents of src into dest. */
void message_size_add(struct message_size *dest,
		      const struct message_size *src);

#endif
