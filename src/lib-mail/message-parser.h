#ifndef __MESSAGE_PARSER_H
#define __MESSAGE_PARSER_H

#define IS_LWSP(c) \
	((c) == ' ' || (c) == '\t')

enum message_part_flags {
	MESSAGE_PART_FLAG_MULTIPART		= 0x01,
	MESSAGE_PART_FLAG_MULTIPART_DIGEST	= 0x02,
	MESSAGE_PART_FLAG_MESSAGE_RFC822	= 0x04,

	/* content-type: text/... */
	MESSAGE_PART_FLAG_TEXT			= 0x08,

	/* content-transfer-encoding: binary */
	MESSAGE_PART_FLAG_BINARY		= 0x10
};

struct message_size {
	uoff_t physical_size;
	uoff_t virtual_size;
	unsigned int lines;
};

struct message_part {
	struct message_part *parent;
	struct message_part *next;
	struct message_part *children;

	uoff_t physical_pos; /* absolute position from beginning of message */
	struct message_size header_size;
	struct message_size body_size;

	enum message_part_flags flags;
	void *context;
};

/* NOTE: name and value aren't \0-terminated. Also called once at end of
   headers with name_len = value_len = 0. */
typedef void (*message_header_callback_t)(struct message_part *part,
					  const unsigned char *name,
					  size_t name_len,
					  const unsigned char *value,
					  size_t value_len,
					  void *context);

/* callback is called for each field in message header. */
struct message_part *message_parse(pool_t pool, struct istream *input,
				   message_header_callback_t callback,
				   void *context);

/* Call callback for each field in message header. Fills the hdr_size.
   part can be NULL, just make sure your header function works with it.
   This function doesn't use data stack so your header function may save
   values to it. When finished, input will point to beginning of message
   body. */
void message_parse_header(struct message_part *part, struct istream *input,
			  struct message_size *hdr_size,
			  message_header_callback_t callback, void *context);

#endif
