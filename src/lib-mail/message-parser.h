#ifndef __MESSAGE_PARSER_H
#define __MESSAGE_PARSER_H

typedef struct _MessagePart MessagePart;
typedef struct _MessagePosition MessagePosition;
typedef struct _MessageSize MessageSize;

struct _MessagePosition {
	off_t physical_pos;
	off_t virtual_pos;
};

struct _MessageSize {
	size_t physical_size;
	size_t virtual_size;
	unsigned int lines;
};

struct _MessagePart {
	MessagePart *parent;
	MessagePart *next;
	MessagePart *children;

        MessagePosition pos; /* absolute position from beginning of message */
	MessageSize header_size;
	MessageSize body_size;

	unsigned int multipart:1;
	unsigned int multipart_digest:1;
	unsigned int message_rfc822:1;
	unsigned int text:1; /* content-type: text/.. */
	unsigned int binary:1; /* content-transfer-encoding: binary */

	void *context;
};

/* NOTE: name and value aren't \0-terminated */
typedef void (*MessageHeaderFunc)(MessagePart *part,
				  const char *name, unsigned int name_len,
				  const char *value, unsigned int value_len,
				  void *context);

/* func is called for each field in message header. */
MessagePart *message_parse(Pool pool, IOBuffer *inbuf,
			   MessageHeaderFunc func, void *context);

/* Call func for each field in message header. Fills the hdr_size.
   part can be NULL, just make sure your header function works with it.
   This function doesn't use temp. mempool so your header function may save
   return values to it. When finished, inbuf will point to beginning of
   message body. */
void message_parse_header(MessagePart *part, IOBuffer *inbuf,
			  MessageSize *hdr_size,
			  MessageHeaderFunc func, void *context);

#endif
