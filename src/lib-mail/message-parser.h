#ifndef __MESSAGE_PARSER_H
#define __MESSAGE_PARSER_H

typedef struct _MessagePart MessagePart;
typedef struct _MessagePosition MessagePosition;
typedef struct _MessageSize MessageSize;

typedef enum {
	MESSAGE_PART_FLAG_MULTIPART		= 0x01,
	MESSAGE_PART_FLAG_MULTIPART_DIGEST	= 0x02,
	MESSAGE_PART_FLAG_MESSAGE_RFC822	= 0x04,

	/* content-type: text/... */
	MESSAGE_PART_FLAG_TEXT			= 0x08,

	/* content-transfer-encoding: binary */
	MESSAGE_PART_FLAG_BINARY		= 0x10
} MessagePartFlags;

struct _MessageSize {
	uoff_t physical_size;
	uoff_t virtual_size;
	unsigned int lines;
};

struct _MessagePart {
	MessagePart *parent;
	MessagePart *next;
	MessagePart *children;

	uoff_t physical_pos; /* absolute position from beginning of message */
	MessageSize header_size;
	MessageSize body_size;

	MessagePartFlags flags;
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
