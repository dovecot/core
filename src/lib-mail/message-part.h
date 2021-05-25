#ifndef MESSAGE_PART_H
#define MESSAGE_PART_H

#include "message-size.h"

struct message_part_data;

/* Note that these flags are used directly by message-parser-serialize, so
   existing flags can't be changed without breaking backwards compatibility */
enum message_part_flags {
	MESSAGE_PART_FLAG_MULTIPART		= 0x01,
	MESSAGE_PART_FLAG_MULTIPART_DIGEST	= 0x02,
	MESSAGE_PART_FLAG_MESSAGE_RFC822	= 0x04,

	/* content-type: text/... */
	MESSAGE_PART_FLAG_TEXT			= 0x08,

	MESSAGE_PART_FLAG_UNUSED		= 0x10,

	/* message part header or body contains NULs */
	MESSAGE_PART_FLAG_HAS_NULS		= 0x20,

	/* Mime-Version header exists. */
	MESSAGE_PART_FLAG_IS_MIME		= 0x40,
	/* Message parsing was aborted because there were too many MIME parts.
	   This MIME part points to a blob which wasn't actually parsed to
	   see if it would contain further MIME parts. */
	MESSAGE_PART_FLAG_OVERFLOW		= 0x80,
};

struct message_part {
	struct message_part *parent;
	struct message_part *next;
	struct message_part *children;

	uoff_t physical_pos; /* absolute position from beginning of message */
	struct message_size header_size;
	struct message_size body_size;

	struct message_part_data *data;

	/* total number of message_parts under children */
	unsigned int children_count;
	enum message_part_flags flags;
	void *context;
};

/* Return index number for the message part. The indexes are in the same order
   as they exist in the flat RFC822 message. The root part is 0, its first
   child is 1 and so on. */
unsigned int message_part_to_idx(const struct message_part *part);
/* Find message part by its index number, or return NULL if the index
   doesn't exist. */
struct message_part *
message_part_by_idx(struct message_part *parts, unsigned int idx);

/* Returns TRUE when message parts are considered equal. Equality is determined
   to be TRUE, when

  - both parts are NULL
  - both parts are not NULL, and
    - both parts children are equal
    - both parts have same position, sizes, line counts and flags. */
bool message_part_is_equal(const struct message_part *p1,
			   const struct message_part *p2) ATTR_NULL(1, 2);

#endif
