#ifndef MESSAGE_BINARY_PART_H
#define MESSAGE_BINARY_PART_H

struct message_binary_part {
	struct message_binary_part *next;

	/* Absolute position from beginning of message. This can be used to
	   match the part to struct message_part. */
	uoff_t physical_pos;
	/* Decoded binary header/body size. The binary header size may differ
	   from message_part's, because Content-Transfer-Encoding is changed to
	   "binary". */
	uoff_t binary_hdr_size;
	uoff_t binary_body_size;
	/* BODYSTRUCTURE for text/ and message/rfc822 parts includes lines
	   count. Decoding may change these numbers. */
	unsigned int binary_body_lines_count;
};

/* Serialize message binary_part. */
void message_binary_part_serialize(const struct message_binary_part *parts,
				   buffer_t *dest);

/* Generate struct message_binary_part from serialized data. Returns 0 if ok,
   -1 if any problems are detected. */
int message_binary_part_deserialize(pool_t pool, const void *data, size_t size,
				    struct message_binary_part **parts_r);

#endif
