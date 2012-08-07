#ifndef ISTREAM_ATTACHMENT_H
#define ISTREAM_ATTACHMENT_H

struct istream_attachment_header {
	struct message_part *part;
	const char *content_type, *content_disposition;
};

struct istream_attachment_info {
	const char *hash;
	/* offset within input stream where the attachment starts */
	uoff_t start_offset;
	/* original (base64-encoded) size of the attachment */
	uoff_t encoded_size;

	unsigned int base64_blocks_per_line;
	bool base64_have_crlf;

	const struct message_part *part;
};

struct istream_attachment_settings {
	/* Minimum size of of a MIME part to be saved separately. */
	uoff_t min_size;
	/* Format to use when calculating attachment's hash. */
	struct hash_format *hash_format;
	/* Set this to TRUE if parent stream can be read from as long as
	   wanted. This is useful when parsing attachments, which the extractor
	   hides from read() output, so they would return a lot of 0.
	   On the other hand if you have a tee-istream, it's not a good idea
	   to let it get to "buffer full" state. */
	bool drain_parent_input;

	/* Returns TRUE if message part is wanted to be stored as separate
	   attachment. If NULL, assume we want the attachment. */
	bool (*want_attachment)(const struct istream_attachment_header *hdr,
				void *context);
	/* Create a temporary file. */
	int (*open_temp_fd)(void *context);
	/* Create output stream for attachment */
	int (*open_attachment_ostream)(struct istream_attachment_info *info,
				       struct ostream **output_r,
				       void *context);
	/* Finish output stream */
	int (*close_attachment_ostream)(struct ostream *output, bool success,
					void *context);
};

struct istream *
i_stream_create_attachment_extractor(struct istream *input,
				     struct istream_attachment_settings *set,
				     void *context) ATTR_NULL(3);

/* Returns TRUE if the last read returned 0 only because
   drain_parent_input=FALSE and we didn't have anything to return, but
   retrying a read from parent stream could give something the next time. */
bool i_stream_attachment_extractor_can_retry(struct istream *input);

#endif
