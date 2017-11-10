#ifndef MESSAGE_PART_DATA_H
#define MESSAGE_PART_DATA_H

#include "message-part.h"

#define MESSAGE_PART_DEFAULT_CHARSET "us-ascii"

struct message_header_line;

struct message_part_param {
	const char *name;
	const char *value;
};

struct message_part_envelope {
	const char *date, *subject;
	struct message_address *from, *sender, *reply_to;
	struct message_address *to, *cc, *bcc;

	const char *in_reply_to, *message_id;
};

struct message_part_data {
	const char *content_type, *content_subtype;
	const struct message_part_param *content_type_params;
	unsigned int content_type_params_count;

	const char *content_transfer_encoding;
	const char *content_id;
	const char *content_description;
	const char *content_disposition;
	const struct message_part_param *content_disposition_params;
	unsigned int content_disposition_params_count;
	const char *content_md5;
	const char *const *content_language;
	const char *content_location;

	struct message_part_envelope *envelope;
};

struct message_part_attachment_settings {
	/* By default, all attachments with content-disposition=attachment
	   or content-disposition=inline;filename=... are consired as an
	   attachment.

	   If content_type_filter is set to an array of masks, then
	   anything starting with ! is excluded, and anything without
	   is considered negating exclusion. Setting foo/bar alone will */
//	   not do anything, but setting !foo/*, foo/bar, will exclude
	/* all attachments with foo/anything content type, but will
	   accept foo/bar.

	   Setting exclude_inlined, will exclude **any** inlined attachment
	   regardless of what content_type_filter is.
	*/
	const char *const *content_type_filter;
	bool exclude_inlined;
};

extern const char *message_part_envelope_headers[];

/*
 *
 */

/* Returns TRUE if this message part has content-type "text/plain",
   chaset "us-ascii" and content-tranfer-encoding "7bit" */
bool message_part_data_is_plain_7bit(const struct message_part *part)
	ATTR_PURE;

/* Returns TRUE if this message part has a filename. The filename is
   returned in filename_r. */
bool message_part_data_get_filename(const struct message_part *part,
	const char **filename_r);

/* See message_part_attachment_settings */
bool message_part_has_content_types(struct message_part *part, const char *const *types);

/* Returns TRUE if message part has given parameter, and has non-empty
   value if has_value is TRUE. */
bool message_part_has_parameter(struct message_part *part, const char *parameter,
				bool has_value);

/* Check if part is attachment according to given settings */
bool message_part_is_attachment(struct message_part *part,
				const struct message_part_attachment_settings *set);
/*
 * Header parsing
 */

/* Update envelope data based from given header field */
void message_part_envelope_parse_from_header(pool_t pool,
	struct message_part_envelope **_data,
	struct message_header_line *hdr);

/* Parse a single header. Note that this modifies part->context. */
void message_part_data_parse_from_header(pool_t pool,
	struct message_part *part,
	struct message_header_line *hdr);

#endif
