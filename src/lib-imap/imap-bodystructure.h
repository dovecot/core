#ifndef IMAP_BODYSTRUCTURE_H
#define IMAP_BODYSTRUCTURE_H

struct message_part_param {
	const char *name;
	const char *value;
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

	struct message_part_envelope_data *envelope;
};

struct message_part;
struct message_header_line;

/* Parse a single header. Note that this modifies part->data. */
void message_part_data_parse_from_header(pool_t pool,
	struct message_part *part,
	struct message_header_line *hdr);

/* Returns TRUE if this message part has content-type "text/plain",
   chaset "us-ascii" and content-tranfer-encoding "7bit" */
bool message_part_data_is_plain_7bit(const struct message_part *part)
	ATTR_PURE;

/* Write a BODY/BODYSTRUCTURE from given message_part. The message_part->data
   field must be set. part->body_size.virtual_size and .lines are also used
   for writing it. */
void imap_bodystructure_write(const struct message_part *part,
			      string_t *dest, bool extended);

/* Parse BODYSTRUCTURE and save the contents to message_part->data for each
   message tree node. Returns 0 if ok, -1 if bodystructure wasn't valid. */
int imap_bodystructure_parse(const char *bodystructure, pool_t pool,
			     struct message_part *parts, const char **error_r);

/* Get BODY part from BODYSTRUCTURE and write it to dest.
   Returns 0 if ok, -1 if bodystructure wasn't valid. */
int imap_body_parse_from_bodystructure(const char *bodystructure,
				       string_t *dest, const char **error_r);

#endif
