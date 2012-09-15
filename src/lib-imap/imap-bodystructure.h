#ifndef IMAP_BODYSTRUCTURE_H
#define IMAP_BODYSTRUCTURE_H

struct message_part_body_data {
	pool_t pool;
	/* NOTE: all the strings are stored via imap_quote(), so they contain
	   "quoted-text" or {123}\r\nliterals */
	const char *content_type, *content_subtype;
	const char *content_type_params; /* "key" "value" "key2" "value2" .. */
	const char *content_transfer_encoding;
	const char *content_id;
	const char *content_description;
	const char *content_disposition;
	const char *content_disposition_params; /* "key" "value" "key2" "value2" .. */
	const char *content_md5;
	const char *content_language; /* "lang1" "lang2" "lang3" .. */
	const char *content_location;

	/* either one of these is set, but not both: */
	struct message_part_envelope_data *envelope;
	const char *envelope_str;
};

struct message_part;
struct message_header_line;

/* Parse a single header. Note that this modifies part->context. */
void imap_bodystructure_parse_header(pool_t pool, struct message_part *part,
				     struct message_header_line *hdr);

/* Returns TRUE if BODYSTRUCTURE is
   ("text" "plain" ("charset" "us-ascii") NIL NIL "7bit" n n NIL NIL NIL) */
bool imap_bodystructure_is_plain_7bit(const struct message_part *part)
	ATTR_PURE;

/* Write a BODY/BODYSTRUCTURE from given message_part. The
   message_part->contexts must contain struct message_part_body_data.
   part->body_size.virtual_size and .lines are also used for writing it. */
void imap_bodystructure_write(const struct message_part *part,
			      string_t *dest, bool extended);

/* Parse BODYSTRUCTURE and save the contents to message_part->contexts.
   Returns 0 if ok, -1 if bodystructure wasn't valid. */
int imap_bodystructure_parse(const char *bodystructure, pool_t pool,
			     struct message_part *parts, const char **error_r);

/* Get BODY part from BODYSTRUCTURE and write it to dest.
   Returns 0 if ok, -1 if bodystructure wasn't valid. */
int imap_body_parse_from_bodystructure(const char *bodystructure,
				       string_t *dest, const char **error_r);

#endif
