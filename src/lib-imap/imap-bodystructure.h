#ifndef __IMAP_BODYSTRUCTURE_H
#define __IMAP_BODYSTRUCTURE_H

struct message_part;
struct message_header_line;

/* Parse a single header. Note that this modifies part->context. */
void imap_bodystructure_parse_header(pool_t pool, struct message_part *part,
				     struct message_header_line *hdr);

/* Returns TRUE if BODYSTRUCTURE is
   ("text" "plain" ("charset" "us-ascii") NIL NIL "7bit" n n NIL NIL NIL) */
int imap_bodystructure_is_plain_7bit(struct message_part *part);

void imap_bodystructure_write(struct message_part *part,
			      string_t *dest, int extended);

/* Return BODY part from BODYSTRUCTURE */
int imap_body_parse_from_bodystructure(const char *bodystructure,
				       string_t *dest);

#endif
