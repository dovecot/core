#ifndef __IMAP_BODYSTRUCTURE_H
#define __IMAP_BODYSTRUCTURE_H

struct message_part;
struct message_header_line;

/* Parse a single header. Note that this modifies part->context. */
void imap_bodystructure_parse_header(pool_t pool, struct message_part *part,
				     struct message_header_line *hdr);

const char *imap_bodystructure_parse_finish(struct message_part *root,
					    int extended);

/* Return BODY part from BODYSTRUCTURE */
const char *imap_body_parse_from_bodystructure(const char *bodystructure);

#endif
