#ifndef __IMAP_BODYSTRUCTURE_H
#define __IMAP_BODYSTRUCTURE_H

struct message_part;

/* If *part is non-NULL, it's used as base for building the body structure.
   Otherwise it's set to the root message_part and parsed. pool is used only
   for allocating message_part, not the return value which is from data
   stack. */
const char *imap_part_get_bodystructure(pool_t pool, struct message_part **part,
					struct istream *input, int extended);

/* Return BODY part from BODYSTRUCTURE */
const char *imap_body_parse_from_bodystructure(const char *bodystructure);

#endif
