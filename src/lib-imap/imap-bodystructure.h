#ifndef __IMAP_BODYSTRUCTURE_H
#define __IMAP_BODYSTRUCTURE_H

/* If *part is non-NULL, it's used as base for building the body structure.
   Otherwise it's set to the root MessagePart and parsed. */
const char *imap_part_get_bodystructure(Pool pool, MessagePart **part,
					IStream *input, int extended);

/* Return BODY part from BODYSTRUCTURE */
const char *imap_body_parse_from_bodystructure(const char *bodystructure);

#endif
