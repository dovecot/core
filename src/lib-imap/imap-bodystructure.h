#ifndef __IMAP_BODYSTRUCTURE_H
#define __IMAP_BODYSTRUCTURE_H

/* If *part is non-NULL, it's used as base for building the body structure.
   Otherwise it's set to the root MessagePart and parsed. */
const char *imap_part_get_bodystructure(Pool pool, MessagePart **part,
					IOBuffer *inbuf, int extended);

#endif
