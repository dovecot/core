#ifndef __IMAP_BASE_SUBJECT_H
#define __IMAP_BASE_SUBJECT_H

/* Returns the base subject of the given string, according to
   draft-ietf-imapext-sort-10. String is returned so that it's suitable for
   strcmp() comparing with another base subject. */
const char *imap_get_base_subject_cased(pool_t pool, const char *subject);

#endif
