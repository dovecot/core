#ifndef IMAP_BASE_SUBJECT_H
#define IMAP_BASE_SUBJECT_H

/* Returns the base subject of the given string, according to
   draft-ietf-imapext-sort-10. String is returned so that it's suitable for
   strcmp() comparing with another base subject.

   is_reply_or_forward is set to TRUE if message looks like reply or forward,
   according to draft-ietf-imapext-thread-12 rules. */
const char *imap_get_base_subject_cased(pool_t pool, const char *subject,
					bool *is_reply_or_forward_r);

#endif
