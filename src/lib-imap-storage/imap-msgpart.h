#ifndef IMAP_MSGPART_H
#define IMAP_MSGPART_H

/* Find message_part for section (eg. 1.3.4) */
int imap_msgpart_find(struct mail *mail, const char *section,
		      const struct message_part **part_r,
		      const char **subsection_r);

/* Open message part refenced by IMAP section as istream. Returns TRUE on
   success and FALSE otherwise. Returned stream_r stream may be NULL when there
   is no data to return. */
bool imap_msgpart_open(struct mail *mail, const char *section,
		       uoff_t partial_offset, uoff_t partial_size,
		       struct istream **stream_r,
		       uoff_t *size_r, const char **error_r);

static inline bool
imap_msgpart_verify(struct mail *mail, const char *section,
		    const char **error_r)
{
	return imap_msgpart_open(mail, section, 0, 0, NULL, NULL, error_r);
}

#endif
