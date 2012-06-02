#ifndef IMAP_MSGPART_H
#define IMAP_MSGPART_H

/* Find message_part for section (eg. 1.3.4). Returns -1 if storage error,
   0 otherwise. part_r is set to NULL if section doesn't exist. */
int imap_msgpart_find(struct mail *mail, const char *section,
		      const struct message_part **part_r,
		      const char **subsection_r);

/* Open message part refenced by IMAP section as istream. Returns 1 if
   successful, 0 if section is invalid, -1 if storage error. Returned stream_r
   stream may be NULL when there is no data to return. */
int imap_msgpart_open(struct mail *mail, const char *section,
		      uoff_t partial_offset, uoff_t partial_size,
		      struct istream **stream_r,
		      uoff_t *size_r, const char **error_r);

static inline int
imap_msgpart_verify(struct mail *mail, const char *section,
		    const char **error_r)
{
	return imap_msgpart_open(mail, section, 0, 0, NULL, NULL, error_r);
}

#endif
