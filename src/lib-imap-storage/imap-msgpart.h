#ifndef IMAP_MSGPART_H
#define IMAP_MSGPART_H

struct imap_msgpart;

struct imap_msgpart_open_result {
	struct istream *input;
	uoff_t size;
	enum mail_fetch_field size_field;
};

struct imap_msgpart *imap_msgpart_full(void);
struct imap_msgpart *imap_msgpart_header(void);
struct imap_msgpart *imap_msgpart_body(void);
/* Parse section into imap_msgpart. Returns 0 and msgpart_r on success,
   -1 if the section isn't valid. The same imap_msgpart can be used to open
   multiple messages. */
int imap_msgpart_parse(struct mailbox *box, const char *section,
		       struct imap_msgpart **msgpart_r);
void imap_msgpart_free(struct imap_msgpart **msgpart);

/* Set the fetch to be partial. For unlimited size use (uoff_t)-1. */
void imap_msgpart_set_partial(struct imap_msgpart *msgpart,
			      uoff_t offset, uoff_t size);
uoff_t imap_msgpart_get_partial_offset(struct imap_msgpart *msgpart);
/* Return wanted_fields mask. */
enum mail_fetch_field imap_msgpart_get_fetch_data(struct imap_msgpart *msgpart);

/* Open message part refenced by IMAP section as istream. Returns 0 if
   successful, -1 if storage error. Returned istream is initially referenced,
   so i_stream_unref() must be called for it. */
int imap_msgpart_open(struct mail *mail, struct imap_msgpart *msgpart,
		      struct imap_msgpart_open_result *result_r);

#endif
