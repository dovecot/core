#ifndef IMAP_MSGPART_H
#define IMAP_MSGPART_H

struct imap_msgpart;

struct imap_msgpart_open_result {
	/* message contents with CRLF linefeeds */
	struct istream *input;
	/* size of input */
	uoff_t size;
	/* if size was looked up using cache and it ends up being wrong,
	   this field can be used to log about cache corruption */
	enum mail_fetch_field size_field;
	/* TRUE if BINARY decoded content contains NUL characters */
	bool binary_decoded_input_has_nuls;
};

struct imap_msgpart *imap_msgpart_full(void);
struct imap_msgpart *imap_msgpart_header(void);
struct imap_msgpart *imap_msgpart_body(void);
/* Parse section into imap_msgpart. Returns 0 and msgpart_r on success,
   -1 if the section isn't valid. The same imap_msgpart can be used to open
   multiple messages. */
int imap_msgpart_parse(const char *section, struct imap_msgpart **msgpart_r);
void imap_msgpart_free(struct imap_msgpart **msgpart);

/* Decode MIME parts with Content-Transfer-Encoding: base64/quoted-printable
   to binary data (IMAP BINARY extension). If something can't be decoded, fails
   with storage error set to MAIL_ERROR_CONVERSION. */
void imap_msgpart_set_decode_to_binary(struct imap_msgpart *msgpart);

/* Set the fetch to be partial. For unlimited size use (uoff_t)-1. */
void imap_msgpart_set_partial(struct imap_msgpart *msgpart,
			      uoff_t offset, uoff_t size);
uoff_t imap_msgpart_get_partial_offset(struct imap_msgpart *msgpart);
uoff_t imap_msgpart_get_partial_size(struct imap_msgpart *msgpart);
/* Return wanted_fields mask. */
enum mail_fetch_field imap_msgpart_get_fetch_data(struct imap_msgpart *msgpart);

/* Open message part refenced by IMAP section as istream. Returns 0 if
   successful, -1 if storage error. Returned istream is initially referenced,
   so i_stream_unref() must be called for it. */
int imap_msgpart_open(struct mail *mail, struct imap_msgpart *msgpart,
		      struct imap_msgpart_open_result *result_r);
/* Return msgpart's size without actually opening the stream (if possible). */
int imap_msgpart_size(struct mail *mail, struct imap_msgpart *msgpart,
		      uoff_t *size_r);

/* Return msgpart's IMAP BODYPARTSTRUCTURE */
int imap_msgpart_bodypartstructure(struct mail *mail,
				   struct imap_msgpart *msgpart,
				   const char **bpstruct_r);

/* Header context is automatically created by imap_msgpart_open() and destroyed
   by imap_msgpart_free(), but if you want to use the same imap_msgpart across
   multiple mailboxes, you need to close the part before closing the mailbox. */
void imap_msgpart_close_mailbox(struct imap_msgpart *msgpart);

#endif
