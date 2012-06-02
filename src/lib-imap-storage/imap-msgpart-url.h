#ifndef IMAP_MSGPART_URL_H
#define IMAP_MSGPART_URL_H

struct imap_url;
struct imap_msgpart_url;

struct imap_msgpart_url *
imap_msgpart_url_create(struct mail_user *user, const struct imap_url *url);
struct imap_msgpart_url *
imap_msgpart_url_parse(struct mail_user *user, struct mailbox *selected_box,
		       const char *urlstr, const char **error_r);

struct mailbox *
imap_msgpart_url_open_mailbox(struct imap_msgpart_url *mpurl,
			      const char **error_r);
struct mailbox *imap_msgpart_url_get_mailbox(struct imap_msgpart_url *mpurl);
struct mail *
imap_msgpart_url_open_mail(struct imap_msgpart_url *mpurl, const char **error_r);

/* Returns NULL stream when part has zero length, e.g. when partial offset is
   larger than the size of the referenced part */
bool imap_msgpart_url_read_part(struct imap_msgpart_url *mpurl,
				struct istream **stream_r, uoff_t *size_r,
				const char **error_r);
bool imap_msgpart_url_verify(struct imap_msgpart_url *mpurl,
			     const char **error_r);
void imap_msgpart_url_free(struct imap_msgpart_url **mpurl);

#endif
