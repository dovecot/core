#ifndef IMAP_URLAUTH_BACKEND_H
#define IMAP_URLAUTH_BACKEND_H

#define IMAP_URLAUTH_KEY_LEN 64

struct imap_urlauth_backend;

int imap_urlauth_backend_create(struct mail_user *user, const char *dict_uri,
				struct imap_urlauth_backend **backend_r);
void imap_urlauth_backend_destroy(struct imap_urlauth_backend **backend);

int imap_urlauth_backend_get_mailbox_key(struct imap_urlauth_backend *backend,
					 struct mailbox *box, bool create,
					 unsigned char mailbox_key_r[IMAP_URLAUTH_KEY_LEN],
					 const char **error_r,
					 enum mail_error *error_code_r);
int imap_urlauth_backend_reset_mailbox_key(struct imap_urlauth_backend *backend,
					   struct mailbox *box);
int imap_urlauth_backend_reset_all_keys(struct imap_urlauth_backend *backend);

#endif

