#ifndef IMAP_METADATA_H
#define IMAP_METADATA_H

#define IMAP_METADATA_PRIVATE_PREFIX "/private"
#define IMAP_METADATA_SHARED_PREFIX "/shared"

struct imap_metadata_iter;
struct imap_metadata_transaction;

/* Checks whether IMAP metadata entry name is valid */
bool imap_metadata_verify_entry_name(
	const char *name, const char **client_error_r);

/* Set IMAP metadata entry to value. */
int imap_metadata_set(struct imap_metadata_transaction *imtrans,
	const char *entry, const struct mail_attribute_value *value);
/* Delete IMAP metadata entry. This is just a wrapper to
   imap_metadata_set() with value->value=NULL. */
int imap_metadata_unset(struct imap_metadata_transaction *imtrans,
	const char *entry);
/* Returns value for IMAP metadata entry. Returns 1 if value was returned,
   0 if value wasn't found (set to NULL), -1 if error */
int imap_metadata_get(struct imap_metadata_transaction *imtrans,
	const char *entry, struct mail_attribute_value *value_r);
/* Same as imap_metadata_get(), but the returned value may be either an
   input stream or a string. */
int imap_metadata_get_stream(struct imap_metadata_transaction *imtrans,
	const char *entry, struct mail_attribute_value *value_r);

/* Iterate through IMAP metadata entries names under the specified entry. */
struct imap_metadata_iter *
imap_metadata_iter_init(struct imap_metadata_transaction *imtrans,
	const char *entry);
/* Returns the next IMAP metadata entry name or NULL if there are no more
   entries. */
const char *imap_metadata_iter_next(struct imap_metadata_iter *iter);
int imap_metadata_iter_deinit(struct imap_metadata_iter **_iter);

struct imap_metadata_transaction *
imap_metadata_transaction_begin(struct mailbox *box);
struct imap_metadata_transaction *
imap_metadata_transaction_begin_mailbox(struct mail_user *user,
					const char *mailbox);
struct imap_metadata_transaction *
imap_metadata_transaction_begin_server(struct mail_user *user);

int imap_metadata_transaction_commit(
	struct imap_metadata_transaction **_imtrans,
	enum mail_error *error_code_r, const char **client_error_r);
void imap_metadata_transaction_rollback(
	struct imap_metadata_transaction **_imtrans);
const char *
imap_metadata_transaction_get_last_error(
	struct imap_metadata_transaction *imtrans,
	enum mail_error *error_code_r);

#endif
