#ifndef DSYNC_IBC_H
#define DSYNC_IBC_H

/* dsync inter-brain communicator */

#include "ioloop.h"
#include "guid.h"
#include "mail-error.h"
#include "dsync-brain.h"

struct dsync_mailbox;
struct dsync_mailbox_state;
struct dsync_mailbox_node;
struct dsync_mailbox_delete;
struct dsync_mailbox_attribute;
struct dsync_mail;
struct dsync_mail_change;
struct dsync_mail_request;

enum dsync_ibc_send_ret {
	DSYNC_IBC_SEND_RET_OK	= 1,
	/* send queue is full, stop sending more */
	DSYNC_IBC_SEND_RET_FULL	= 0
};

enum dsync_ibc_recv_ret {
	DSYNC_IBC_RECV_RET_FINISHED	= -1,
	/* try again / error (the error handling delayed until io callback) */
	DSYNC_IBC_RECV_RET_TRYAGAIN	= 0,
	DSYNC_IBC_RECV_RET_OK		= 1
};

enum dsync_ibc_eol_type {
	DSYNC_IBC_EOL_MAILBOX_STATE,
	DSYNC_IBC_EOL_MAILBOX_TREE,
	DSYNC_IBC_EOL_MAILBOX_ATTRIBUTE,
	DSYNC_IBC_EOL_MAILBOX,
	DSYNC_IBC_EOL_MAIL_CHANGES,
	DSYNC_IBC_EOL_MAIL_REQUESTS,
	DSYNC_IBC_EOL_MAILS
};

struct dsync_ibc_settings {
	/* Server hostname. Used for determining which server does the
	   locking. */
	const char *hostname;
	/* if non-NULL, sync only these namespaces (LF-separated) */
	const char *sync_ns_prefixes;
	/* if non-NULL, sync only this mailbox name */
	const char *sync_box;
	/* if non-NULL, use this mailbox for finding messages with GUIDs and
	   copying them instead of saving them again. */
	const char *virtual_all_box;
	/* if non-empty, sync only this mailbox GUID */
	guid_128_t sync_box_guid;
	/* Exclude these mailboxes from the sync. They can contain '*'
	   wildcards and be \special-use flags. */
	const char *const *exclude_mailboxes;
	/* Sync only mails with received timestamp at least this high. */
	time_t sync_since_timestamp;
	/* Sync only mails with specified flags. */
	const char *sync_flags;

	enum dsync_brain_sync_type sync_type;
	enum dsync_brain_flags brain_flags;
	bool hdr_hash_v2;
	unsigned int lock_timeout;
};

void dsync_ibc_init_pipe(struct dsync_ibc **ibc1_r,
			 struct dsync_ibc **ibc2_r);
struct dsync_ibc *
dsync_ibc_init_stream(struct istream *input, struct ostream *output,
		      const char *name, const char *temp_path_prefix,
		      unsigned int timeout_secs);
void dsync_ibc_deinit(struct dsync_ibc **ibc);

/* I/O callback is called whenever new data is available. It's also called on
   errors, so check first the error status. */
void dsync_ibc_set_io_callback(struct dsync_ibc *ibc,
			       io_callback_t *callback, void *context);

void dsync_ibc_send_handshake(struct dsync_ibc *ibc,
			      const struct dsync_ibc_settings *set);
enum dsync_ibc_recv_ret
dsync_ibc_recv_handshake(struct dsync_ibc *ibc,
			 const struct dsync_ibc_settings **set_r);

enum dsync_ibc_send_ret ATTR_NOWARN_UNUSED_RESULT
dsync_ibc_send_end_of_list(struct dsync_ibc *ibc, enum dsync_ibc_eol_type type);

enum dsync_ibc_send_ret ATTR_NOWARN_UNUSED_RESULT
dsync_ibc_send_mailbox_state(struct dsync_ibc *ibc,
			     const struct dsync_mailbox_state *state);
enum dsync_ibc_recv_ret
dsync_ibc_recv_mailbox_state(struct dsync_ibc *ibc,
			     struct dsync_mailbox_state *state_r);

enum dsync_ibc_send_ret ATTR_NOWARN_UNUSED_RESULT
dsync_ibc_send_mailbox_tree_node(struct dsync_ibc *ibc,
				 const char *const *name,
				 const struct dsync_mailbox_node *node);
enum dsync_ibc_recv_ret
dsync_ibc_recv_mailbox_tree_node(struct dsync_ibc *ibc,
				 const char *const **name_r,
				 const struct dsync_mailbox_node **node_r);

enum dsync_ibc_send_ret ATTR_NOWARN_UNUSED_RESULT
dsync_ibc_send_mailbox_deletes(struct dsync_ibc *ibc,
			       const struct dsync_mailbox_delete *deletes,
			       unsigned int count, char hierarchy_sep);
enum dsync_ibc_recv_ret
dsync_ibc_recv_mailbox_deletes(struct dsync_ibc *ibc,
			       const struct dsync_mailbox_delete **deletes_r,
			       unsigned int *count_r, char *hierarchy_sep_r);

enum dsync_ibc_send_ret ATTR_NOWARN_UNUSED_RESULT
dsync_ibc_send_mailbox(struct dsync_ibc *ibc,
		       const struct dsync_mailbox *dsync_box);
enum dsync_ibc_recv_ret
dsync_ibc_recv_mailbox(struct dsync_ibc *ibc,
		       const struct dsync_mailbox **dsync_box_r);

enum dsync_ibc_send_ret ATTR_NOWARN_UNUSED_RESULT
dsync_ibc_send_mailbox_attribute(struct dsync_ibc *ibc,
				 const struct dsync_mailbox_attribute *attr);
enum dsync_ibc_recv_ret
dsync_ibc_recv_mailbox_attribute(struct dsync_ibc *ibc,
				 const struct dsync_mailbox_attribute **attr_r);

enum dsync_ibc_send_ret ATTR_NOWARN_UNUSED_RESULT
dsync_ibc_send_change(struct dsync_ibc *ibc,
		      const struct dsync_mail_change *change);
enum dsync_ibc_recv_ret
dsync_ibc_recv_change(struct dsync_ibc *ibc,
		      const struct dsync_mail_change **change_r);

enum dsync_ibc_send_ret ATTR_NOWARN_UNUSED_RESULT
dsync_ibc_send_mail_request(struct dsync_ibc *ibc,
			    const struct dsync_mail_request *request);
enum dsync_ibc_recv_ret
dsync_ibc_recv_mail_request(struct dsync_ibc *ibc,
			    const struct dsync_mail_request **request_r);

enum dsync_ibc_send_ret ATTR_NOWARN_UNUSED_RESULT
dsync_ibc_send_mail(struct dsync_ibc *ibc, const struct dsync_mail *mail);
enum dsync_ibc_recv_ret
dsync_ibc_recv_mail(struct dsync_ibc *ibc, struct dsync_mail **mail_r);

void dsync_ibc_send_finish(struct dsync_ibc *ibc, const char *error,
			   enum mail_error mail_error,
			   bool require_full_resync);
enum dsync_ibc_recv_ret
dsync_ibc_recv_finish(struct dsync_ibc *ibc, const char **error_r,
		      enum mail_error *mail_error_r,
		      bool *require_full_resync_r);

/* Close any mail input streams that are kept open. This needs to be called
   before the mail is attempted to be freed (usually on error conditions). */
void dsync_ibc_close_mail_streams(struct dsync_ibc *ibc);

bool dsync_ibc_has_failed(struct dsync_ibc *ibc);
bool dsync_ibc_has_timed_out(struct dsync_ibc *ibc);
bool dsync_ibc_is_send_queue_full(struct dsync_ibc *ibc);
bool dsync_ibc_has_pending_data(struct dsync_ibc *ibc);

#endif
