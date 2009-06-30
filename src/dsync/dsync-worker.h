#ifndef DSYNC_WORKER_H
#define DSYNC_WORKER_H

#include "ioloop.h"
#include "dsync-data.h"

struct dsync_msg_static_data {
	const char *pop3_uidl;
	time_t received_date;
	struct istream *input;
};

struct dsync_worker *dsync_worker_init_local(struct mail_user *user);
struct dsync_worker *dsync_worker_init_proxy_client(int fd_in, int fd_out);
void dsync_worker_deinit(struct dsync_worker **worker);

/* If any function returns with "waiting for more data", the given callback
   gets called when more data is available. */
void dsync_worker_set_input_callback(struct dsync_worker *worker,
				     io_callback_t *callback, void *context);

/* Request next command to return its result when it's finished. */
void dsync_worker_set_next_result_tag(struct dsync_worker *worker,
				      uint32_t tag);
void dsync_worker_verify_result_is_clear(struct dsync_worker *worker);
/* Returns TRUE if result was returned, FALSE if waiting for more data */
bool dsync_worker_get_next_result(struct dsync_worker *worker,
				 uint32_t *tag_r, int *result_r);
/* Returns TRUE if command queue is full and caller should stop sending
   more commands. */
bool dsync_worker_is_output_full(struct dsync_worker *worker);
/* The given callback gets called when more commands can be queued. */
void dsync_worker_set_output_callback(struct dsync_worker *worker,
				      io_callback_t *callback, void *context);
/* Try to flush command queue. Returns 1 if all flushed, 0 if something is
   still in queue, -1 if failed. */
int dsync_worker_output_flush(struct dsync_worker *worker);

/* Iterate though all mailboxes */
struct dsync_worker_mailbox_iter *
dsync_worker_mailbox_iter_init(struct dsync_worker *worker);
/* Get the next available mailbox. Returns 1 if ok, 0 if waiting for more data,
   -1 if there are no more mailboxes. */
int dsync_worker_mailbox_iter_next(struct dsync_worker_mailbox_iter *iter,
				   struct dsync_mailbox *dsync_box_r);
/* Finish mailbox iteration. Returns 0 if ok, -1 if iteration failed. */
int dsync_worker_mailbox_iter_deinit(struct dsync_worker_mailbox_iter **iter);

/* Iterate through all messages in given mailboxes. The mailboxes are iterated
   in the given order. */
struct dsync_worker_msg_iter *
dsync_worker_msg_iter_init(struct dsync_worker *worker,
			   const mailbox_guid_t mailboxes[],
			   unsigned int mailbox_count);
/* Get the next available message. mailbox_idx_r contains the mailbox's index
   in mailbox_guids[] array given to _iter_init(). Returns 1 if ok, 0 if
   waiting for more data, -1 if there are no more messages. */
int dsync_worker_msg_iter_next(struct dsync_worker_msg_iter *iter,
			       unsigned int *mailbox_idx_r,
			       struct dsync_message *msg_r);
/* Finish message iteration. Returns 0 if ok, -1 if iteration failed. */
int dsync_worker_msg_iter_deinit(struct dsync_worker_msg_iter **iter);

/* Create mailbox with given name, GUID and UIDVALIDITY. */
void dsync_worker_create_mailbox(struct dsync_worker *worker,
				 const struct dsync_mailbox *dsync_box);
/* Find mailbox with given GUID and make sure its name, uid_next and
   highest_modseq are up to date (but don't shrink them). */
void dsync_worker_update_mailbox(struct dsync_worker *worker,
				 const struct dsync_mailbox *dsync_box);

/* The following message syncing functions access the this selected mailbox. */
void dsync_worker_select_mailbox(struct dsync_worker *worker,
				 const mailbox_guid_t *mailbox);
/* Update message's metadata (flags, keywords, modseq). */
void dsync_worker_msg_update_metadata(struct dsync_worker *worker,
				      const struct dsync_message *msg);
/* Change message's UID. */
void dsync_worker_msg_update_uid(struct dsync_worker *worker, uint32_t uid);
/* Expunge given message. */
void dsync_worker_msg_expunge(struct dsync_worker *worker, uint32_t uid);
/* Copy given message. */
void dsync_worker_msg_copy(struct dsync_worker *worker,
			   const mailbox_guid_t *src_mailbox, uint32_t src_uid,
			   const struct dsync_message *dest_msg);
/* Save given message from the given input stream. The stream is destroyed once
   saving is finished. */
void dsync_worker_msg_save(struct dsync_worker *worker,
			   const struct dsync_message *msg,
			   struct dsync_msg_static_data *data);
/* Get message data for saving. Returns 1 if success, 0 if message is already
   expunged or -1 if error. Caller must unreference the returned input
   stream. */
int dsync_worker_msg_get(struct dsync_worker *worker, uint32_t uid,
			 struct dsync_msg_static_data *data_r);

#endif
