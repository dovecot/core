#ifndef DSYNC_WORKER_H
#define DSYNC_WORKER_H

#include "ioloop.h"
#include "dsync-data.h"

enum dsync_msg_get_result {
	DSYNC_MSG_GET_RESULT_SUCCESS,
	DSYNC_MSG_GET_RESULT_EXPUNGED,
	DSYNC_MSG_GET_RESULT_FAILED
};

typedef void dsync_worker_copy_callback_t(bool success, void *context);
typedef void dsync_worker_msg_callback_t(enum dsync_msg_get_result result,
					 const struct dsync_msg_static_data *data,
					 void *context);
typedef void dsync_worker_finish_callback_t(bool success, void *context);

struct dsync_worker *dsync_worker_init_local(struct mail_user *user);
struct dsync_worker *dsync_worker_init_proxy_client(int fd_in, int fd_out);
void dsync_worker_deinit(struct dsync_worker **worker);

/* If any function returns with "waiting for more data", the given callback
   gets called when more data is available. */
void dsync_worker_set_input_callback(struct dsync_worker *worker,
				     io_callback_t *callback, void *context);

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
/* Get the next available message. Also returns all expunged messages from
   the end of mailbox (if next_uid-1 message exists, nothing is returned).
   mailbox_idx_r contains the mailbox's index in mailboxes[] array given
   to _iter_init(). Returns 1 if ok, 0 if waiting for more data, -1 if there
   are no more messages. */
int dsync_worker_msg_iter_next(struct dsync_worker_msg_iter *iter,
			       unsigned int *mailbox_idx_r,
			       struct dsync_message *msg_r);
/* Finish message iteration. Returns 0 if ok, -1 if iteration failed. */
int dsync_worker_msg_iter_deinit(struct dsync_worker_msg_iter **iter);

/* Create mailbox with given name, GUID and UIDVALIDITY. */
void dsync_worker_create_mailbox(struct dsync_worker *worker,
				 const struct dsync_mailbox *dsync_box);
/* Delete mailbox/dir with given GUID. */
void dsync_worker_delete_mailbox(struct dsync_worker *worker,
				 const mailbox_guid_t *mailbox);
/* Change a mailbox and its childrens' name */
void dsync_worker_rename_mailbox(struct dsync_worker *worker,
				 const mailbox_guid_t *mailbox,
				 const char *name);
/* Find mailbox with given GUID and make sure its uid_next and
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
void dsync_worker_msg_update_uid(struct dsync_worker *worker,
				 uint32_t old_uid, uint32_t new_uid);
/* Expunge given message. */
void dsync_worker_msg_expunge(struct dsync_worker *worker, uint32_t uid);
/* Copy given message. */
void dsync_worker_msg_copy(struct dsync_worker *worker,
			   const mailbox_guid_t *src_mailbox, uint32_t src_uid,
			   const struct dsync_message *dest_msg,
			   dsync_worker_copy_callback_t *callback,
			   void *context);
/* Save given message from the given input stream. The stream is destroyed once
   saving is finished. */
void dsync_worker_msg_save(struct dsync_worker *worker,
			   const struct dsync_message *msg,
			   const struct dsync_msg_static_data *data);
/* Cancel any pending saves */
void dsync_worker_msg_save_cancel(struct dsync_worker *worker);
/* Get message data for saving. The callback is called once when the static
   data has been received. The whole message may not have been downloaded yet,
   so the caller must read the input stream until it returns EOF and then
   unreference it. */
void dsync_worker_msg_get(struct dsync_worker *worker,
			  const mailbox_guid_t *mailbox, uint32_t uid,
			  dsync_worker_msg_callback_t *callback, void *context);
/* Call the callback once all the pending commands are finished. */
void dsync_worker_finish(struct dsync_worker *worker,
			 dsync_worker_finish_callback_t *callback,
			 void *context);

/* Returns TRUE if some commands have failed. */
bool dsync_worker_has_failed(struct dsync_worker *worker);

#endif
