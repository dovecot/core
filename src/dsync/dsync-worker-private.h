#ifndef DSYNC_WORKER_PRIVATE_H
#define DSYNC_WORKER_PRIVATE_H

#include "dsync-worker.h"

struct mail_user;

struct dsync_worker_vfuncs {
	void (*deinit)(struct dsync_worker *);

	bool (*get_next_result)(struct dsync_worker *worker,
				uint32_t *tag_r, int *result_r);
	bool (*is_output_full)(struct dsync_worker *worker);
	int (*output_flush)(struct dsync_worker *worker);

	struct dsync_worker_mailbox_iter *
		(*mailbox_iter_init)(struct dsync_worker *worker);
	int (*mailbox_iter_next)(struct dsync_worker_mailbox_iter *iter,
				 struct dsync_mailbox *dsync_box_r);
	int (*mailbox_iter_deinit)(struct dsync_worker_mailbox_iter *iter);

	struct dsync_worker_msg_iter *
		(*msg_iter_init)(struct dsync_worker *worker,
				 const mailbox_guid_t mailboxes[],
				 unsigned int mailbox_count);
	int (*msg_iter_next)(struct dsync_worker_msg_iter *iter,
			     unsigned int *mailbox_idx_r,
			     struct dsync_message *msg_r);
	int (*msg_iter_deinit)(struct dsync_worker_msg_iter *iter);

	void (*create_mailbox)(struct dsync_worker *worker,
			       const struct dsync_mailbox *dsync_box);
	void (*update_mailbox)(struct dsync_worker *worker,
			       const struct dsync_mailbox *dsync_box);

	void (*select_mailbox)(struct dsync_worker *worker,
			       const mailbox_guid_t *mailbox);
	void (*msg_update_metadata)(struct dsync_worker *worker,
				    const struct dsync_message *msg);
	void (*msg_update_uid)(struct dsync_worker *worker, uint32_t uid);
	void (*msg_expunge)(struct dsync_worker *worker, uint32_t uid);
	void (*msg_copy)(struct dsync_worker *worker,
			 const mailbox_guid_t *src_mailbox, uint32_t src_uid,
			 const struct dsync_message *dest_msg);
	void (*msg_save)(struct dsync_worker *worker,
			 const struct dsync_message *msg,
			 struct dsync_msg_static_data *data);
	int (*msg_get)(struct dsync_worker *worker, uint32_t uid,
		       struct dsync_msg_static_data *data_r);
};

struct dsync_worker {
	struct dsync_worker_vfuncs v;

	io_callback_t *input_callback, *output_callback;
	void *input_context, *output_context;

	uint32_t next_tag;
};

struct dsync_worker_mailbox_iter {
	struct dsync_worker *worker;
	bool failed;
};

struct dsync_worker_msg_iter {
	struct dsync_worker *worker;
	bool failed;
};

#endif
