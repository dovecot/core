#ifndef DSYNC_WORKER_PRIVATE_H
#define DSYNC_WORKER_PRIVATE_H

#include "dsync-worker.h"

struct mail_user;

struct dsync_worker_vfuncs {
	void (*deinit)(struct dsync_worker *);

	bool (*is_output_full)(struct dsync_worker *worker);
	int (*output_flush)(struct dsync_worker *worker);

	struct dsync_worker_mailbox_iter *
		(*mailbox_iter_init)(struct dsync_worker *worker);
	int (*mailbox_iter_next)(struct dsync_worker_mailbox_iter *iter,
				 struct dsync_mailbox *dsync_box_r);
	int (*mailbox_iter_deinit)(struct dsync_worker_mailbox_iter *iter);

	struct dsync_worker_subs_iter *
		(*subs_iter_init)(struct dsync_worker *worker);
	int (*subs_iter_next)(struct dsync_worker_subs_iter *iter,
			      struct dsync_worker_subscription *rec_r);
	int (*subs_iter_next_un)(struct dsync_worker_subs_iter *iter,
				 struct dsync_worker_unsubscription *rec_r);
	int (*subs_iter_deinit)(struct dsync_worker_subs_iter *iter);
	void (*set_subscribed)(struct dsync_worker *worker,
			       const char *name, time_t last_change, bool set);

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
	void (*delete_mailbox)(struct dsync_worker *worker,
			       const struct dsync_mailbox *dsync_box);
	void (*delete_dir)(struct dsync_worker *worker,
			   const struct dsync_mailbox *dsync_box);
	void (*rename_mailbox)(struct dsync_worker *worker,
			       const mailbox_guid_t *mailbox,
			       const struct dsync_mailbox *dsync_box);
	void (*update_mailbox)(struct dsync_worker *worker,
			       const struct dsync_mailbox *dsync_box);

	void (*select_mailbox)(struct dsync_worker *worker,
			       const mailbox_guid_t *mailbox,
			       const ARRAY_TYPE(const_string) *cache_fields);
	void (*msg_update_metadata)(struct dsync_worker *worker,
				    const struct dsync_message *msg);
	void (*msg_update_uid)(struct dsync_worker *worker,
			       uint32_t old_uid, uint32_t new_uid);
	void (*msg_expunge)(struct dsync_worker *worker, uint32_t uid);
	void (*msg_copy)(struct dsync_worker *worker,
			 const mailbox_guid_t *src_mailbox, uint32_t src_uid,
			 const struct dsync_message *dest_msg,
			 dsync_worker_copy_callback_t *callback, void *context);
	void (*msg_save)(struct dsync_worker *worker,
			 const struct dsync_message *msg,
			 const struct dsync_msg_static_data *data,
			 dsync_worker_save_callback_t *callback,
			 void *context);
	void (*msg_save_cancel)(struct dsync_worker *worker);
	void (*msg_get)(struct dsync_worker *worker,
			const mailbox_guid_t *mailbox, uint32_t uid,
			dsync_worker_msg_callback_t *callback, void *context);
	void (*finish)(struct dsync_worker *worker,
		       dsync_worker_finish_callback_t *callback, void *context);
};

struct dsync_worker {
	struct dsync_worker_vfuncs v;

	io_callback_t *input_callback, *output_callback;
	void *input_context, *output_context;

	unsigned int readonly:1;
	unsigned int failed:1;
	unsigned int verbose:1;
	unsigned int unexpected_changes:1;
};

struct dsync_worker_mailbox_iter {
	struct dsync_worker *worker;
	bool failed;
};

struct dsync_worker_subs_iter {
	struct dsync_worker *worker;
	bool failed;
};

struct dsync_worker_msg_iter {
	struct dsync_worker *worker;
	bool failed;
};

void dsync_worker_set_failure(struct dsync_worker *worker);

#endif
