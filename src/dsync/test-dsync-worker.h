#ifndef TEST_DSYNC_WORKER_H
#define TEST_DSYNC_WORKER_H

#include "dsync-worker-private.h"

enum test_dsync_last_box_type {
	LAST_BOX_TYPE_CREATE,
	LAST_BOX_TYPE_DELETE,
	LAST_BOX_TYPE_DELETE_DIR,
	LAST_BOX_TYPE_RENAME,
	LAST_BOX_TYPE_UPDATE,
	LAST_BOX_TYPE_SUBSCRIBE,
	LAST_BOX_TYPE_UNSUBSCRIBE
};

enum test_dsync_last_msg_type {
	LAST_MSG_TYPE_UPDATE,
	LAST_MSG_TYPE_UPDATE_UID,
	LAST_MSG_TYPE_EXPUNGE,
	LAST_MSG_TYPE_COPY,
	LAST_MSG_TYPE_SAVE
};

struct test_dsync_worker_mailbox_iter {
	struct dsync_worker_mailbox_iter iter;
	struct dsync_mailbox *next_box;
	bool last;
};

struct test_dsync_worker_subs_iter {
	struct dsync_worker_subs_iter iter;
	struct dsync_worker_subscription *next_subscription;
	struct dsync_worker_unsubscription *next_unsubscription;
	bool last_subs, last_unsubs;
};

struct test_dsync_worker_msg {
	struct dsync_message msg;
	unsigned int mailbox_idx;
};

struct test_dsync_worker_msg_iter {
	struct dsync_worker_msg_iter iter;
	ARRAY_DEFINE(msgs, struct test_dsync_worker_msg);
	unsigned int idx;
	bool last;
};

struct test_dsync_worker_result {
	uint32_t tag;
	int result;
};

struct test_dsync_box_event {
	enum test_dsync_last_box_type type;
	struct dsync_mailbox box;
};

struct test_dsync_msg_event {
	enum test_dsync_last_msg_type type;
	struct dsync_message msg;

	mailbox_guid_t mailbox, copy_src_mailbox;
	uint32_t copy_src_uid;
	struct dsync_msg_static_data save_data;
	const char *save_body;
};

struct test_dsync_worker {
	struct dsync_worker worker;
	struct istream *body_stream;

	struct test_dsync_worker_mailbox_iter box_iter;
	struct test_dsync_worker_subs_iter subs_iter;
	struct test_dsync_worker_msg_iter msg_iter;
	ARRAY_DEFINE(results, struct test_dsync_worker_result);

	pool_t tmp_pool;

	ARRAY_DEFINE(box_events, struct test_dsync_box_event);
	ARRAY_DEFINE(msg_events, struct test_dsync_msg_event);

	mailbox_guid_t selected_mailbox;
	mailbox_guid_t *msg_iter_mailboxes;
	unsigned int msg_iter_mailbox_count;
	const ARRAY_TYPE(const_string) *cache_fields;
};

struct dsync_worker *dsync_worker_init_test(void);

bool test_dsync_worker_next_box_event(struct test_dsync_worker *worker,
				      struct test_dsync_box_event *event_r);
bool test_dsync_worker_next_msg_event(struct test_dsync_worker *worker,
				      struct test_dsync_msg_event *event_r);

#endif
