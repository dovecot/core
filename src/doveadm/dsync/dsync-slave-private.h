#ifndef DSYNC_SLAVE_PRIVATE_H
#define DSYNC_SLAVE_PRIVATE_H

#include "dsync-slave.h"

struct dsync_slave_vfuncs {
	void (*deinit)(struct dsync_slave *slave);

	void (*send_handshake)(struct dsync_slave *slave,
			       const struct dsync_slave_settings *set);
	enum dsync_slave_recv_ret
		(*recv_handshake)(struct dsync_slave *slave,
				  const struct dsync_slave_settings **set_r);

	void (*send_end_of_list)(struct dsync_slave *slave);

	void (*send_mailbox_state)(struct dsync_slave *slave,
				   const struct dsync_mailbox_state *state);
	enum dsync_slave_recv_ret
		(*recv_mailbox_state)(struct dsync_slave *slave,
				      struct dsync_mailbox_state *state_r);

	void (*send_mailbox_tree_node)(struct dsync_slave *slave,
				       const char *const *name,
				       const struct dsync_mailbox_node *node);
	enum dsync_slave_recv_ret
		(*recv_mailbox_tree_node)(struct dsync_slave *slave,
					  const char *const **name_r,
					  const struct dsync_mailbox_node **node_r);

	void (*send_mailbox_deletes)(struct dsync_slave *slave,
				     const struct dsync_mailbox_delete *deletes,
				     unsigned int count, char hierarchy_sep);
	enum dsync_slave_recv_ret
		(*recv_mailbox_deletes)(struct dsync_slave *slave,
					const struct dsync_mailbox_delete **deletes_r,
					unsigned int *count_r,
					char *hierarchy_sep_r);

	void (*send_mailbox)(struct dsync_slave *slave,
			     const struct dsync_mailbox *dsync_box);
	enum dsync_slave_recv_ret
		(*recv_mailbox)(struct dsync_slave *slave,
				const struct dsync_mailbox **dsync_box_r);

	void (*send_change)(struct dsync_slave *slave,
			    const struct dsync_mail_change *change);
	enum dsync_slave_recv_ret
		(*recv_change)(struct dsync_slave *slave,
			       const struct dsync_mail_change **change_r);

	void (*send_mail_request)(struct dsync_slave *slave,
				  const struct dsync_mail_request *request);
	enum dsync_slave_recv_ret
		(*recv_mail_request)(struct dsync_slave *slave,
				     const struct dsync_mail_request **request_r);

	void (*send_mail)(struct dsync_slave *slave,
			  const struct dsync_mail *mail);
	enum dsync_slave_recv_ret
		(*recv_mail)(struct dsync_slave *slave,
			     struct dsync_mail **mail_r);

	void (*flush)(struct dsync_slave *slave);
	bool (*is_send_queue_full)(struct dsync_slave *slave);
	bool (*has_pending_data)(struct dsync_slave *slave);
};

struct dsync_slave {
	struct dsync_slave_vfuncs v;

	io_callback_t *io_callback;
	void *io_context;

	unsigned int failed:1;
};

#endif
