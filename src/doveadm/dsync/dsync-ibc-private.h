#ifndef DSYNC_IBC_PRIVATE_H
#define DSYNC_IBC_PRIVATE_H

#include "dsync-ibc.h"

struct dsync_ibc_vfuncs {
	void (*deinit)(struct dsync_ibc *ibc);

	void (*send_handshake)(struct dsync_ibc *ibc,
			       const struct dsync_ibc_settings *set);
	enum dsync_ibc_recv_ret
		(*recv_handshake)(struct dsync_ibc *ibc,
				  const struct dsync_ibc_settings **set_r);

	void (*send_end_of_list)(struct dsync_ibc *ibc,
				 enum dsync_ibc_eol_type type);

	void (*send_mailbox_state)(struct dsync_ibc *ibc,
				   const struct dsync_mailbox_state *state);
	enum dsync_ibc_recv_ret
		(*recv_mailbox_state)(struct dsync_ibc *ibc,
				      struct dsync_mailbox_state *state_r);

	void (*send_mailbox_tree_node)(struct dsync_ibc *ibc,
				       const char *const *name,
				       const struct dsync_mailbox_node *node);
	enum dsync_ibc_recv_ret
		(*recv_mailbox_tree_node)(struct dsync_ibc *ibc,
					  const char *const **name_r,
					  const struct dsync_mailbox_node **node_r);

	void (*send_mailbox_deletes)(struct dsync_ibc *ibc,
				     const struct dsync_mailbox_delete *deletes,
				     unsigned int count, char hierarchy_sep);
	enum dsync_ibc_recv_ret
		(*recv_mailbox_deletes)(struct dsync_ibc *ibc,
					const struct dsync_mailbox_delete **deletes_r,
					unsigned int *count_r,
					char *hierarchy_sep_r);

	void (*send_mailbox)(struct dsync_ibc *ibc,
			     const struct dsync_mailbox *dsync_box);
	enum dsync_ibc_recv_ret
		(*recv_mailbox)(struct dsync_ibc *ibc,
				const struct dsync_mailbox **dsync_box_r);

	void (*send_mailbox_attribute)(struct dsync_ibc *ibc,
				       const struct dsync_mailbox_attribute *attr);
	enum dsync_ibc_recv_ret
		(*recv_mailbox_attribute)(struct dsync_ibc *ibc,
					  const struct dsync_mailbox_attribute **attr_r);

	void (*send_change)(struct dsync_ibc *ibc,
			    const struct dsync_mail_change *change);
	enum dsync_ibc_recv_ret
		(*recv_change)(struct dsync_ibc *ibc,
			       const struct dsync_mail_change **change_r);

	void (*send_mail_request)(struct dsync_ibc *ibc,
				  const struct dsync_mail_request *request);
	enum dsync_ibc_recv_ret
		(*recv_mail_request)(struct dsync_ibc *ibc,
				     const struct dsync_mail_request **request_r);

	void (*send_mail)(struct dsync_ibc *ibc,
			  const struct dsync_mail *mail);
	enum dsync_ibc_recv_ret
		(*recv_mail)(struct dsync_ibc *ibc,
			     struct dsync_mail **mail_r);

	void (*close_mail_streams)(struct dsync_ibc *ibc);
	bool (*is_send_queue_full)(struct dsync_ibc *ibc);
	bool (*has_pending_data)(struct dsync_ibc *ibc);
};

struct dsync_ibc {
	struct dsync_ibc_vfuncs v;

	io_callback_t *io_callback;
	void *io_context;

	unsigned int failed:1;
	unsigned int timeout:1;
};

#endif
