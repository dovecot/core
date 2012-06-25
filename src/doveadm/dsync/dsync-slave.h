#ifndef DSYNC_SLAVE_H
#define DSYNC_SLAVE_H

#include "ioloop.h"
#include "guid.h"
#include "dsync-brain.h"

struct dsync_mailbox;
struct dsync_mailbox_state;
struct dsync_mailbox_node;
struct dsync_mailbox_delete;
struct dsync_mail;
struct dsync_mail_change;
struct dsync_mail_request;
struct dsync_slave_settings;

enum dsync_slave_send_ret {
	DSYNC_SLAVE_SEND_RET_OK		= 1,
	/* send queue is full, stop sending more */
	DSYNC_SLAVE_SEND_RET_FULL	= 0
};

enum dsync_slave_recv_ret {
	DSYNC_SLAVE_RECV_RET_FINISHED	= -1,
	/* try again / error (the error handling delayed until io callback) */
	DSYNC_SLAVE_RECV_RET_TRYAGAIN	= 0,
	DSYNC_SLAVE_RECV_RET_OK	= 1
};

struct dsync_slave_settings {
	/* if non-NULL, sync only this namespace */
	const char *sync_ns_prefix;

	enum dsync_brain_sync_type sync_type;
	bool guid_requests;
	bool mails_have_guids;
};

void dsync_slave_init_pipe(struct dsync_slave **slave1_r,
			   struct dsync_slave **slave2_r);
struct dsync_slave *
dsync_slave_init_io(int fd_in, int fd_out, const char *name,
		    const char *temp_path_prefix);
void dsync_slave_deinit(struct dsync_slave **slave);

/* I/O callback is called whenever new data is available. It's also called on
   errors, so check first the error status. */
void dsync_slave_set_io_callback(struct dsync_slave *slave,
				 io_callback_t *callback, void *context);

void dsync_slave_send_handshake(struct dsync_slave *slave,
				const struct dsync_slave_settings *set);
enum dsync_slave_recv_ret
dsync_slave_recv_handshake(struct dsync_slave *slave,
			   const struct dsync_slave_settings **set_r);

enum dsync_slave_send_ret ATTR_NOWARN_UNUSED_RESULT
dsync_slave_send_end_of_list(struct dsync_slave *slave);

enum dsync_slave_send_ret ATTR_NOWARN_UNUSED_RESULT
dsync_slave_send_mailbox_state(struct dsync_slave *slave,
			       const struct dsync_mailbox_state *state);
enum dsync_slave_recv_ret
dsync_slave_recv_mailbox_state(struct dsync_slave *slave,
			       struct dsync_mailbox_state *state_r);

enum dsync_slave_send_ret ATTR_NOWARN_UNUSED_RESULT
dsync_slave_send_mailbox_tree_node(struct dsync_slave *slave,
				   const char *const *name,
				   const struct dsync_mailbox_node *node);
enum dsync_slave_recv_ret
dsync_slave_recv_mailbox_tree_node(struct dsync_slave *slave,
				   const char *const **name_r,
				   const struct dsync_mailbox_node **node_r);

enum dsync_slave_send_ret ATTR_NOWARN_UNUSED_RESULT
dsync_slave_send_mailbox_deletes(struct dsync_slave *slave,
				 const struct dsync_mailbox_delete *deletes,
				 unsigned int count, char hierarchy_sep);
enum dsync_slave_recv_ret
dsync_slave_recv_mailbox_deletes(struct dsync_slave *slave,
				 const struct dsync_mailbox_delete **deletes_r,
				 unsigned int *count_r, char *hierarchy_sep_r);

enum dsync_slave_send_ret ATTR_NOWARN_UNUSED_RESULT
dsync_slave_send_mailbox(struct dsync_slave *slave,
			 const struct dsync_mailbox *dsync_box);
enum dsync_slave_recv_ret
dsync_slave_recv_mailbox(struct dsync_slave *slave,
			 const struct dsync_mailbox **dsync_box_r);

enum dsync_slave_send_ret ATTR_NOWARN_UNUSED_RESULT
dsync_slave_send_change(struct dsync_slave *slave,
			const struct dsync_mail_change *change);
enum dsync_slave_recv_ret
dsync_slave_recv_change(struct dsync_slave *slave,
			const struct dsync_mail_change **change_r);

enum dsync_slave_send_ret ATTR_NOWARN_UNUSED_RESULT
dsync_slave_send_mail_request(struct dsync_slave *slave,
			      const struct dsync_mail_request *request);
enum dsync_slave_recv_ret
dsync_slave_recv_mail_request(struct dsync_slave *slave,
			      const struct dsync_mail_request **request_r);

enum dsync_slave_send_ret ATTR_NOWARN_UNUSED_RESULT
dsync_slave_send_mail(struct dsync_slave *slave,
		      const struct dsync_mail *mail);
enum dsync_slave_recv_ret
dsync_slave_recv_mail(struct dsync_slave *slave,
		      struct dsync_mail **mail_r);

void dsync_slave_flush(struct dsync_slave *slave);
bool dsync_slave_has_failed(struct dsync_slave *slave);
bool dsync_slave_is_send_queue_full(struct dsync_slave *slave);
bool dsync_slave_has_pending_data(struct dsync_slave *slave);

#endif
