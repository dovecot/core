/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dsync-mail.h"
#include "dsync-slave-private.h"

void dsync_slave_deinit(struct dsync_slave **_slave)
{
	struct dsync_slave *slave = *_slave;

	*_slave = NULL;
	slave->v.deinit(slave);
}

void dsync_slave_set_io_callback(struct dsync_slave *slave,
				 io_callback_t *callback, void *context)
{
	slave->io_callback = callback;
	slave->io_context = context;
}

void dsync_slave_send_handshake(struct dsync_slave *slave,
				const struct dsync_slave_settings *set)
{
	slave->v.send_handshake(slave, set);
}

enum dsync_slave_recv_ret
dsync_slave_recv_handshake(struct dsync_slave *slave,
			   const struct dsync_slave_settings **set_r)
{
	return slave->v.recv_handshake(slave, set_r);
}

static enum dsync_slave_send_ret
dsync_slave_send_ret(struct dsync_slave *slave)
{
	return slave->v.is_send_queue_full(slave) ?
		DSYNC_SLAVE_SEND_RET_FULL :
		DSYNC_SLAVE_SEND_RET_OK;
}

enum dsync_slave_send_ret
dsync_slave_send_end_of_list(struct dsync_slave *slave)
{
	slave->v.send_end_of_list(slave);
	return dsync_slave_send_ret(slave);
}

enum dsync_slave_send_ret
dsync_slave_send_mailbox_state(struct dsync_slave *slave,
			       const struct dsync_mailbox_state *state)
{
	T_BEGIN {
		slave->v.send_mailbox_state(slave, state);
	} T_END;
	return dsync_slave_send_ret(slave);
}

enum dsync_slave_recv_ret
dsync_slave_recv_mailbox_state(struct dsync_slave *slave,
			       struct dsync_mailbox_state *state_r)
{
	return slave->v.recv_mailbox_state(slave, state_r);
}

enum dsync_slave_send_ret
dsync_slave_send_mailbox_tree_node(struct dsync_slave *slave,
				   const char *const *name,
				   const struct dsync_mailbox_node *node)
{
	i_assert(*name != NULL);

	T_BEGIN {
		slave->v.send_mailbox_tree_node(slave, name, node);
	} T_END;
	return dsync_slave_send_ret(slave);
}

enum dsync_slave_recv_ret
dsync_slave_recv_mailbox_tree_node(struct dsync_slave *slave,
				   const char *const **name_r,
				   const struct dsync_mailbox_node **node_r)
{
	return slave->v.recv_mailbox_tree_node(slave, name_r, node_r);
}

enum dsync_slave_send_ret
dsync_slave_send_mailbox_deletes(struct dsync_slave *slave,
				 const struct dsync_mailbox_delete *deletes,
				 unsigned int count, char hierarchy_sep)
{
	T_BEGIN {
		slave->v.send_mailbox_deletes(slave, deletes, count,
					      hierarchy_sep);
	} T_END;
	return dsync_slave_send_ret(slave);
}

enum dsync_slave_recv_ret
dsync_slave_recv_mailbox_deletes(struct dsync_slave *slave,
				 const struct dsync_mailbox_delete **deletes_r,
				 unsigned int *count_r, char *hierarchy_sep_r)
{
	return slave->v.recv_mailbox_deletes(slave, deletes_r, count_r,
					     hierarchy_sep_r);
}

enum dsync_slave_send_ret
dsync_slave_send_mailbox(struct dsync_slave *slave,
			 const struct dsync_mailbox *dsync_box)
{
	T_BEGIN {
		slave->v.send_mailbox(slave, dsync_box);
	} T_END;
	return dsync_slave_send_ret(slave);
}

enum dsync_slave_recv_ret
dsync_slave_recv_mailbox(struct dsync_slave *slave,
			 const struct dsync_mailbox **dsync_box_r)
{
	return slave->v.recv_mailbox(slave, dsync_box_r);
}

enum dsync_slave_send_ret
dsync_slave_send_change(struct dsync_slave *slave,
			const struct dsync_mail_change *change)
{
	i_assert(change->uid > 0);

	T_BEGIN {
		slave->v.send_change(slave, change);
	} T_END;
	return dsync_slave_send_ret(slave);
}

enum dsync_slave_recv_ret
dsync_slave_recv_change(struct dsync_slave *slave,
			const struct dsync_mail_change **change_r)
{
	return slave->v.recv_change(slave, change_r);
}

enum dsync_slave_send_ret
dsync_slave_send_mail_request(struct dsync_slave *slave,
			      const struct dsync_mail_request *request)
{
	i_assert(*request->guid != '\0' || request->uid != 0);

	T_BEGIN {
		slave->v.send_mail_request(slave, request);
	} T_END;
	return dsync_slave_send_ret(slave);
}

enum dsync_slave_recv_ret
dsync_slave_recv_mail_request(struct dsync_slave *slave,
			      const struct dsync_mail_request **request_r)
{
	return slave->v.recv_mail_request(slave, request_r);
}

enum dsync_slave_send_ret
dsync_slave_send_mail(struct dsync_slave *slave,
		      const struct dsync_mail *mail)
{
	i_assert(*mail->guid != '\0' || mail->uid != 0);

	T_BEGIN {
		slave->v.send_mail(slave, mail);
	} T_END;
	return dsync_slave_send_ret(slave);
}

enum dsync_slave_recv_ret
dsync_slave_recv_mail(struct dsync_slave *slave,
		      struct dsync_mail **mail_r)
{
	return slave->v.recv_mail(slave, mail_r);
}

void dsync_slave_flush(struct dsync_slave *slave)
{
	if (slave->v.flush != NULL)
		slave->v.flush(slave);
}

bool dsync_slave_has_failed(struct dsync_slave *slave)
{
	return slave->failed;
}

bool dsync_slave_is_send_queue_full(struct dsync_slave *slave)
{
	return slave->v.is_send_queue_full(slave);
}

bool dsync_slave_has_pending_data(struct dsync_slave *slave)
{
	return slave->v.has_pending_data(slave);
}
