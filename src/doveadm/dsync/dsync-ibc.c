/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dsync-mail.h"
#include "dsync-ibc-private.h"

void dsync_ibc_deinit(struct dsync_ibc **_ibc)
{
	struct dsync_ibc *ibc = *_ibc;

	*_ibc = NULL;
	ibc->v.deinit(ibc);
}

void dsync_ibc_set_io_callback(struct dsync_ibc *ibc,
			       io_callback_t *callback, void *context)
{
	ibc->io_callback = callback;
	ibc->io_context = context;
}

void dsync_ibc_send_handshake(struct dsync_ibc *ibc,
			      const struct dsync_ibc_settings *set)
{
	ibc->v.send_handshake(ibc, set);
}

enum dsync_ibc_recv_ret
dsync_ibc_recv_handshake(struct dsync_ibc *ibc,
			 const struct dsync_ibc_settings **set_r)
{
	return ibc->v.recv_handshake(ibc, set_r);
}

static enum dsync_ibc_send_ret
dsync_ibc_send_ret(struct dsync_ibc *ibc)
{
	return ibc->v.is_send_queue_full(ibc) ?
		DSYNC_IBC_SEND_RET_FULL :
		DSYNC_IBC_SEND_RET_OK;
}

enum dsync_ibc_send_ret
dsync_ibc_send_end_of_list(struct dsync_ibc *ibc, enum dsync_ibc_eol_type type)
{
	ibc->v.send_end_of_list(ibc, type);
	return dsync_ibc_send_ret(ibc);
}

enum dsync_ibc_send_ret
dsync_ibc_send_mailbox_state(struct dsync_ibc *ibc,
			     const struct dsync_mailbox_state *state)
{
	T_BEGIN {
		ibc->v.send_mailbox_state(ibc, state);
	} T_END;
	return dsync_ibc_send_ret(ibc);
}

enum dsync_ibc_recv_ret
dsync_ibc_recv_mailbox_state(struct dsync_ibc *ibc,
			     struct dsync_mailbox_state *state_r)
{
	return ibc->v.recv_mailbox_state(ibc, state_r);
}

enum dsync_ibc_send_ret
dsync_ibc_send_mailbox_tree_node(struct dsync_ibc *ibc,
				 const char *const *name,
				 const struct dsync_mailbox_node *node)
{
	i_assert(*name != NULL);

	T_BEGIN {
		ibc->v.send_mailbox_tree_node(ibc, name, node);
	} T_END;
	return dsync_ibc_send_ret(ibc);
}

enum dsync_ibc_recv_ret
dsync_ibc_recv_mailbox_tree_node(struct dsync_ibc *ibc,
				 const char *const **name_r,
				 const struct dsync_mailbox_node **node_r)
{
	return ibc->v.recv_mailbox_tree_node(ibc, name_r, node_r);
}

enum dsync_ibc_send_ret
dsync_ibc_send_mailbox_deletes(struct dsync_ibc *ibc,
			       const struct dsync_mailbox_delete *deletes,
			       unsigned int count, char hierarchy_sep)
{
	T_BEGIN {
		ibc->v.send_mailbox_deletes(ibc, deletes, count,
					      hierarchy_sep);
	} T_END;
	return dsync_ibc_send_ret(ibc);
}

enum dsync_ibc_recv_ret
dsync_ibc_recv_mailbox_deletes(struct dsync_ibc *ibc,
			       const struct dsync_mailbox_delete **deletes_r,
			       unsigned int *count_r, char *hierarchy_sep_r)
{
	return ibc->v.recv_mailbox_deletes(ibc, deletes_r, count_r,
					     hierarchy_sep_r);
}

enum dsync_ibc_send_ret
dsync_ibc_send_mailbox(struct dsync_ibc *ibc,
		       const struct dsync_mailbox *dsync_box)
{
	T_BEGIN {
		ibc->v.send_mailbox(ibc, dsync_box);
	} T_END;
	return dsync_ibc_send_ret(ibc);
}

enum dsync_ibc_recv_ret
dsync_ibc_recv_mailbox(struct dsync_ibc *ibc,
		       const struct dsync_mailbox **dsync_box_r)
{
	return ibc->v.recv_mailbox(ibc, dsync_box_r);
}

enum dsync_ibc_send_ret ATTR_NOWARN_UNUSED_RESULT
dsync_ibc_send_mailbox_attribute(struct dsync_ibc *ibc,
				 const struct dsync_mailbox_attribute *attr)
{
	T_BEGIN {
		ibc->v.send_mailbox_attribute(ibc, attr);
	} T_END;
	return dsync_ibc_send_ret(ibc);
}

enum dsync_ibc_recv_ret
dsync_ibc_recv_mailbox_attribute(struct dsync_ibc *ibc,
				 const struct dsync_mailbox_attribute **attr_r)
{
	return ibc->v.recv_mailbox_attribute(ibc, attr_r);
}

enum dsync_ibc_send_ret
dsync_ibc_send_change(struct dsync_ibc *ibc,
		      const struct dsync_mail_change *change)
{
	i_assert(change->uid > 0);

	T_BEGIN {
		ibc->v.send_change(ibc, change);
	} T_END;
	return dsync_ibc_send_ret(ibc);
}

enum dsync_ibc_recv_ret
dsync_ibc_recv_change(struct dsync_ibc *ibc,
		      const struct dsync_mail_change **change_r)
{
	return ibc->v.recv_change(ibc, change_r);
}

enum dsync_ibc_send_ret
dsync_ibc_send_mail_request(struct dsync_ibc *ibc,
			    const struct dsync_mail_request *request)
{
	i_assert(request->guid != NULL || request->uid != 0);

	T_BEGIN {
		ibc->v.send_mail_request(ibc, request);
	} T_END;
	return dsync_ibc_send_ret(ibc);
}

enum dsync_ibc_recv_ret
dsync_ibc_recv_mail_request(struct dsync_ibc *ibc,
			    const struct dsync_mail_request **request_r)
{
	return ibc->v.recv_mail_request(ibc, request_r);
}

enum dsync_ibc_send_ret
dsync_ibc_send_mail(struct dsync_ibc *ibc, const struct dsync_mail *mail)
{
	i_assert(*mail->guid != '\0' || mail->uid != 0);

	T_BEGIN {
		ibc->v.send_mail(ibc, mail);
	} T_END;
	return dsync_ibc_send_ret(ibc);
}

enum dsync_ibc_recv_ret
dsync_ibc_recv_mail(struct dsync_ibc *ibc, struct dsync_mail **mail_r)
{
	return ibc->v.recv_mail(ibc, mail_r);
}

void dsync_ibc_close_mail_streams(struct dsync_ibc *ibc)
{
	ibc->v.close_mail_streams(ibc);
}

bool dsync_ibc_has_failed(struct dsync_ibc *ibc)
{
	return ibc->failed;
}

bool dsync_ibc_has_timed_out(struct dsync_ibc *ibc)
{
	return ibc->timeout;
}

bool dsync_ibc_is_send_queue_full(struct dsync_ibc *ibc)
{
	return ibc->v.is_send_queue_full(ibc);
}

bool dsync_ibc_has_pending_data(struct dsync_ibc *ibc)
{
	return ibc->v.has_pending_data(ibc);
}
