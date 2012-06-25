/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "dsync-mail.h"
#include "dsync-mailbox.h"
#include "dsync-mailbox-state.h"
#include "dsync-mailbox-tree.h"
#include "dsync-slave-private.h"

enum item_type {
	ITEM_END_OF_LIST,
	ITEM_HANDSHAKE,
	ITEM_MAILBOX_STATE,
	ITEM_MAILBOX_TREE_NODE,
	ITEM_MAILBOX_DELETE,
	ITEM_MAILBOX,
	ITEM_MAIL_CHANGE,
	ITEM_MAIL_REQUEST,
	ITEM_MAIL
};

struct item {
	enum item_type type;
	pool_t pool;

	union {
		struct dsync_slave_settings set;
		struct dsync_mailbox_state state;
		struct dsync_mailbox_node node;
		guid_128_t mailbox_guid;
		struct dsync_mailbox dsync_box;
		struct dsync_mail_change change;
		struct dsync_mail_request request;
		struct dsync_mail mail;
		struct {
			const struct dsync_mailbox_delete *deletes;
			unsigned int count;
			char hierarchy_sep;
		} mailbox_delete;
	} u;
};

struct dsync_slave_pipe {
	struct dsync_slave slave;

	ARRAY_DEFINE(pools, pool_t);
	ARRAY_DEFINE(item_queue, struct item);
	struct dsync_slave_pipe *remote;

	pool_t pop_pool;
	struct item pop_item;
};

static pool_t dsync_slave_pipe_get_pool(struct dsync_slave_pipe *pipe)
{
	pool_t *pools, ret;
	unsigned int count;

	pools = array_get_modifiable(&pipe->pools, &count);
	if (count == 0)
		return pool_alloconly_create("pipe item pool", 128);

	ret = pools[count-1];
	array_delete(&pipe->pools, count-1, 1);
	p_clear(ret);
	return ret;
}

static struct item * ATTR_NOWARN_UNUSED_RESULT
dsync_slave_pipe_push_item(struct dsync_slave_pipe *pipe, enum item_type type)
{
	struct item *item;

	item = array_append_space(&pipe->item_queue);
	item->type = type;

	switch (type) {
	case ITEM_END_OF_LIST:
	case ITEM_MAILBOX_STATE:
	case ITEM_MAILBOX_DELETE:
		break;
	case ITEM_HANDSHAKE:
	case ITEM_MAILBOX:
	case ITEM_MAILBOX_TREE_NODE:
	case ITEM_MAIL_CHANGE:
	case ITEM_MAIL_REQUEST:
	case ITEM_MAIL:
		item->pool = dsync_slave_pipe_get_pool(pipe);
		break;
	}
	return item;
}

static struct item *
dsync_slave_pipe_pop_item(struct dsync_slave_pipe *pipe, enum item_type type)
{
	struct item *item;

	if (array_count(&pipe->item_queue) == 0)
		return NULL;

	item = array_idx_modifiable(&pipe->item_queue, 0);
	i_assert(item->type == type);
	pipe->pop_item = *item;
	array_delete(&pipe->item_queue, 0, 1);
	item = NULL;

	if (pipe->pop_pool != NULL)
		pool_unref(&pipe->pop_pool);
	pipe->pop_pool = pipe->pop_item.pool;
	return &pipe->pop_item;
}

static bool dsync_slave_pipe_try_pop_eol(struct dsync_slave_pipe *pipe)
{
	const struct item *item;

	if (array_count(&pipe->item_queue) == 0)
		return FALSE;

	item = array_idx(&pipe->item_queue, 0);
	if (item->type != ITEM_END_OF_LIST)
		return FALSE;

	array_delete(&pipe->item_queue, 0, 1);
	return TRUE;
}

static void dsync_slave_pipe_deinit(struct dsync_slave *slave)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;
	pool_t *poolp;

	if (pipe->remote != NULL) {
		i_assert(pipe->remote->remote == pipe);
		pipe->remote->remote = NULL;
	}

	if (pipe->pop_pool != NULL)
		pool_unref(&pipe->pop_pool);
	array_foreach_modifiable(&pipe->pools, poolp)
		pool_unref(poolp);
	array_free(&pipe->pools);
	array_free(&pipe->item_queue);
	i_free(pipe);
}

static void
dsync_slave_pipe_send_handshake(struct dsync_slave *slave,
				const struct dsync_slave_settings *set)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;
	struct item *item;

	item = dsync_slave_pipe_push_item(pipe->remote, ITEM_HANDSHAKE);
	item->u.set = *set;
	item->u.set.sync_ns_prefix = p_strdup(item->pool, set->sync_ns_prefix);
}

static enum dsync_slave_recv_ret
dsync_slave_pipe_recv_handshake(struct dsync_slave *slave,
				const struct dsync_slave_settings **set_r)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;
	struct item *item;

	item = dsync_slave_pipe_pop_item(pipe, ITEM_HANDSHAKE);
	if (item == NULL)
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;

	*set_r = &item->u.set;
	return DSYNC_SLAVE_RECV_RET_OK;
}

static bool dsync_slave_pipe_is_send_queue_full(struct dsync_slave *slave)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;

	return array_count(&pipe->remote->item_queue) > 0;
}

static bool dsync_slave_pipe_has_pending_data(struct dsync_slave *slave)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;

	return array_count(&pipe->item_queue) > 0;
}

static void
dsync_slave_pipe_send_end_of_list(struct dsync_slave *slave)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;

	dsync_slave_pipe_push_item(pipe->remote, ITEM_END_OF_LIST);
}

static void
dsync_slave_pipe_send_mailbox_state(struct dsync_slave *slave,
				    const struct dsync_mailbox_state *state)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;
	struct item *item;

	item = dsync_slave_pipe_push_item(pipe->remote, ITEM_MAILBOX_STATE);
	item->u.state = *state;
}

static enum dsync_slave_recv_ret
dsync_slave_pipe_recv_mailbox_state(struct dsync_slave *slave,
				    struct dsync_mailbox_state *state_r)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;
	struct item *item;

	if (dsync_slave_pipe_try_pop_eol(pipe))
		return DSYNC_SLAVE_RECV_RET_FINISHED;

	item = dsync_slave_pipe_pop_item(pipe, ITEM_MAILBOX_STATE);
	if (item == NULL)
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;

	*state_r = item->u.state;
	return DSYNC_SLAVE_RECV_RET_OK;
}

static void
dsync_slave_pipe_send_mailbox_tree_node(struct dsync_slave *slave,
					const char *const *name,
					const struct dsync_mailbox_node *node)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;
	struct item *item;

	item = dsync_slave_pipe_push_item(pipe->remote, ITEM_MAILBOX_TREE_NODE);

	/* a little bit kludgy way to send it */
	item->u.node.name = (void *)p_strarray_dup(item->pool, name);
	dsync_mailbox_node_copy_data(&item->u.node, node);
}

static enum dsync_slave_recv_ret
dsync_slave_pipe_recv_mailbox_tree_node(struct dsync_slave *slave,
					const char *const **name_r,
					const struct dsync_mailbox_node **node_r)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;
	struct item *item;

	if (dsync_slave_pipe_try_pop_eol(pipe))
		return DSYNC_SLAVE_RECV_RET_FINISHED;

	item = dsync_slave_pipe_pop_item(pipe, ITEM_MAILBOX_TREE_NODE);
	if (item == NULL)
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;

	*name_r = (void *)item->u.node.name;
	item->u.node.name = NULL;

	*node_r = &item->u.node;
	return DSYNC_SLAVE_RECV_RET_OK;
}

static void
dsync_slave_pipe_send_mailbox_deletes(struct dsync_slave *slave,
				      const struct dsync_mailbox_delete *deletes,
				      unsigned int count, char hierarchy_sep)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;
	struct item *item;

	item = dsync_slave_pipe_push_item(pipe->remote, ITEM_MAILBOX_DELETE);

	/* we'll assume that the deletes are permanent. this works for now.. */
	/* a little bit kludgy way to send it */
	item->u.mailbox_delete.deletes = deletes;
	item->u.mailbox_delete.count = count;
	item->u.mailbox_delete.hierarchy_sep = hierarchy_sep;
}

static enum dsync_slave_recv_ret
dsync_slave_pipe_recv_mailbox_deletes(struct dsync_slave *slave,
				      const struct dsync_mailbox_delete **deletes_r,
				      unsigned int *count_r,
				      char *hierarchy_sep_r)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;
	struct item *item;

	if (dsync_slave_pipe_try_pop_eol(pipe))
		return DSYNC_SLAVE_RECV_RET_FINISHED;

	item = dsync_slave_pipe_pop_item(pipe, ITEM_MAILBOX_DELETE);
	if (item == NULL)
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;

	*deletes_r = item->u.mailbox_delete.deletes;
	*count_r = item->u.mailbox_delete.count;
	*hierarchy_sep_r = item->u.mailbox_delete.hierarchy_sep;
	return DSYNC_SLAVE_RECV_RET_OK;
}

static void
dsync_slave_pipe_send_mailbox(struct dsync_slave *slave,
			      const struct dsync_mailbox *dsync_box)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;
	struct item *item;
	const struct mailbox_cache_field *cf;
	struct mailbox_cache_field *ncf;

	item = dsync_slave_pipe_push_item(pipe->remote, ITEM_MAILBOX);
	item->u.dsync_box = *dsync_box;
	p_array_init(&item->u.dsync_box.cache_fields, item->pool,
		     array_count(&dsync_box->cache_fields));
	array_foreach(&dsync_box->cache_fields, cf) {
		ncf = array_append_space(&item->u.dsync_box.cache_fields);
		ncf->name = p_strdup(item->pool, cf->name);
		ncf->decision = cf->decision;
		ncf->last_used = cf->last_used;
	}
}

static enum dsync_slave_recv_ret
dsync_slave_pipe_recv_mailbox(struct dsync_slave *slave,
			      const struct dsync_mailbox **dsync_box_r)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;
	struct item *item;

	if (dsync_slave_pipe_try_pop_eol(pipe))
		return DSYNC_SLAVE_RECV_RET_FINISHED;

	item = dsync_slave_pipe_pop_item(pipe, ITEM_MAILBOX);
	if (item == NULL)
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;

	*dsync_box_r = &item->u.dsync_box;
	return DSYNC_SLAVE_RECV_RET_OK;
}

static void
dsync_slave_pipe_send_change(struct dsync_slave *slave,
			     const struct dsync_mail_change *change)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;
	struct item *item;

	item = dsync_slave_pipe_push_item(pipe->remote, ITEM_MAIL_CHANGE);
	dsync_mail_change_dup(item->pool, change, &item->u.change);
}

static enum dsync_slave_recv_ret
dsync_slave_pipe_recv_change(struct dsync_slave *slave,
			     const struct dsync_mail_change **change_r)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;
	struct item *item;

	if (dsync_slave_pipe_try_pop_eol(pipe))
		return DSYNC_SLAVE_RECV_RET_FINISHED;

	item = dsync_slave_pipe_pop_item(pipe, ITEM_MAIL_CHANGE);
	if (item == NULL)
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;

	*change_r = &item->u.change;
	return DSYNC_SLAVE_RECV_RET_OK;
}

static void
dsync_slave_pipe_send_mail_request(struct dsync_slave *slave,
				   const struct dsync_mail_request *request)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;
	struct item *item;

	item = dsync_slave_pipe_push_item(pipe->remote, ITEM_MAIL_REQUEST);
	item->u.request.guid = p_strdup(item->pool, request->guid);
	item->u.request.uid = request->uid;
}

static enum dsync_slave_recv_ret
dsync_slave_pipe_recv_mail_request(struct dsync_slave *slave,
				   const struct dsync_mail_request **request_r)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;
	struct item *item;

	if (dsync_slave_pipe_try_pop_eol(pipe))
		return DSYNC_SLAVE_RECV_RET_FINISHED;

	item = dsync_slave_pipe_pop_item(pipe, ITEM_MAIL_REQUEST);
	if (item == NULL)
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;

	*request_r = &item->u.request;
	return DSYNC_SLAVE_RECV_RET_OK;
}

static void
dsync_slave_pipe_send_mail(struct dsync_slave *slave,
			   const struct dsync_mail *mail)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;
	struct item *item;

	item = dsync_slave_pipe_push_item(pipe->remote, ITEM_MAIL);
	item->u.mail.guid = p_strdup(item->pool, mail->guid);
	item->u.mail.pop3_uidl = p_strdup(item->pool, mail->pop3_uidl);
	item->u.mail.pop3_order = mail->pop3_order;
	item->u.mail.received_date = mail->received_date;
	if (mail->input != NULL) {
		item->u.mail.input = mail->input;
		i_stream_ref(mail->input);
	}
}

static enum dsync_slave_recv_ret
dsync_slave_pipe_recv_mail(struct dsync_slave *slave,
			   struct dsync_mail **mail_r)
{
	struct dsync_slave_pipe *pipe = (struct dsync_slave_pipe *)slave;
	struct item *item;

	if (dsync_slave_pipe_try_pop_eol(pipe))
		return DSYNC_SLAVE_RECV_RET_FINISHED;

	item = dsync_slave_pipe_pop_item(pipe, ITEM_MAIL);
	if (item == NULL)
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;

	*mail_r = &item->u.mail;
	return DSYNC_SLAVE_RECV_RET_OK;
}

static const struct dsync_slave_vfuncs dsync_slave_pipe_vfuncs = {
	dsync_slave_pipe_deinit,
	dsync_slave_pipe_send_handshake,
	dsync_slave_pipe_recv_handshake,
	dsync_slave_pipe_send_end_of_list,
	dsync_slave_pipe_send_mailbox_state,
	dsync_slave_pipe_recv_mailbox_state,
	dsync_slave_pipe_send_mailbox_tree_node,
	dsync_slave_pipe_recv_mailbox_tree_node,
	dsync_slave_pipe_send_mailbox_deletes,
	dsync_slave_pipe_recv_mailbox_deletes,
	dsync_slave_pipe_send_mailbox,
	dsync_slave_pipe_recv_mailbox,
	dsync_slave_pipe_send_change,
	dsync_slave_pipe_recv_change,
	dsync_slave_pipe_send_mail_request,
	dsync_slave_pipe_recv_mail_request,
	dsync_slave_pipe_send_mail,
	dsync_slave_pipe_recv_mail,
	NULL,
	dsync_slave_pipe_is_send_queue_full,
	dsync_slave_pipe_has_pending_data
};

static struct dsync_slave_pipe *
dsync_slave_pipe_alloc(void)
{
	struct dsync_slave_pipe *pipe;

	pipe = i_new(struct dsync_slave_pipe, 1);
	pipe->slave.v = dsync_slave_pipe_vfuncs;
	i_array_init(&pipe->pools, 4);
	i_array_init(&pipe->item_queue, 4);
	return pipe;
}

void dsync_slave_init_pipe(struct dsync_slave **slave1_r,
			   struct dsync_slave **slave2_r)
{
	struct dsync_slave_pipe *pipe1, *pipe2;

	pipe1 = dsync_slave_pipe_alloc();
	pipe2 = dsync_slave_pipe_alloc();
	pipe1->remote = pipe2;
	pipe2->remote = pipe1;
	*slave1_r = &pipe1->slave;
	*slave2_r = &pipe2->slave;
}
