/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "message-id.h"
#include "mail-storage.h"
#include "index-thread-private.h"

static struct mail_thread_node *
thread_msgid_get(struct mail_thread_update_context *ctx, uint32_t ref_uid,
		 const char *msgid, uint32_t *idx_r)
{
	struct mail_thread_node *node, new_node;
	struct msgid_search_key key;
	const char **msgidp;
	uint32_t idx;

	key.msgid = msgid;
	key.msgid_crc32 = crc32_str_nonzero(msgid);

	node = mail_hash_lookup(ctx->hash_trans, &key, &idx);
	if (node == NULL) {
		/* not found, create */
		memset(&new_node, 0, sizeof(new_node));
		new_node.msgid_crc32 = key.msgid_crc32;
		new_node.uid = ref_uid;

		mail_hash_insert(ctx->hash_trans, &key, &new_node, &idx);
		node = mail_hash_lookup_idx(ctx->hash_trans, idx);
	} else if (node->uid == 0 && ref_uid != 0) {
		/* make non-existing node uniquely identifiable */
		if (node->exists) {
			mail_hash_transaction_set_corrupted(ctx->hash_trans,
							    "uid=0 found");
			ctx->failed = TRUE;
		} else {
			node->uid = ref_uid;
			mail_hash_update(ctx->hash_trans, idx);
		}
	}

	/* keep message-ids cached */
	msgidp = array_idx_modifiable(&ctx->msgid_cache, idx);
	if (*msgidp == NULL)
		*msgidp = p_strdup(ctx->msgid_pool, msgid);

	*idx_r = idx;
	return node;
}

static void thread_msg_add(struct mail_thread_update_context *ctx, uint32_t uid,
			   const char *msgid, uint32_t *idx_r)
{
	struct mail_thread_node *node;
	struct mail_thread_node unode;

	if (msgid != NULL) {
		node = thread_msgid_get(ctx, 0, msgid, idx_r);
		if (!node->exists) {
			/* add UID to node */
			node->uid = uid;
			node->exists = TRUE;
		} else {
			/* duplicate, keep the original. if the original ever
			   gets expunged, rebuild. */
			node->expunge_rebuilds = TRUE;
			msgid = NULL;
		}
		mail_hash_update(ctx->hash_trans, *idx_r);
	}

	if (msgid == NULL) {
		/* no valid message-id */
		memset(&unode, 0, sizeof(unode));
		unode.uid = uid;
		unode.exists = TRUE;
		mail_hash_insert(ctx->hash_trans, NULL, &unode, idx_r);
	}
}

static bool thread_node_has_ancestor(struct mail_thread_update_context *ctx,
				     const struct mail_thread_node *node,
				     const struct mail_thread_node *ancestor)
{
	while (node != ancestor) {
		if (node->parent_idx == 0)
			return FALSE;

		node = mail_hash_lookup_idx(ctx->hash_trans, node->parent_idx);
	}
	return TRUE;
}

static void thread_link_reference(struct mail_thread_update_context *ctx,
				  uint32_t parent_idx, uint32_t child_idx)
{
	struct mail_thread_node *node, *parent, *child;
	uint32_t idx;

	parent = mail_hash_lookup_idx(ctx->hash_trans, parent_idx);
	child = mail_hash_lookup_idx(ctx->hash_trans, child_idx);

	child->link_refcount++;
	mail_hash_update(ctx->hash_trans, child_idx);

	if (thread_node_has_ancestor(ctx, parent, child)) {
		if (parent == child) {
			/* loops to itself - ignore */
			return;
		}

		/* child is an ancestor of parent. Adding child -> parent_node
		   would introduce a loop. If any messages referencing the path
		   between parent_node's parent and child_node get expunged, we
		   have to rebuild the tree because the loop might break.
		   For example:

		     #1: a -> b       (a.ref=1, b.ref=1)
		     #2: b -> a       (a.ref=2, b.ref=2)
		     #3: c -> a -> b  (a.ref=3, b.ref=3, c.ref=1)

		   Expunging #3 wouldn't break the loop, but expunging #1
		   would. */
		node = parent;
		do {
			idx = node->parent_idx;
			if (idx == 0) {
				/* earlier lookup_idx() failed */
				ctx->failed = TRUE;
				break;
			}
			node = mail_hash_lookup_idx(ctx->hash_trans, idx);
			node->parent_unref_rebuilds = TRUE;
			mail_hash_update(ctx->hash_trans, idx);
		} while (node != child);
		return;
	} else if (child->parent_idx == parent_idx) {
		/* The same link already exists */
		return;
	}

	/* Set parent_node as child_node's parent */
	if (child->parent_idx == 0)
		child->parent_idx = parent_idx;
	else {
		/* Conflicting parent already exists, keep the original */
		if (child->exists) {
			/* If this message gets expunged,
			   the parent is changed. */
			child->expunge_rebuilds = TRUE;
		} else {
			/* Message doesn't exist, so it was one of the node's
			   children that created the original reference. If
			   that reference gets dropped, the parent is changed.
			   We could catch this in one of several ways:

			    a) Link to parent node gets unreferenced
			    b) Link to this node gets unreferenced
			    c) Any of the child nodes gets expunged

			   b) is probably the least likely to happen,
			   so use it */
			child->parent_unref_rebuilds = TRUE;
		}
	}
	mail_hash_update(ctx->hash_trans, child_idx);
}

static void
thread_link_references(struct mail_thread_update_context *ctx, uint32_t ref_uid,
		       const char **references)
{
	const char *msgid, *last_msgid;
	uint32_t parent_idx, child_idx;

	last_msgid = message_id_get_next(references);
	if (last_msgid == NULL)
		return;
	(void)thread_msgid_get(ctx, ref_uid, last_msgid, &parent_idx);

	while ((msgid = message_id_get_next(references)) != NULL) {
		(void)thread_msgid_get(ctx, ref_uid, msgid, &child_idx);
		thread_link_reference(ctx, parent_idx, child_idx);
		parent_idx = child_idx;
		last_msgid = msgid;
	}

	/* link the last ID to us */
	*references = last_msgid;
}

static int thread_get_mail_header(struct mail *mail, const char *name,
				  const char **value_r)
{
	if (mail_get_first_header(mail, name, value_r) < 0) {
		if (!mail->expunged)
			return -1;

		/* Message is expunged. Instead of failing the entire THREAD
		   command, just treat the header as non-existing. */
		*value_r = NULL;
	}
	return 0;
}

static bool references_are_crc32_unique(const char *references)
{
	const char *msgid;
	uint32_t msgid_crc32;
	ARRAY_TYPE(uint32_t) crc_arr;
	const uint32_t *crc;
	unsigned int i, count;

	t_array_init(&crc_arr, 32);
	while ((msgid = message_id_get_next(&references)) != NULL) {
		msgid_crc32 = crc32_str_nonzero(msgid);
		crc = array_get(&crc_arr, &count);
		for (i = 0; i < count; i++) {
			if (crc[i] == msgid_crc32)
				return FALSE;
		}
		array_append(&crc_arr, &msgid_crc32, 1);
	}
	return TRUE;
}

int mail_thread_add(struct mail_thread_update_context *ctx, struct mail *mail)
{
	const char *message_id, *in_reply_to, *references, *parent_msgid;
	const struct mail_thread_node *parent, *old_parent;
	struct mail_hash_header *hdr;
	struct mail_thread_node *node;
	uint32_t idx, parent_idx, ref_uid;

	hdr = mail_hash_get_header(ctx->hash_trans);
	i_assert(mail->uid > hdr->last_uid);
	hdr->last_uid = mail->uid;
	hdr->message_count++;

	if (thread_get_mail_header(mail, HDR_MESSAGE_ID, &message_id) < 0 ||
	    thread_get_mail_header(mail, HDR_REFERENCES, &references) < 0)
		return -1;

	ref_uid = references_are_crc32_unique(references) ? mail->uid : 0;
	thread_msg_add(ctx, mail->uid, message_id_get_next(&message_id), &idx);
	thread_link_references(ctx, ref_uid, &references);

	if (references != NULL)
		parent_msgid = references;
	else {
		/* no valid IDs in References:, use In-Reply-To: instead */
		if (thread_get_mail_header(mail, HDR_IN_REPLY_TO,
					   &in_reply_to) < 0)
			return -1;
		parent_msgid = message_id_get_next(&in_reply_to);
	}
	parent = parent_msgid == NULL ? NULL :
		thread_msgid_get(ctx, ref_uid, parent_msgid, &parent_idx);

	node = mail_hash_lookup_idx(ctx->hash_trans, idx);
	old_parent = node->parent_idx == 0 ? NULL :
		mail_hash_lookup_idx(ctx->hash_trans, node->parent_idx);

	if (old_parent != NULL &&
	    (parent == NULL || old_parent->parent_idx != parent_idx)) {
		/* conflicting parent, remove it. */
		node->parent_idx = 0;
		/* If this message gets expunged, we have to revert back to
		   the original parent. */
		node->expunge_rebuilds = TRUE;
		mail_hash_update(ctx->hash_trans, idx);
	}
	if (parent != NULL)
		thread_link_reference(ctx, parent_idx, idx);
	return 0;
}

static bool
mail_thread_node_lookup(struct mail_thread_update_context *ctx, uint32_t uid,
			uint32_t *idx_r, struct mail_thread_node **node_r)
{
	struct msgid_search_key key;
	const char *msgids;
	int ret;

	if (!mail_set_uid(ctx->tmp_mail, uid))
		return FALSE;

	ret = mail_get_first_header(ctx->tmp_mail, HDR_MESSAGE_ID, &msgids);
	if (ret <= 0)
		return FALSE;

	key.msgid = message_id_get_next(&msgids);
	if (key.msgid == NULL)
		return FALSE;
	key.msgid_crc32 = crc32_str_nonzero(key.msgid);

	*node_r = mail_hash_lookup(ctx->hash_trans, &key, idx_r);
	if (*node_r == NULL)
		return FALSE;

	if ((*node_r)->uid != ctx->tmp_mail->uid) {
		/* duplicate Message-ID probably */
		return FALSE;
	}
	return TRUE;
}

static bool
thread_unref_msgid(struct mail_thread_update_context *ctx, uint32_t child_idx,
		   const char *msgid, uint32_t *parent_idx_r)
{
	struct msgid_search_key key;
	struct mail_thread_node *parent, *child;
	uint32_t parent_idx;

	key.msgid = msgid;
	key.msgid_crc32 = crc32_str_nonzero(msgid);

	ctx->cmp_match_count = 0;
	ctx->cmp_last_idx = 0;

	parent = mail_hash_lookup(ctx->hash_trans, &key, &parent_idx);
	if (parent == NULL) {
		if (ctx->cmp_match_count != 1 || ctx->failed) {
			/* couldn't find the message-id */
			return FALSE;
		}

		/* there's only one key with this crc32 value, so it
		   must be what we're looking for */
		parent_idx = ctx->cmp_last_idx;
		parent = mail_hash_lookup_idx(ctx->hash_trans, parent_idx);
	}
	if (parent->parent_unref_rebuilds)
		return FALSE;

	child = mail_hash_lookup_idx(ctx->hash_trans, child_idx);
	if (child->link_refcount == 0) {
		mail_hash_transaction_set_corrupted(ctx->hash_trans,
						    "unexpected refcount=0");
		return FALSE;
	}
	child->link_refcount--;
	if (child->link_refcount == 0) {
		/* we don't have a root anymore */
		child->parent_idx = 0;
	}
	mail_hash_update(ctx->hash_trans, child_idx);
	*parent_idx_r = parent_idx;
	return TRUE;
}

static bool
thread_unref_links(struct mail_thread_update_context *ctx, uint32_t child_idx,
		   const char *references, bool *valid_r)
{
	uint32_t parent_idx;
	const char *msgid;

	/* tmp_mail may be changed below, so we have to duplicate the
	   references string */
	references = t_strdup(references);
	*valid_r = FALSE;

	while ((msgid = message_id_get_next(&references)) != NULL) {
		*valid_r = TRUE;
		if (!thread_unref_msgid(ctx, child_idx, msgid, &parent_idx))
			return FALSE;
		child_idx = parent_idx;
	}
	return TRUE;
}

int mail_thread_remove(struct mail_thread_update_context *ctx, uint32_t uid)
{
	struct mail_hash_header *hdr;
	struct mail_thread_node *node;
	const char *references, *in_reply_to;
	uint32_t idx, parent_idx;
	bool have_refs;

	if (!mail_thread_node_lookup(ctx, uid, &idx, &node))
		return 0;
	if (node->expunge_rebuilds)
		return 0;

	if (mail_get_first_header(ctx->tmp_mail, HDR_REFERENCES,
				  &references) < 0)
		return -1;

	if (!thread_unref_links(ctx, idx, references, &have_refs))
		return 0;
	if (!have_refs) {
		/* no valid IDs in References:, use In-Reply-To: instead */
		if (mail_get_first_header(ctx->tmp_mail, HDR_IN_REPLY_TO,
					  &in_reply_to) < 0)
			return -1;
		in_reply_to = message_id_get_next(&in_reply_to);
		if (in_reply_to != NULL) {
			if (!thread_unref_msgid(ctx, idx, in_reply_to,
						&parent_idx))
				return 0;
		}
	}

	/* get the node again, the pointer may have changed */
	node = mail_hash_lookup_idx(ctx->hash_trans, idx);

	node->uid = 0;
	node->exists = FALSE;
	mail_hash_update(ctx->hash_trans, idx);

	hdr = mail_hash_get_header(ctx->hash_trans);
	hdr->message_count--;
	return 1;
}
