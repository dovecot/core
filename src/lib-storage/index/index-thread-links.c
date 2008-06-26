/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "message-id.h"
#include "mail-storage.h"
#include "index-thread-private.h"

static struct mail_thread_node *
thread_msgid_get(struct mail_thread_update_context *ctx, uint32_t ref_uid,
		 unsigned int ref_index, const char *msgid, uint32_t *idx_r)
{
	struct mail_thread_node *node, new_node;
	struct msgid_search_key key;
	const char **msgidp;
	uint32_t idx;

	i_assert(ref_index != MAIL_INDEX_NODE_REF_MSGID);

	key.msgid = msgid;
	key.msgid_crc32 = crc32_str_nonzero(msgid);

	node = mail_hash_lookup(ctx->hash_trans, &key, &idx);
	if (node == NULL) {
		/* not found, create */
		memset(&new_node, 0, sizeof(new_node));
		new_node.msgid_crc32 = key.msgid_crc32;
		if (ref_index <= MAIL_INDEX_NODE_REF_MAX_VALUE) {
			new_node.uid_or_id = ref_uid;
			new_node.ref_index = ref_index;
		} else {
			new_node.uid_or_id =
				mail_thread_list_add(ctx->thread_list_ctx,
						     msgid);
			new_node.ref_index = MAIL_INDEX_NODE_REF_EXT;
		}

		mail_hash_insert(ctx->hash_trans, &key, &new_node, &idx);
		node = mail_hash_lookup_idx(ctx->hash_trans, idx);
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
		node = thread_msgid_get(ctx, 0, 0, msgid, idx_r);
		if (!MAIL_INDEX_NODE_EXISTS(node)) {
			/* add UID to node */
			if (node->ref_index == MAIL_INDEX_NODE_REF_EXT &&
			    node->uid_or_id != 0) {
				mail_thread_list_remove(ctx->thread_list_ctx,
							node->uid_or_id);
			}

			node->uid_or_id = uid;
			node->ref_index = MAIL_INDEX_NODE_REF_MSGID;
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
		unode.uid_or_id = uid;
		unode.ref_index = MAIL_INDEX_NODE_REF_MSGID;
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

	child->parent_link_refcount++;
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
		if (MAIL_INDEX_NODE_EXISTS(child)) {
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

struct thread_message_id {
	const char *str;
	uint32_t crc32;
	unsigned int collisions_after;
};

static const char *
thread_link_references(struct mail_thread_update_context *ctx, uint32_t ref_uid,
		       const char *references)
{
	ARRAY_DEFINE(id_arr, struct thread_message_id);
	struct thread_message_id *ids;
	struct thread_message_id id;
	uint32_t parent_idx, child_idx;
	unsigned int i, j, count, ref_index;

	/* put all message IDs to an array */
	memset(&id, 0, sizeof(id));
	t_array_init(&id_arr, 32);
	while ((id.str = message_id_get_next(&references)) != NULL) {
		id.crc32 = crc32_str_nonzero(id.str);
		array_append(&id_arr, &id, 1);
	}

	ids = array_get_modifiable(&id_arr, &count);
	if (count <= 1)
		return count == 0 ? NULL : ids[0].str;

	/* count collisions */
	for (i = 0; i < count; i++) {
		for (j = i + 1; j < count; j++) {
			if (ids[i].crc32 == ids[j].crc32)
				ids[i].collisions_after++;
		}
	}

	ref_index = MAIL_INDEX_NODE_REF_REFERENCES_LAST +
		ids[0].collisions_after;
	thread_msgid_get(ctx, ref_uid, ref_index, ids[0].str, &parent_idx);
	for (i = 1; i < count; i++) {
		ref_index = MAIL_INDEX_NODE_REF_REFERENCES_LAST +
			ids[i].collisions_after;
		thread_msgid_get(ctx, ref_uid, ref_index,
				 ids[i].str, &child_idx);
		thread_link_reference(ctx, parent_idx, child_idx);
		parent_idx = child_idx;
	}

	/* link the last ID to us */
	return ids[count-1].str;
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

int mail_thread_add(struct mail_thread_update_context *ctx, struct mail *mail)
{
	const char *message_id, *in_reply_to, *references, *parent_msgid;
	const struct mail_thread_node *parent, *old_parent;
	struct mail_hash_header *hdr;
	struct mail_thread_node *node;
	uint32_t idx, parent_idx;
	unsigned int ref_index;

	hdr = mail_hash_get_header(ctx->hash_trans);
	i_assert(mail->uid > hdr->last_uid);
	hdr->last_uid = mail->uid;
	hdr->message_count++;

	if (thread_get_mail_header(mail, HDR_MESSAGE_ID, &message_id) < 0 ||
	    thread_get_mail_header(mail, HDR_REFERENCES, &references) < 0)
		return -1;

	thread_msg_add(ctx, mail->uid, message_id_get_next(&message_id), &idx);
	parent_msgid = thread_link_references(ctx, mail->uid, references);

	if (parent_msgid != NULL)
		ref_index = MAIL_INDEX_NODE_REF_REFERENCES_LAST;
	else {
		/* no valid IDs in References:, use In-Reply-To: instead */
		if (thread_get_mail_header(mail, HDR_IN_REPLY_TO,
					   &in_reply_to) < 0)
			return -1;
		parent_msgid = message_id_get_next(&in_reply_to);
		ref_index = MAIL_INDEX_NODE_REF_INREPLYTO;
	}
	parent = parent_msgid == NULL ? NULL :
		thread_msgid_get(ctx, mail->uid, ref_index,
				 parent_msgid, &parent_idx);

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
			uint32_t *idx_r, const char **msgid_r,
			struct mail_thread_node **node_r)
{
	struct mail_thread_node *node;
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

	node = mail_hash_lookup(ctx->hash_trans, &key, idx_r);
	if (node == NULL)
		return FALSE;

	if (node->ref_index != MAIL_INDEX_NODE_REF_MSGID ||
	    node->uid_or_id != uid) {
		/* duplicate Message-ID probably */
		return FALSE;
	}
	*msgid_r = key.msgid;
	*node_r = node;
	return TRUE;
}

static bool
thread_msgid_lookup(struct mail_thread_update_context *ctx, const char *msgid,
		    uint32_t *idx_r)
{
	struct msgid_search_key key;

	key.msgid = msgid;
	key.msgid_crc32 = crc32_str_nonzero(msgid);

	ctx->cmp_match_count = 0;
	ctx->cmp_last_idx = 0;

	if (mail_hash_lookup(ctx->hash_trans, &key, idx_r) == NULL) {
		if (ctx->cmp_match_count != 1 || ctx->failed) {
			/* couldn't find the message-id */
			return FALSE;
		}

		/* there's only one key with this crc32 value, so it
		   must be what we're looking for */
		*idx_r = ctx->cmp_last_idx;
	}
	return TRUE;
}

static bool
thread_unref_msgid(struct mail_thread_update_context *ctx,
		   uint32_t ref_uid, uint32_t parent_idx,
		   const char *child_msgid, uint32_t child_idx)
{
	struct mail_thread_node *parent, *child;

	parent = mail_hash_lookup_idx(ctx->hash_trans, parent_idx);
	if (parent->parent_unref_rebuilds)
		return FALSE;

	child = mail_hash_lookup_idx(ctx->hash_trans, child_idx);
	if (child->parent_link_refcount == 0) {
		mail_hash_transaction_set_corrupted(ctx->hash_trans,
						    "unexpected refcount=0");
		return FALSE;
	}
	child->parent_link_refcount--;
	if (child->parent_link_refcount == 0) {
		/* we don't have a root anymore */
		child->parent_idx = 0;
	}

	if (child->uid_or_id == ref_uid &&
	    child->ref_index != MAIL_INDEX_NODE_REF_EXT) {
		child->uid_or_id =
			mail_thread_list_add(ctx->thread_list_ctx, child_msgid);
		child->ref_index = MAIL_INDEX_NODE_REF_EXT;
	}
	mail_hash_update(ctx->hash_trans, child_idx);

	if (parent->uid_or_id == ref_uid &&
	    parent->ref_index != MAIL_INDEX_NODE_REF_EXT) {
		parent->uid_or_id =
			mail_thread_list_add(ctx->thread_list_ctx, child_msgid);
		parent->ref_index = MAIL_INDEX_NODE_REF_EXT;
		mail_hash_update(ctx->hash_trans, parent_idx);
	}
	return TRUE;
}

static bool
thread_unref_links(struct mail_thread_update_context *ctx, uint32_t ref_uid,
		   const char *last_child_msgid, uint32_t last_child_idx,
		   const char *references, bool *valid_r)
{
	const char *msgid;
	uint32_t parent_idx, child_idx;

	/* tmp_mail may be changed below, so we have to duplicate the
	   references string */
	references = t_strdup(references);
	*valid_r = FALSE;

	msgid = message_id_get_next(&references);
	if (msgid == NULL)
		return TRUE;
	if (!thread_msgid_lookup(ctx, msgid, &parent_idx))
		return FALSE;
	*valid_r = TRUE;

	while ((msgid = message_id_get_next(&references)) != NULL) {
		if (!thread_msgid_lookup(ctx, msgid, &child_idx) ||
		    !thread_unref_msgid(ctx, ref_uid, parent_idx,
					msgid, child_idx))
			return FALSE;
		parent_idx = child_idx;
	}
	return thread_unref_msgid(ctx, ref_uid, parent_idx,
				  last_child_msgid, last_child_idx);
}

int mail_thread_remove(struct mail_thread_update_context *ctx, uint32_t uid)
{
	struct mail_hash_header *hdr;
	struct mail_thread_node *node;
	const char *msgid, *references, *in_reply_to;
	uint32_t idx, parent_idx;
	bool have_refs;

	if (!mail_thread_node_lookup(ctx, uid, &idx, &msgid, &node))
		return 0;
	if (node->expunge_rebuilds)
		return 0;

	if (mail_get_first_header(ctx->tmp_mail, HDR_REFERENCES,
				  &references) < 0)
		return -1;

	if (!thread_unref_links(ctx, uid, msgid, idx, references, &have_refs))
		return 0;
	if (!have_refs) {
		/* no valid IDs in References:, use In-Reply-To: instead */
		if (mail_get_first_header(ctx->tmp_mail, HDR_IN_REPLY_TO,
					  &in_reply_to) < 0)
			return -1;
		in_reply_to = message_id_get_next(&in_reply_to);
		if (in_reply_to != NULL &&
		    (!thread_msgid_lookup(ctx, in_reply_to, &parent_idx) ||
		     !thread_unref_msgid(ctx, uid, parent_idx,
					 in_reply_to, idx)))
			return 0;
	}

	/* get the node again, the pointer may have changed */
	node = mail_hash_lookup_idx(ctx->hash_trans, idx);

	node->uid_or_id = mail_thread_list_add(ctx->thread_list_ctx, msgid);
	node->ref_index = MAIL_INDEX_NODE_REF_EXT;
	mail_hash_update(ctx->hash_trans, idx);

	hdr = mail_hash_get_header(ctx->hash_trans);
	hdr->message_count--;
	return 1;
}
