/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "message-id.h"
#include "mail-storage.h"
#include "index-thread-private.h"

static uint32_t thread_msg_add(struct mail_thread_cache *cache,
			       uint32_t uid, uint32_t msgid_idx)
{
	struct mail_thread_node *node;

	i_assert(msgid_idx != 0);
	i_assert(msgid_idx < cache->first_invalid_msgid_str_idx);

	node = array_idx_modifiable(&cache->thread_nodes, msgid_idx);
	if (node->uid == 0)
		node->uid = uid;
	else {
		/* duplicate message-id, keep the original.
		   if the original ever gets expunged, rebuild. */
		node->expunge_rebuilds = TRUE;

		msgid_idx = cache->next_invalid_msgid_str_idx++;
		node = array_idx_modifiable(&cache->thread_nodes, msgid_idx);
		node->uid = uid;
	}
	return msgid_idx;
}

static bool thread_node_has_ancestor(struct mail_thread_cache *cache,
				     const struct mail_thread_node *node,
				     const struct mail_thread_node *ancestor)
{
	while (node != ancestor) {
		if (node->parent_idx == 0)
			return FALSE;

		node = array_idx(&cache->thread_nodes, node->parent_idx);
	}
	return TRUE;
}

static void thread_link_reference(struct mail_thread_cache *cache,
				  uint32_t parent_idx, uint32_t child_idx)
{
	struct mail_thread_node *node, *parent, *child;
	uint32_t idx;

	i_assert(parent_idx < cache->first_invalid_msgid_str_idx);

	/* either child_idx or parent_idx may cause thread_nodes array to
	   grow. in such situation the other pointer may become invalid if
	   we don't get the pointers in correct order. */
	if (child_idx < parent_idx) {
		parent = array_idx_modifiable(&cache->thread_nodes, parent_idx);
		child = array_idx_modifiable(&cache->thread_nodes, child_idx);
	} else {
		child = array_idx_modifiable(&cache->thread_nodes, child_idx);
		parent = array_idx_modifiable(&cache->thread_nodes, parent_idx);
	}

	child->parent_link_refcount++;
	if (thread_node_has_ancestor(cache, parent, child)) {
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
			i_assert(idx != 0);
			node = array_idx_modifiable(&cache->thread_nodes, idx);
			node->child_unref_rebuilds = TRUE;
		} while (node != child);
		return;
	} else if (child->parent_idx == parent_idx) {
		/* The same link already exists */
		return;
	}

	/* Set parent_node as child_node's parent */
	if (child->parent_idx == 0) {
		child->parent_idx = parent_idx;
	} else {
		/* Conflicting parent already exists, keep the original */
		if (MAIL_THREAD_NODE_EXISTS(child)) {
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
			child->child_unref_rebuilds = TRUE;
		}
	}
}

static uint32_t
thread_link_references(struct mail_thread_cache *cache, uint32_t uid,
		       const struct mail_index_strmap_rec *msgid_map,
		       unsigned int *msgid_map_idx)
{
	uint32_t parent_idx;

	if (msgid_map->uid != uid)
		return 0;

	parent_idx = msgid_map->str_idx;
	msgid_map++;
	*msgid_map_idx += 1;

	for (; msgid_map->uid == uid; msgid_map++) {
		thread_link_reference(cache, parent_idx, msgid_map->str_idx);
		parent_idx = msgid_map->str_idx;
		*msgid_map_idx += 1;
	}
	i_assert(parent_idx < cache->first_invalid_msgid_str_idx);
	return parent_idx;
}

void mail_thread_add(struct mail_thread_cache *cache,
		     const struct mail_index_strmap_rec *msgid_map,
		     unsigned int *msgid_map_idx)
{
	struct mail_thread_node *node;
	uint32_t idx, parent_idx;

	i_assert(msgid_map->ref_index == MAIL_THREAD_NODE_REF_MSGID);
	i_assert(cache->last_uid <= msgid_map->uid);

	cache->last_uid = msgid_map->uid;

	idx = thread_msg_add(cache, msgid_map->uid, msgid_map->str_idx);
	parent_idx = thread_link_references(cache, msgid_map->uid,
					    msgid_map + 1, msgid_map_idx);

	node = array_idx_modifiable(&cache->thread_nodes, idx);
	if (node->parent_idx != parent_idx && node->parent_idx != 0) {
		/* conflicting parent, remove it. */
		node->parent_idx = 0;
		/* If this message gets expunged, we have to revert back to
		   the original parent. */
		node->expunge_rebuilds = TRUE;
	}
	if (parent_idx != 0)
		thread_link_reference(cache, parent_idx, idx);
	*msgid_map_idx += 1;
}

static bool
mail_thread_unref_link(struct mail_thread_cache *cache,
		       uint32_t parent_idx, uint32_t child_idx)
{
	struct mail_thread_node *parent, *child;

	parent = array_idx_modifiable(&cache->thread_nodes, parent_idx);
	if (parent->child_unref_rebuilds)
		return FALSE;

	child = array_idx_modifiable(&cache->thread_nodes, child_idx);
	i_assert(child->parent_link_refcount > 0);

	child->parent_link_refcount--;
	if (child->parent_link_refcount == 0) {
		/* we don't have a root anymore */
		child->parent_idx = 0;
	}
	return TRUE;
}

bool mail_thread_remove(struct mail_thread_cache *cache,
			const struct mail_index_strmap_rec *msgid_map,
			unsigned int *msgid_map_idx)
{
	struct mail_thread_node *node;
	uint32_t idx, parent_idx;
	unsigned int count = 1;

	idx = msgid_map->str_idx;
	i_assert(idx != 0);

	if (msgid_map->uid > cache->last_uid) {
		/* this message was never added to the cache, skip */
		while (msgid_map[count].uid == msgid_map->uid)
			count++;
		*msgid_map_idx += count;
		return TRUE;
	}

	node = array_idx_modifiable(&cache->thread_nodes, idx);
	if (node->expunge_rebuilds) {
		/* this catches the duplicate message-id case */
		return FALSE;
	}
	i_assert(node->uid == msgid_map->uid);

	/* update link refcounts */
	if (msgid_map[count].uid == node->uid) {
		parent_idx = msgid_map[count].str_idx;
		count++;
		while (msgid_map[count].uid == node->uid) {
			if (!mail_thread_unref_link(cache, parent_idx,
						    msgid_map[count].str_idx))
				return FALSE;
			parent_idx = msgid_map[count].str_idx;
			count++;
		}
		if (!mail_thread_unref_link(cache, parent_idx, idx))
			return FALSE;
	}
	/* mark this message as expunged */
	node->uid = 0;

	/* we don't know (and don't want to waste time figuring out) if other
	   messages point to this removed message, so don't delete the node */
	*msgid_map_idx += count;
	return TRUE;
}
