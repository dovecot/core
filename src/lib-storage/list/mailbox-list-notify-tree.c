/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "mail-index.h"
#include "mail-storage.h"
#include "mailbox-list-private.h"
#include "mailbox-list-index.h"
#include "mailbox-list-notify-tree.h"

struct mailbox_list_notify_tree {
	struct mailbox_list *list;
	struct mailbox_tree_context *mailboxes;

	struct mail_index_view *view;
	bool failed;
};

static void
mailbox_list_notify_node_get_status(struct mailbox_list_notify_tree *tree,
				    struct mailbox_notify_node *nnode)
{
	struct mailbox_status status;
	uint32_t seq;

	if (!mail_index_lookup_seq(tree->view, nnode->index_uid, &seq))
		return;

	memset(&status, 0, sizeof(status));
	(void)mailbox_list_index_status(tree->list, tree->view, seq,
		STATUS_UIDVALIDITY | STATUS_UIDNEXT | STATUS_MESSAGES |
		STATUS_UNSEEN | STATUS_HIGHESTMODSEQ, &status, nnode->guid);
	nnode->uidvalidity = status.uidvalidity;
	nnode->uidnext = status.uidnext;
	nnode->messages = status.messages;
	nnode->unseen = status.unseen;
	nnode->highest_modseq = status.highest_modseq;
}

static void
mailbox_list_notify_node_build(struct mailbox_list_notify_tree *tree,
			       struct mailbox_list_index_node *index_node,
			       string_t *path)
{
	struct mailbox_node *node;
	struct mailbox_notify_node *nnode;
	unsigned int prefix_len;
	bool created;

	str_append(path, index_node->name);

	node = mailbox_tree_get(tree->mailboxes, str_c(path), &created);
	nnode = (struct mailbox_notify_node *)node;
	nnode->index_uid = index_node->uid;

	if ((index_node->flags & MAILBOX_LIST_INDEX_FLAG_NONEXISTENT) != 0)
		node->flags = MAILBOX_NONEXISTENT;
	else if ((index_node->flags & MAILBOX_LIST_INDEX_FLAG_NOSELECT) != 0)
		node->flags = MAILBOX_NOSELECT;
	else {
		node->flags = 0;
		mailbox_list_notify_node_get_status(tree, nnode);
	}
	if ((index_node->flags & MAILBOX_LIST_INDEX_FLAG_NOINFERIORS) != 0)
		node->flags |= MAILBOX_NOINFERIORS;

	if (index_node->children != NULL) {
		str_append_c(path, mailbox_list_get_hierarchy_sep(tree->list));
		prefix_len = str_len(path);
		index_node = index_node->children;
		for (; index_node != NULL; index_node = index_node->next) {
			str_truncate(path, prefix_len);
			mailbox_list_notify_node_build(tree, index_node, path);
		}
	}
}

static void
mailbox_list_notify_tree_build(struct mailbox_list_notify_tree *tree)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(tree->list);
	struct mailbox_list_index_node *index_node;
	string_t *path = t_str_new(128);

	if (mailbox_list_index_refresh(tree->list) < 0)
		tree->failed = TRUE;

	tree->view = mail_index_view_open(ilist->index);
	index_node = ilist->mailbox_tree;
	for (; index_node != NULL; index_node = index_node->next) {
		str_truncate(path, 0);
		mailbox_list_notify_node_build(tree, index_node, path);
	}
	mail_index_view_close(&tree->view);
}

struct mailbox_list_notify_tree *
mailbox_list_notify_tree_init(struct mailbox_list *list)
{
	struct mailbox_list_notify_tree *tree;

	tree = i_new(struct mailbox_list_notify_tree, 1);
	tree->list = list;
	tree->mailboxes =
		mailbox_tree_init_size(mailbox_list_get_hierarchy_sep(list),
				       sizeof(struct mailbox_notify_node));
	mailbox_list_notify_tree_build(tree);
	return tree;
}

void mailbox_list_notify_tree_deinit(struct mailbox_list_notify_tree **_tree)
{
	struct mailbox_list_notify_tree *tree = *_tree;

	*_tree = NULL;

	mailbox_tree_deinit(&tree->mailboxes);
	i_free(tree);
}

struct mailbox_notify_node *
mailbox_list_notify_tree_lookup(struct mailbox_list_notify_tree *tree,
				const char *storage_name)
{
	struct mailbox_node *node;

	node = mailbox_tree_lookup(tree->mailboxes, storage_name);
	return (struct mailbox_notify_node *)node;
}
