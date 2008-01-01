/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

/*
 * Merge sort code in sort_nodes() is copyright 2001 Simon Tatham.
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL SIMON TATHAM BE LIABLE FOR
 * ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* Implementation of draft-ietf-imapext-thread-12 threading algorithm */

#include "common.h"
#include "hash.h"
#include "ostream.h"
#include "str.h"
#include "rfc822-parser.h"
#include "imap-base-subject.h"
#include "mail-storage.h"
#include "imap-thread.h"

#include <stdlib.h>

/* how much memory to allocate initially. these are very rough
   approximations. */
#define APPROX_MSG_COUNT 128
#define APPROX_MSGID_SIZE 45

/* Try to buffer this much data before sending it to output stream. */
#define OUTPUT_BUF_SIZE 2048

#define NODE_IS_DUMMY(node) ((node)->id == 0)
#define NODE_HAS_PARENT(ctx, node) \
	((node)->parent != NULL && (node)->parent != &(ctx)->root_node)

struct root_info {
	char *base_subject;
	unsigned int reply:1;
	unsigned int sorted:1;
};

struct node {
	struct node *parent, *first_child, *next;

	unsigned int id;
	time_t sent_date;

	union {
		char *msgid;
		struct root_info *info;
	} u;
};

struct thread_context {
	struct mail_search_context *search_ctx;
	struct mailbox_transaction_context *t;
	struct mailbox *box;
	struct ostream *output;
	struct mail *mail;

	pool_t pool;
	pool_t temp_pool;

	struct hash_table *msgid_hash;
	struct hash_table *subject_hash;

	struct node root_node;
	size_t root_count; /* not exact after prune_dummy_messages() */

	bool id_is_uid;
};

static void mail_thread_input(struct thread_context *ctx, struct mail *mail);
static void mail_thread_finish(struct thread_context *ctx);

static void mail_thread_deinit(struct thread_context *ctx)
{
	if (ctx->msgid_hash != NULL)
		hash_destroy(&ctx->msgid_hash);
	if (ctx->subject_hash != NULL)
		hash_destroy(&ctx->subject_hash);

	pool_unref(&ctx->temp_pool);
	pool_unref(&ctx->pool);
}

int imap_thread(struct client_command_context *cmd, const char *charset,
		struct mail_search_arg *args, enum mail_thread_type type)
{
	static const char *wanted_headers[] = {
		"message-id", "in-reply-to", "references", "subject",
		NULL
	};
	struct client *client = cmd->client;
	struct mailbox_header_lookup_ctx *headers_ctx;
	struct thread_context *ctx;
	struct mail *mail;
	int ret;

	if (type != MAIL_THREAD_REFERENCES)
		i_fatal("Only REFERENCES threading supported");

	ctx = t_new(struct thread_context, 1);

	/* initialize searching */
	ctx->t = mailbox_transaction_begin(client->mailbox, 0);
	ctx->search_ctx = mailbox_search_init(ctx->t, charset, args, NULL);

	ctx->box = client->mailbox;
	ctx->output = client->output;
	ctx->pool = pool_alloconly_create("thread_context",
					  sizeof(struct node) *
					  APPROX_MSG_COUNT);
	ctx->temp_pool = pool_alloconly_create("thread_context temp",
					       APPROX_MSG_COUNT *
					       APPROX_MSGID_SIZE);
	ctx->msgid_hash = hash_create(default_pool, ctx->temp_pool,
				      APPROX_MSG_COUNT*2, str_hash,
				      (hash_cmp_callback_t *)strcmp);
	ctx->id_is_uid = cmd->uid;

	headers_ctx = mailbox_header_lookup_init(client->mailbox,
						 wanted_headers);
	mail = mail_alloc(ctx->t, MAIL_FETCH_DATE, headers_ctx);
	while (mailbox_search_next(ctx->search_ctx, mail) > 0) {
		T_FRAME(
			mail_thread_input(ctx, mail);
		);
	}

	mail_free(&mail);

	o_stream_send_str(client->output, "* THREAD");
	mail_thread_finish(ctx);
	o_stream_send_str(client->output, "\r\n");

	ret = mailbox_search_deinit(&ctx->search_ctx);
	if (mailbox_transaction_commit(&ctx->t) < 0)
		ret = -1;

	mailbox_header_lookup_deinit(&headers_ctx);
        mail_thread_deinit(ctx);
	return ret;
}

static void add_root(struct thread_context *ctx, struct node *node)
{
	node->parent = &ctx->root_node;
	node->next = ctx->root_node.first_child;
	ctx->root_node.first_child = node;

	ctx->root_count++;
}

static struct node *create_node(struct thread_context *ctx, const char *msgid)
{
	struct node *node;

	node = p_new(ctx->pool, struct node, 1);
	node->u.msgid = p_strdup(ctx->temp_pool, msgid);

	hash_insert(ctx->msgid_hash, node->u.msgid, node);
	return node;
}

static struct node *create_id_node(struct thread_context *ctx,
				   unsigned int id, time_t sent_date)
{
	struct node *node;

	node = p_new(ctx->pool, struct node, 1);
	node->id = id;
	node->sent_date = sent_date;

	add_root(ctx, node);
	return node;
}

static struct node *update_message(struct thread_context *ctx,
				   const char *msgid, time_t sent_date,
				   unsigned int id)
{
	struct node *node;

	if (msgid == NULL)
		return create_id_node(ctx, id, sent_date);

	node = hash_lookup(ctx->msgid_hash, msgid);
	if (node == NULL) {
		/* first time we see this message */
		node = create_node(ctx, msgid);
		node->id = id;
		node->sent_date = sent_date;
		return node;
	}

	if (node->id == 0) {
		/* seen before in references */
		node->id = id;
		node->sent_date = sent_date;
	} else {
		/* duplicate */
		node = create_id_node(ctx, id, sent_date);
	}

	return node;
}

static bool get_untokenized_msgid(const char **msgid_p, string_t *msgid)
{
	struct rfc822_parser_context parser;

	rfc822_parser_init(&parser, (const unsigned char *)*msgid_p,
			   strlen(*msgid_p), NULL);

	/*
	   msg-id          = [CFWS] "<" id-left "@" id-right ">" [CFWS]
	   id-left         = dot-atom-text / no-fold-quote / obs-id-left
	   id-right        = dot-atom-text / no-fold-literal / obs-id-right
	   no-fold-quote   = DQUOTE *(qtext / quoted-pair) DQUOTE
	   no-fold-literal = "[" *(dtext / quoted-pair) "]"
	*/

	(void)rfc822_skip_lwsp(&parser);

	if (rfc822_parse_dot_atom(&parser, msgid) <= 0)
		return FALSE;

	if (*parser.data != '@')
		return FALSE;
	parser.data++;
	(void)rfc822_skip_lwsp(&parser);

	if (rfc822_parse_dot_atom(&parser, msgid) <= 0)
		return FALSE;

	if (*parser.data != '>')
		return FALSE;

	*msgid_p = (const char *)parser.data + 1;
	return TRUE;
}

static void strip_lwsp(char *str)
{
	/* @UNSAFE */
	char *dest;

	/* find the first lwsp */
	while (*str != ' ' && *str != '\t' && *str != '\r' && *str != '\n') {
		if (*str == '\0')
			return;
		str++;
	}

	for (dest = str; *str != '\0'; str++) {
		if (*str != ' ' && *str != '\t' && *str != '\r' && *str != '\n')
			*dest++ = *str;
	}
	*dest = '\0';
}

static const char *get_msgid(const char **msgid_p)
{
	const char *msgid = *msgid_p;
	const char *p;
	string_t *str = NULL;
	bool found_at;

	if (*msgid_p == NULL)
		return NULL;

	for (;;) {
		/* skip until '<' */
		while (*msgid != '<') {
			if (*msgid == '\0') {
				*msgid_p = msgid;
				return NULL;
			}
			msgid++;
		}
		msgid++;

		/* check it through quickly to see if it's already normalized */
		p = msgid; found_at = FALSE;
		for (;; p++) {
			if ((unsigned char)*p >= 'A') /* matches most */
				continue;

			if (*p == '@')
				found_at = TRUE;
			if (*p == '>' || *p == '"' || *p == '(' || *p == '[')
				break;

			if (*p == '\0') {
				*msgid_p = p;
				return NULL;
			}
		}

		if (*p == '>') {
			*msgid_p = p+1;
			if (found_at) {
				char *s;

				s = p_strdup_until(unsafe_data_stack_pool,
						   msgid, p);
				strip_lwsp(s);
				return s;
			}
		} else {
			/* ok, do it the slow way */
			*msgid_p = msgid;

			if (str == NULL) {
				/* allocate only once, so we don't leak
				   with multiple invalid message IDs */
				str = t_str_new(256);
			}
			if (get_untokenized_msgid(msgid_p, str))
				return str_c(str);
		}

		/* invalid message id, see if there's another valid one */
		msgid = *msgid_p;
	}
}

static void unlink_child(struct thread_context *ctx,
			 struct node *child, bool add_to_root)
{
	struct node **node;

        node = &child->parent->first_child;
	for (; *node != NULL; node = &(*node)->next) {
		if (*node == child) {
			*node = child->next;
			break;
		}
	}

	child->next = NULL;
	if (!add_to_root)
		child->parent = NULL;
	else
		add_root(ctx, child);
}

static bool find_parent(struct node *node, struct node *parent)
{
	while (node != NULL) {
		if (node == parent)
			return TRUE;
		node = node->parent;
	}
	return FALSE;
}

static void link_node(struct thread_context *ctx, const char *parent_msgid,
		      struct node *child, bool replace)
{
	struct node *parent, **node;

	if (NODE_HAS_PARENT(ctx, child) && !replace) {
		/* already got a parent, don't want to replace it */
		return;
	}

	parent = hash_lookup(ctx->msgid_hash, parent_msgid);
	if (parent == NULL)
		parent = create_node(ctx, parent_msgid);

	if (child->parent == parent) {
		/* already have this parent, ignore */
		return;
	}

	if (find_parent(parent, child)) {
		/* this would create a loop, not allowed */
		return;
	}

	if (child->parent != NULL)
		unlink_child(ctx, child, FALSE);

	/* link them */
	child->parent = parent;

	node = &parent->first_child;
	while (*node != NULL)
		node = &(*node)->next;
	*node = child;
}

static void link_message(struct thread_context *ctx,
			 const char *parent_msgid, const char *child_msgid,
			 bool replace)
{
	struct node *child;

	child = hash_lookup(ctx->msgid_hash, child_msgid);
	if (child == NULL)
		child = create_node(ctx, child_msgid);

	link_node(ctx, parent_msgid, child, replace);
}

static bool link_references(struct thread_context *ctx,
			    struct node *node, const char *references)
{
	const char *parent_id, *child_id;

	parent_id = get_msgid(&references);
	if (parent_id == NULL)
		return FALSE;

	while ((child_id = get_msgid(&references)) != NULL) {
		link_message(ctx, parent_id, child_id, FALSE);
		parent_id = child_id;
	}

	/* link the last message to us */
	link_node(ctx, parent_id, node, TRUE);
	return TRUE;
}

static void mail_thread_input(struct thread_context *ctx, struct mail *mail)
{
	const char *refid, *message_id, *in_reply_to, *references;
	struct node *node;
	time_t sent_date;

	if (mail_get_date(mail, &sent_date, NULL) < 0)
		sent_date = 0;

	if (mail_get_first_header(mail, "message-id", &message_id) < 0)
		message_id = NULL;
	node = update_message(ctx, get_msgid(&message_id), sent_date,
			      ctx->id_is_uid ? mail->uid : mail->seq);

	/* link references */
	if (mail_get_first_header(mail, "references", &references) < 0)
		references = NULL;

	if (!link_references(ctx, node, references)) {
		if (mail_get_first_header(mail, "in-reply-to",
					  &in_reply_to) <= 0)
			refid = NULL;
		else
			refid = get_msgid(&in_reply_to);

		if (refid != NULL)
			link_node(ctx, refid, node, TRUE);
		else {
			/* no references, make sure it's not linked */
			if (node != NULL && NODE_HAS_PARENT(ctx, node))
				unlink_child(ctx, node, TRUE);
		}
	}
}

static struct node *find_last_child(struct node *node)
{
	node = node->first_child;
	while (node->next != NULL)
		node = node->next;

	return node;
}

static struct node **promote_children(struct node **parent)
{
	struct node *new_parent, *old_parent, *child;

	old_parent = *parent;
	new_parent = old_parent->parent;

	child = old_parent->first_child;
	*parent = child;

	for (;;) {
		child->parent = new_parent;
		if (child->next == NULL)
			break;
		child = child->next;
	}

	child->next = old_parent->next;
	return &child->next;
}

static void prune_dummy_messages(struct thread_context *ctx,
				 struct node **node_p)
{
	struct node **a;

	a = node_p;
	while (*node_p != NULL) {
		if ((*node_p)->first_child != NULL)
			prune_dummy_messages(ctx, &(*node_p)->first_child);

		if (NODE_IS_DUMMY(*node_p)) {
			if ((*node_p)->first_child == NULL) {
				/* no children -> delete */
				*node_p = (*node_p)->next;
				continue;
			} else if (NODE_HAS_PARENT(ctx, *node_p) ||
				   (*node_p)->first_child->next == NULL) {
				/* promote children to our level,
				   deleting the dummy node */
				node_p = promote_children(node_p);
				continue;
			}
		}

                node_p = &(*node_p)->next;
	}
}

static int node_cmp(struct node *a, struct node *b)
{
	time_t date_a, date_b;
	unsigned int id_a, id_b;

	date_a = a->id != 0 ? a->sent_date : a->first_child->sent_date;
	date_b = b->id != 0 ? b->sent_date : b->first_child->sent_date;

	if (date_a != date_b && date_a != 0 && date_b != 0)
		return date_a < date_b ? -1 : 1;

	id_a = a->id != 0 ? a->id : a->first_child->id;
	id_b = b->id != 0 ? b->id : b->first_child->id;
	return id_a < id_b ? -1 : 1;
}

static struct node *sort_nodes(struct node *list)
{
	struct node *p, *q, *e, *tail;
	size_t insize, nmerges, psize, qsize, i;

	i_assert(list != NULL);

	if (list->next == NULL)
		return list; /* just one node */

	insize = 1;

	for (;;) {
		p = list;
		list = NULL;
		tail = NULL;

		nmerges = 0;  /* count number of merges we do in this pass */
		while (p != 0) {
			nmerges++;  /* there exists a merge to be done */

			/* step `insize' places along from p */
			q = p;
			psize = 0;
			for (i = 0; i < insize; i++) {
				psize++;
				q = q->next;
				if (q == NULL) break;
			}

			/* if q hasn't fallen off end, we have two lists to
			   merge */
			qsize = insize;

			/* now we have two lists; merge them */
			while (psize > 0 || (qsize > 0 && q != NULL)) {
				/* decide whether next element of merge comes
				   from p or q */
				if (psize == 0) {
					/* p is empty; e must come from q. */
					e = q; q = q->next; qsize--;
				} else if (qsize == 0 || !q) {
					/* q is empty; e must come from p. */
					e = p; p = p->next; psize--;
				} else if (node_cmp(p, q) <= 0) {
					/* First element of p is lower
					   (or same); e must come from p. */
					e = p; p = p->next; psize--;
				} else {
					/* First element of q is lower;
					   e must come from q. */
					e = q; q = q->next; qsize--;
				}

				/* add the next element to the merged list */
				if (tail)
					tail->next = e;
				else
					list = e;
				tail = e;
			}

			/* now p has stepped `insize' places along,
			   and q has too */
			p = q;
		}
		tail->next = NULL;

		/* If we have done only one merge, we're finished. */
		if (nmerges <= 1) {
                        /* allow for nmerges == 0, the empty list case */
			return list;
		}

		/* Otherwise repeat, merging lists twice the size */
		insize *= 2;
	}
}

static void add_base_subject(struct thread_context *ctx,
			     const char *subject, struct node *node)
{
	struct node *hash_node;
	char *hash_subject;
	void *key, *value;
	bool is_reply_or_forward;

	if (subject == NULL)
		return;

	subject = imap_get_base_subject_cased(pool_datastack_create(), subject,
					      &is_reply_or_forward);
	if (*subject == '\0')
		return;

	if (!hash_lookup_full(ctx->subject_hash, subject, &key, &value)) {
		hash_subject = p_strdup(ctx->temp_pool, subject);
		hash_insert(ctx->subject_hash, hash_subject, node);
	} else {
		hash_subject = key;
		hash_node = value;

		if (!NODE_IS_DUMMY(hash_node) &&
		    (NODE_IS_DUMMY(node) ||
		     (hash_node->u.info->reply && !is_reply_or_forward)))
			hash_update(ctx->subject_hash, hash_subject, node);
	}

	node->u.info->base_subject = hash_subject;
	node->u.info->reply = is_reply_or_forward;
}

static void gather_base_subjects(struct thread_context *ctx)
{
	static const char *wanted_headers[] = { "subject", NULL };
	struct mailbox_header_lookup_ctx *headers_ctx;
	struct node *node;
	const char *subject;
	unsigned int id;
	uint32_t seq;

	ctx->subject_hash =
		hash_create(default_pool, ctx->temp_pool, ctx->root_count * 2,
			    str_hash, (hash_cmp_callback_t *)strcmp);

	headers_ctx = mailbox_header_lookup_init(ctx->box, wanted_headers);
	ctx->mail = mail_alloc(ctx->t, 0, headers_ctx);

	node = ctx->root_node.first_child;
	for (; node != NULL; node = node->next) {
		if (!NODE_IS_DUMMY(node))
			id = node->id;
		else {
			/* sort children, use the first one's id */
			node->first_child = sort_nodes(node->first_child);
			id = node->first_child->id;

			node->u.info->sorted = TRUE;
		}

		if (!ctx->id_is_uid)
			seq = id;
		else
			mailbox_get_uids(ctx->box, id, id, &seq, &seq);

		if (seq != 0) {
			mail_set_seq(ctx->mail, seq);
			if (mail_get_first_header(ctx->mail, "subject",
						  &subject) > 0) {
				T_FRAME(
					add_base_subject(ctx, subject, node);
				);
			}
		}
	}

	mail_free(&ctx->mail);
	mailbox_header_lookup_deinit(&headers_ctx);
}

static void reset_children_parent(struct node *parent)
{
	struct node *node;

	for (node = parent->first_child; node != NULL; node = node->next)
		node->parent = parent;
}

static void merge_subject_threads(struct thread_context *ctx)
{
	struct node **node_p, *node, *hash_node;
	char *base_subject;

	for (node_p = &ctx->root_node.first_child; *node_p != NULL; ) {
		node = *node_p;

		if (node->u.info == NULL) {
			/* deleted node */
			*node_p = node->next;
			continue;
		}

		/* (ii) If the thread subject is empty, skip this message. */
		base_subject = node->u.info->base_subject;
		if (base_subject == NULL) {
			node_p = &node->next;
			continue;
		}

		/* (iii) Lookup the message associated with this thread
		   subject in the subject table. */
		hash_node = hash_lookup(ctx->subject_hash, base_subject);
		i_assert(hash_node != NULL);

		/* (iv) If the message in the subject table is the current
		   message, skip this message. */
		if (hash_node == node) {
			node_p = &node->next;
			continue;
		}

		/* Otherwise, merge the current message with the one in the
		   subject table using the following rules: */

		if (NODE_IS_DUMMY(node) &&
		    NODE_IS_DUMMY(hash_node)) {
			/* If both messages are dummies, append the current
			   message's children to the children of the message in
			   the subject table (the children of both messages
			   become siblings), and then delete the current
			   message. */
			find_last_child(hash_node)->next = node->first_child;

			*node_p = node->next;
			hash_node->u.info->sorted = FALSE;
		} else if (NODE_IS_DUMMY(hash_node) ||
			   (node->u.info->reply && !hash_node->u.info->reply)) {
			/* If the message in the subject table is a dummy
			   and the current message is not, make the current
			   message a child of the message in the subject table
			   (a sibling of its children).

			   If the current message is a reply or forward and
			   the message in the subject table is not, make the
			   current message a child of the message in the
			   subject table (a sibling of its children). */
			*node_p = node->next;

			node->parent = hash_node;
			node->next = hash_node->first_child;
			hash_node->first_child = node;

			hash_node->u.info->sorted = FALSE;
		} else {
			/* Otherwise, create a new dummy message and make both
			   the current message and the message in the subject
			   table children of the dummy.  Then replace the
			   message in the subject table with the dummy
			   message. */

			/* create new nodes for the children - reusing
			   existing ones have problems since the other one
			   might have been handled already and we'd introduce
			   loops..

			   current node will be destroyed, hash_node will be
			   the dummy so we don't need to update hash */
			struct node *node1, *node2;

			node1 = p_new(ctx->pool, struct node, 1);
			node2 = p_new(ctx->pool, struct node, 1);

			memcpy(node1, node, sizeof(struct node));
			memcpy(node2, hash_node, sizeof(struct node));

			node1->parent = hash_node;
			node2->parent = hash_node;
			node1->next = node2;
			node2->next = NULL;

			reset_children_parent(node1);
			reset_children_parent(node2);

			hash_node->id = 0;
			hash_node->first_child = node1;
			hash_node->u.info->reply = FALSE;
			hash_node->u.info->sorted = FALSE;

			node->first_child = NULL;
			node->u.info = NULL;
			*node_p = node->next;
		}
	}
}

static void sort_root_nodes(struct thread_context *ctx)
{
	struct node *node;

	/* sort the children first, they're needed to sort dummy root nodes */
        node = ctx->root_node.first_child;
	for (; node != NULL; node = node->next) {
		if (node->u.info == NULL)
			continue;

		if (NODE_IS_DUMMY(node) && !node->u.info->sorted &&
		    node->first_child != NULL)
			node->first_child = sort_nodes(node->first_child);
	}

	ctx->root_node.first_child = sort_nodes(ctx->root_node.first_child);
}

static bool send_nodes(struct thread_context *ctx,
		       string_t *str, struct node *node)
{
	if (node->next == NULL && NODE_HAS_PARENT(ctx, node)) {
		/* no siblings - special case to avoid extra paranthesis */
		if (node->first_child == NULL)
			str_printfa(str, "%u", node->id);
		else {
			str_printfa(str, "%u ", node->id);
			send_nodes(ctx, str, sort_nodes(node->first_child));
		}
		return TRUE;
	}

	while (node != NULL) {
		if (str_len(str) + MAX_INT_STRLEN*2 + 3 >= OUTPUT_BUF_SIZE) {
			/* string getting full, flush it */
			if (o_stream_send(ctx->output,
					  str_data(str), str_len(str)) < 0)
				return FALSE;
			str_truncate(str, 0);
		}

		if (node->first_child == NULL)
			str_printfa(str, "(%u)", node->id);
		else {
			str_printfa(str, "(%u ", node->id);
			send_nodes(ctx, str, sort_nodes(node->first_child));
			str_append_c(str, ')');
		}

		node = node->next;
	}
	return TRUE;
}

static void send_roots(struct thread_context *ctx)
{
	struct node *node;
	string_t *str;

	str = t_str_new(OUTPUT_BUF_SIZE);
	str_append_c(str, ' ');

	/* sort root nodes again, they have been modified since the last time */
	sort_root_nodes(ctx);

        node = ctx->root_node.first_child;
	for (; node != NULL; node = node->next) {
		if (node->u.info == NULL)
			continue;

		if (str_len(str) + MAX_INT_STRLEN*2 + 3 >= OUTPUT_BUF_SIZE) {
			/* string getting full, flush it */
			if (o_stream_send(ctx->output,
					  str_data(str), str_len(str)) < 0)
				return;
			str_truncate(str, 0);
		}

		str_append_c(str, '(');
		if (!NODE_IS_DUMMY(node))
			str_printfa(str, "%u", node->id);

		if (node->first_child != NULL) {
			if (!NODE_IS_DUMMY(node))
				str_append_c(str, ' ');

			if (!node->u.info->sorted) {
				node->first_child =
					sort_nodes(node->first_child);
			}

			if (!send_nodes(ctx, str, node->first_child))
				return;
		}

		str_append_c(str, ')');
	}

	(void)o_stream_send(ctx->output, str_data(str), str_len(str));
}

static void mail_thread_finish(struct thread_context *ctx)
{
	struct hash_iterate_context *iter;
	void *key, *value;
	struct node *node;

	/* (2) save root nodes and drop the msgids */
	iter = hash_iterate_init(ctx->msgid_hash);
	while (hash_iterate(iter, &key, &value)) {
		struct node *node = value;

		if (node->parent == NULL)
			add_root(ctx, node);
	}
	hash_iterate_deinit(&iter);

	/* drop the memory allocated for message-IDs and msgid_hash,
	   reuse their memory for base subjects */
	hash_destroy(&ctx->msgid_hash);
	p_clear(ctx->temp_pool);

	if (ctx->root_node.first_child == NULL) {
		/* no messages */
		return;
	}

	/* (3) */
	prune_dummy_messages(ctx, &ctx->root_node.first_child);

	/* initialize the node->u.info for all root nodes */
        node = ctx->root_node.first_child;
	for (; node != NULL; node = node->next)
		node->u.info = p_new(ctx->pool, struct root_info, 1);

	/* (4) */
	sort_root_nodes(ctx);

	/* (5) Gather together messages under the root that have the same
	   base subject text. */
	gather_base_subjects(ctx);

	/* (5.C) Merge threads with the same thread subject. */
	merge_subject_threads(ctx);

	/* (6) Sort and send replies */
	T_FRAME(
		send_roots(ctx);
	);
}
