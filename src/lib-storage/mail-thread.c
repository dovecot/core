/* Copyright (C) 2002 Timo Sirainen */

/*
 * Merge sort code in sort_child_nodes() is copyright 2001 Simon Tatham.
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

#include "lib.h"
#include "hash.h"
#include "ostream.h"
#include "str.h"
#include "message-tokenize.h"
#include "imap-base-subject.h"
#include "mail-thread.h"

#include <stdlib.h>

/* how much memory to allocate initially. these are very rough
   approximations. */
#define APPROX_MSG_COUNT 128
#define APPROX_MSGID_SIZE 45

/* Try to buffer this much data before sending it to output stream. */
#define OUTPUT_BUF_SIZE 2048

#define NODE_IS_DUMMY(node) ((node)->id == 0 || (node)->id == UINT_MAX)

struct node {
	struct node *parent, *first_child, *next;

	char *msgid;
	unsigned int id;
};

struct root_data {
	struct node *node;

	time_t sent_date;
	unsigned int sort_id;

	const char *base_subject;
	unsigned int reply:1;
};

struct mail_thread_context {
	pool_t pool;
	pool_t str_pool; /* for node->msgid and root_data->base_subject */

	struct hash_table *msgid_hash;
	struct hash_table *subject_hash;

	struct node *root_nodes;
	struct root_data *root_data; /* [root_count] */
	size_t root_count;

	const struct mail_sort_callbacks *callbacks;
	void *callback_context;

        struct ostream *output;
};

struct mail_thread_context *
mail_thread_init(enum mail_thread_type type, struct ostream *output,
		 const struct mail_sort_callbacks *callbacks,
		 void *callback_context)
{
	struct mail_thread_context *ctx;
	pool_t pool;

	pool = pool_alloconly_create("mail_thread_context",
				     sizeof(struct node) * APPROX_MSG_COUNT);

	ctx = p_new(pool, struct mail_thread_context, 1);
	ctx->pool = pool;
	ctx->str_pool =
		pool_alloconly_create("mail_thread_context strings",
				      sizeof(struct node) *
				      APPROX_MSG_COUNT * APPROX_MSGID_SIZE);
	ctx->msgid_hash = hash_create(default_pool,
				      APPROX_MSGID_SIZE*2, str_hash,
				      (HashCompareFunc)strcmp);
	ctx->callbacks = callbacks;
	ctx->callback_context = callback_context;
	ctx->output = output;
	return ctx;
}

static void mail_thread_deinit(struct mail_thread_context *ctx)
{
	if (ctx->msgid_hash != NULL)
		hash_destroy(ctx->msgid_hash);
	if (ctx->subject_hash != NULL)
		hash_destroy(ctx->subject_hash);
	pool_unref(ctx->str_pool);
	pool_unref(ctx->pool);
}

static void add_root(struct mail_thread_context *ctx, struct node *node)
{
	i_assert(node->next == NULL);

	node->next = ctx->root_nodes;
	ctx->root_nodes = node;
}

static struct node *create_node(struct mail_thread_context *ctx,
				const char *msgid)
{
	struct node *node;

	node = p_new(ctx->pool, struct node, 1);
	node->msgid = p_strdup(ctx->str_pool, msgid);

	hash_insert(ctx->msgid_hash, node->msgid, node);
	return node;
}

static struct node *create_invalid_node(struct mail_thread_context *ctx,
					unsigned int id)
{
	struct node *node;

	node = p_new(ctx->pool, struct node, 1);
	node->id = id;
	return node;
}

static void update_message_id(struct mail_thread_context *ctx,
			      const char *msgid, unsigned int id)
{
	struct node *node;

	if (msgid == NULL) {
		add_root(ctx, create_invalid_node(ctx, id));
		return;
	}

	node = hash_lookup(ctx->msgid_hash, msgid);
	if (node == NULL) {
		/* first time we see this message */
		node = create_node(ctx, msgid);
		node->id = id;
		return;
	}

	if (node->id == 0) {
		/* seen before in references */
		node->id = id;
	} else {
		/* duplicate -> invalidate all of them.
		   the message-id stays and acts like a dummy node. */
		if (node->id != UINT_MAX) {
			add_root(ctx, create_invalid_node(ctx, node->id));
			node->id = UINT_MAX;
		}

		add_root(ctx, create_invalid_node(ctx, id));
	}
}

static int get_untokenized_msgid(const char **msgid_p, string_t *msgid)
{
	static const enum message_token stop_tokens[] = { '>', TOKEN_LAST };
	struct message_tokenizer *tok;
	int valid_end;

	tok = message_tokenize_init(*msgid_p, (size_t)-1, NULL, NULL);
	message_tokenize_dot_token(tok, FALSE); /* just a minor speedup */

	message_tokenize_get_string(tok, msgid, NULL, stop_tokens);
	valid_end = message_tokenize_get(tok) == '>';

	*msgid_p += message_tokenize_get_parse_position(tok);
	message_tokenize_deinit(tok);

	if (valid_end) {
		if (strchr(str_c(msgid), '@') != NULL) {
			/* <xx@xx> - valid message ID found */
			return TRUE;
		}
	}

	return FALSE;
}

static const char *get_msgid(const char **msgid_p)
{
	const char *msgid = *msgid_p;
	const char *p;
	string_t *str = NULL;
	int found_at;

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
			if ((unsigned char)*p >= '0') /* matches most */
				continue;

			if (*p == '@')
				found_at = TRUE;
			if (*p == '>' || *p == '"' || *p == '(' ||
			    *p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
				break;

			if (*p == '\0') {
				*msgid_p = p;
				return NULL;
			}
		}

		if (*p == '>') {
			*msgid_p = p+1;
			if (found_at)
				return t_strdup_until(msgid, p-1);
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

static void unlink_child(struct node *child)
{
	struct node **node;

        node = &child->parent->first_child;
	for (; *node != NULL; node = &(*node)->next) {
		if (*node == child) {
			*node = child->next;
			break;
		}
	}

	child->parent = NULL;
}

static int find_child(struct node *node, struct node *child)
{
	do {
		if (node == child)
			return TRUE;

		if (node->first_child != NULL) {
			if (find_child(node->first_child, child))
				return TRUE;
		}

		node = node->next;
	} while (node != NULL);

	return FALSE;
}

static void link_message(struct mail_thread_context *ctx,
			 const char *parent_msgid, const char *child_msgid,
			 int replace)
{
	struct node *parent, *child, **node;

	child = hash_lookup(ctx->msgid_hash, child_msgid);
	if (child == NULL)
		child = create_node(ctx, child_msgid);

	if (child->parent != NULL && !replace) {
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

	if (find_child(child, parent)) {
		/* this would create a loop, not allowed */
		return;
	}

	if (child->parent != NULL)
		unlink_child(child);

	/* link them */
	child->parent = parent;

	node = &parent->first_child;
	while (*node != NULL)
		node = &(*node)->next;
	*node = child;
}

static int link_references(struct mail_thread_context *ctx,
			   const char *msgid, const char *references)
{
	const char *parent_id, *child_id;

	parent_id = get_msgid(&references);
	if (parent_id == NULL)
		return FALSE;

	while ((child_id = get_msgid(&references)) != NULL) {
		link_message(ctx, parent_id, child_id, FALSE);
		parent_id = child_id;
	}

	if (msgid != NULL) {
		/* link the last message to us */
		link_message(ctx, msgid, parent_id, TRUE);
	}

	return TRUE;
}

void mail_thread_input(struct mail_thread_context *ctx, unsigned int id,
		       const char *message_id, const char *in_reply_to,
		       const char *references)
{
	/* (1) link message ids */
	const char *msgid, *refid;

	i_assert(id > 0 && id < UINT_MAX);

	/* get our message ID */
	msgid = get_msgid(&message_id);
	update_message_id(ctx, msgid, id);

	/* link references */
	if (!link_references(ctx, msgid, references) && msgid != NULL) {
		refid = get_msgid(&in_reply_to);
		if (refid != NULL)
			link_message(ctx, msgid, refid, TRUE);
		else {
			/* no references, make sure it's not linked */
			struct node *node;

			node = hash_lookup(ctx->msgid_hash, msgid);
			if (node != NULL)
				unlink_child(node);
		}
	}
}

static struct node *find_last_child(struct node *node)
{
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

static void prune_dummy_messages(struct node **node_p)
{
	struct node **a;

	a = node_p;
	while (*node_p != NULL) {
		if ((*node_p)->first_child != NULL)
			prune_dummy_messages(&(*node_p)->first_child);

		if (NODE_IS_DUMMY(*node_p)) {
			if ((*node_p)->first_child == NULL) {
				/* no children -> delete */
				*node_p = (*node_p)->next;
				continue;
			} else if ((*node_p)->parent != NULL ||
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

static int node_cmp(struct mail_thread_context *ctx,
		    struct node *a, struct node *b)
{
	time_t date_a, date_b;

	t_push();
	date_a = ctx->callbacks->input_time(MAIL_SORT_DATE,
					    a->id, ctx->callback_context);
	date_b = ctx->callbacks->input_time(MAIL_SORT_DATE,
					    b->id, ctx->callback_context);
	ctx->callbacks->input_reset(ctx->callback_context);
	t_pop();

	if (date_a == date_b || date_a == 0 || date_b == 0)
		return a->id < b->id ? -1 : 1;
	else
		return date_a < date_b ? -1 : 1;
}

static struct node *
sort_nodes(struct mail_thread_context *ctx, struct node *list)
{
	struct node *p, *q, *e, *tail;
	size_t insize, nmerges, psize, qsize, i;

	i_assert(list != NULL);

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
				} else if (node_cmp(ctx, p, q) <= 0) {
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

static void add_base_subject(struct mail_thread_context *ctx,
			     const char *subject, struct root_data *root)
{
	struct root_data *hash_root;
	char *hash_subject;
	void *key, *value;
	int is_reply_or_forward;

	if (subject == NULL)
		return;

	subject = imap_get_base_subject_cased(data_stack_pool, subject,
					      &is_reply_or_forward);
	if (*subject == '\0')
		return;

	if (!hash_lookup_full(ctx->subject_hash, subject, &key, &value)) {
		hash_subject = p_strdup(ctx->str_pool, subject);
		hash_root = root;
		hash_insert(ctx->subject_hash, hash_subject, root);
	} else {
		hash_subject = key;
		hash_root = value;

		if (!NODE_IS_DUMMY(hash_root->node) &&
		    (NODE_IS_DUMMY(root->node) ||
		     (hash_root->reply && !is_reply_or_forward)))
			hash_update(ctx->subject_hash, hash_subject, root);
	}

	root->base_subject = hash_subject;
	root->reply = is_reply_or_forward;
}

static void gather_root_data(struct mail_thread_context *ctx)
{
	const struct mail_sort_callbacks *cb;
	struct node *node;
	size_t i, count;
	unsigned int id;

	/* get the number of root nodes */
	for (count = 0, node = ctx->root_nodes; node != NULL; node = node->next)
		count++;
	ctx->root_count = count;

	ctx->root_data = p_new(ctx->pool, struct root_data, ctx->root_count);
	cb = ctx->callbacks;

	ctx->subject_hash =
		hash_create(default_pool, ctx->root_count * 2, str_hash,
			    (HashCompareFunc)strcmp);

	node = ctx->root_nodes;
	for (i = 0; i < ctx->root_count; i++, node = node->next) {
		ctx->root_data[i].node = node;

		if (!NODE_IS_DUMMY(node))
			id = node->id;
		else {
			/* sort children, use the first one's id */
			node->first_child = sort_nodes(ctx, node->first_child);
			id = node->first_child->id;
		}

		t_push();

		ctx->root_data[i].sort_id = id;
		ctx->root_data[i].sent_date =
			cb->input_time(MAIL_SORT_DATE, id,
				       ctx->callback_context);

		add_base_subject(ctx, cb->input_str(MAIL_SORT_SUBJECT, id,
						    ctx->callback_context),
				 &ctx->root_data[i]);

		cb->input_reset(ctx->callback_context);
		t_pop();
	}

	i_assert(node == NULL);
}

static void merge_subject_threads(struct mail_thread_context *ctx)
{
        struct root_data *root, *hash_root;
	size_t i;

	for (i = 0; i < ctx->root_count; i++) {
		root = &ctx->root_data[i];

		/* (ii) If the thread subject is empty, skip this message. */
		if (root->base_subject == NULL)
			continue;

		/* (iii) Lookup the message associated with this thread
		   subject in the subject table. */
		hash_root = hash_lookup(ctx->subject_hash, root->base_subject);
		i_assert(hash_root != NULL);

		/* (iv) If the message in the subject table is the current
		   message, skip this message. */
		if (hash_root == root)
			continue;

		/* Otherwise, merge the current message with the one in the
		   subject table using the following rules: */

		if (NODE_IS_DUMMY(root->node) &&
		    NODE_IS_DUMMY(hash_root->node)) {
			/* If both messages are dummies, append the current
			   message's children to the children of the message in
			   the subject table (the children of both messages
			   become siblings), and then delete the current
			   message. */
			find_last_child(hash_root->node)->next =
				root->node->first_child;
			root->node = NULL;
		} else if (NODE_IS_DUMMY(hash_root->node) ||
			   (root->reply && !hash_root->reply)) {
			/* If the message in the subject table is a dummy
			   and the current message is not, make the current
			   message a child of the message in the subject table
			   (a sibling of its children).

			   If the current message is a reply or forward and
			   the message in the subject table is not, make the
			   current message a child of the message in the
			   subject table (a sibling of its children). */
			root->node->parent = hash_root->node;
			root->node->next = hash_root->node->first_child;
			hash_root->node->first_child = root->node;
			root->node = NULL;
		} else {
			/* Otherwise, create a new dummy message and make both
			   the current message and the message in the subject
			   table children of the dummy.  Then replace the
			   message in the subject table with the dummy
			   message. */
			struct node *node;

			node = p_new(ctx->pool, struct node, 1);
			node->first_child = root->node;

			root->node->next = hash_root->node;
			root->node->parent = node;

			hash_root->node->next = NULL;
			hash_root->node->parent = node;

			hash_root->node = node;
			hash_root->reply = FALSE;
			root->node = NULL;
		}
	}
}

static int send_nodes(struct mail_thread_context *ctx,
		      string_t *str, struct node *node)
{
	/* sort the siblings first */
	node = sort_nodes(ctx, node);

	while (node != NULL) {
		if (str_len(str) + MAX_INT_STRLEN + 3 >= OUTPUT_BUF_SIZE) {
			/* string getting full, flush it */
			if (!o_stream_send(ctx->output,
					   str_data(str), str_len(str)))
				return FALSE;
			str_truncate(str, 0);
		}

		if (node->first_child == NULL)
			str_printfa(str, "(%u)", node->id);
		else {
			str_printfa(str, "(%u ", node->id);
			send_nodes(ctx, str, node->first_child);
			str_append_c(str, ')');
		}

		node = node->next;
	}
	return TRUE;
}

static void send_roots(struct mail_thread_context *ctx)
{
	struct root_data *root;
	string_t *str;
	size_t i;

	str = t_str_new(OUTPUT_BUF_SIZE);
	str_append_c(str, ' ');

	for (i = 0; i < ctx->root_count; i++) {
		root = &ctx->root_data[i];

		if (root->node == NULL)
			continue;

		if (str_len(str) + MAX_INT_STRLEN + 3 >= OUTPUT_BUF_SIZE) {
			/* string getting full, flush it */
			if (!o_stream_send(ctx->output,
					   str_data(str), str_len(str)))
				return;
			str_truncate(str, 0);
		}

		str_append_c(str, '(');
		if (!NODE_IS_DUMMY(root->node))
			str_printfa(str, "%u", root->node->id);

		if (root->node->first_child != NULL) {
			if (!NODE_IS_DUMMY(root->node))
				str_append_c(str, ' ');

			if (!send_nodes(ctx, str, root->node->first_child))
				return;
		}

		str_append_c(str, ')');
	}

	(void)o_stream_send(ctx->output, str_data(str), str_len(str));
}

static int root_data_cmp(const void *p1, const void *p2)
{
	const struct root_data *d1 = p1;
	const struct root_data *d2 = p2;

	if (d1->sent_date == d2->sent_date ||
	    d1->sent_date == 0 || d2->sent_date == 0)
		return d1->sort_id < d2->sort_id ? -1 :
			d1->sort_id > d2->sort_id ? 1 : 0;
	else
		return d1->sent_date < d2->sent_date ? -1 : 1;
}

static void save_root_cb(void *key __attr_unused__, void *value, void *context)
{
	struct mail_thread_context *ctx = context;
	struct node *node = value;

	if (node->parent == NULL)
		add_root(ctx, node);
}

void mail_thread_finish(struct mail_thread_context *ctx)
{
	if (ctx->root_nodes == NULL) {
		/* no messages */
		return;
	}

	/* (2) save root nodes and drop the msgid_hash */
	hash_foreach(ctx->msgid_hash, save_root_cb, ctx);
	hash_destroy(ctx->msgid_hash);
	ctx->msgid_hash = NULL;

	/* drop the memory allocated for message-IDs, reuse their memory
	   for base subjects */
	p_clear(ctx->str_pool);

	/* (3) */
	prune_dummy_messages(&ctx->root_nodes);

	/* get the message dates and subjects here and save them to an array.
	   this probably gets us better caching than fetching them separately.
	   for dummy nodes sort their children as required by (4).
	   subjects are stored into hash as required by (5.B). */
	gather_root_data(ctx);

	/* (5.C) Merge threads with the same thread subject. */
	merge_subject_threads(ctx);

	/* (4) sort roots. doing it before subject merging would break
	   subject_hash, and I can't see how doing it later would change
	   anything */
	qsort(ctx->root_data, ctx->root_count,
	      sizeof(struct root_data), root_data_cmp);

	/* (6) Sort and send replies */
	t_push();
	send_roots(ctx);
	t_pop();

        mail_thread_deinit(ctx);
}
