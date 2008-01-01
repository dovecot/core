/* Copyright (c) 2006-2008 Dovecot authors, see the included COPYING file */

/* The idea in here is that we use a 32bit integer (sort ID) which specifies
   the sort order for primary sort condition. With fixed size fields (time,
   size) we use the field itself as the sort ID. They can be looked up fast
   enough from cache file, so we don't add them to index file.

   Strings can't be used as sort IDs directly. The way they're currently
   handled is that the whole 32bit integer space is used for them and whenever
   adding a string, the available space is halved and the new ID is added in
   the middle. For example if we add one mail the first time, it gets ID
   2^31. If we then add two mails which are sorted before the first one, they
   get IDs 2^31/3 and 2^31/3*2. Once we run out of the available space between
   IDs, a large amount of the IDs are renumbered.
*/

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "str.h"
#include "unichar.h"
#include "message-address.h"
#include "imap-base-subject.h"
#include "index-storage.h"
#include "index-sort.h"

#include <stdlib.h>

#define RENUMBER_SPACE 100

struct mail_sort_node {
	uint32_t seq;
	uint32_t sort_id;
};
ARRAY_DEFINE_TYPE(mail_sort_node, struct mail_sort_node);

struct mail_search_sort_program {
	struct mailbox_transaction_context *t;
	enum mail_sort_type sort_program[MAX_SORT_PROGRAM_SIZE];
	struct mail *temp_mail;

	ARRAY_TYPE(mail_sort_node) nodes, all_nodes;
	const struct mail_sort_node *nodes_ptr;
	unsigned int nodes_count, iter_idx;

	uint32_t ext_id;
	unsigned int first_missing_sort_id_idx;
	uint32_t (*get_sort_id)(struct mail *);

	unsigned int reverse:1;
	unsigned int sort_ids_added:1;
	unsigned int missing_sort_ids:1;
};

struct sort_cmp_context {
	struct mail_search_sort_program *program;
	struct mail *mail;
};

static struct sort_cmp_context static_node_cmp_context;

static uint32_t sort_get_arrival(struct mail *mail);
static uint32_t sort_get_date(struct mail *mail);
static uint32_t sort_get_size(struct mail *mail);

struct mail_search_sort_program *
index_sort_program_init(struct mailbox_transaction_context *t,
			const enum mail_sort_type *sort_program)
{
	struct index_mailbox *ibox = (struct index_mailbox *)t->box;
	struct mail_search_sort_program *program;
	const char *name = NULL;
	unsigned int i;

	if (sort_program == NULL || sort_program[0] == MAIL_SORT_END)
		return NULL;

	/* we support internal sorting by the primary condition */
	program = i_new(struct mail_search_sort_program, 1);
	program->t = t;
	program->temp_mail = mail_alloc(t, 0, NULL);
	i_array_init(&program->nodes, 64);

	/* primary reversion isn't stored to sort_program. we handle it by
	   iterating backwards at the end. */
	program->reverse = (sort_program[0] & MAIL_SORT_FLAG_REVERSE) != 0;
	program->sort_program[0] = sort_program[0] & ~MAIL_SORT_FLAG_REVERSE;
	for (i = 1; i < MAX_SORT_PROGRAM_SIZE; i++) {
		program->sort_program[i] = sort_program[i];
		if (sort_program[i] == MAIL_SORT_END)
			break;
	}
	if (i == MAX_SORT_PROGRAM_SIZE)
		i_panic("index_sort_program_init(): Invalid sort program");

	switch (program->sort_program[0] & MAIL_SORT_MASK) {
	case MAIL_SORT_ARRIVAL:
		program->get_sort_id = sort_get_arrival;
		break;
	case MAIL_SORT_DATE:
		program->get_sort_id = sort_get_date;
		break;
	case MAIL_SORT_SIZE:
		program->get_sort_id = sort_get_size;
		break;
	case MAIL_SORT_CC:
		name = "sort-c";
		break;
	case MAIL_SORT_FROM:
		name = "sort-f";
		break;
	case MAIL_SORT_SUBJECT:
		name = "sort-s";
		break;
	case MAIL_SORT_TO:
		name = "sort-t";
		break;
	default:
		i_unreached();
	}
	program->ext_id = name == NULL ? (uint32_t)-1 :
		mail_index_ext_register(ibox->index, name, 0,
					sizeof(uint32_t), sizeof(uint32_t));
	return program;
}

void index_sort_program_deinit(struct mail_search_sort_program **_program)
{
	struct mail_search_sort_program *program = *_program;

	*_program = NULL;
	mail_free(&program->temp_mail);
	array_free(&program->nodes);
	i_free(program);
}

static const char *get_first_mailbox(struct mail *mail, const char *header)
{
	struct message_address *addr;
	const char *str;

	if (mail_get_first_header_utf8(mail, header, &str) <= 0)
		return "";

	addr = message_address_parse(pool_datastack_create(),
				     (const unsigned char *)str,
				     strlen(str), 1, TRUE);
	return addr != NULL ? addr->mailbox : "";
}

static void
sort_header_get(string_t *dest, enum mail_sort_type sort_type,
		struct mail *mail, uint32_t seq)
{
	const char *str;

	mail_set_seq(mail, seq);
	switch (sort_type & MAIL_SORT_MASK) {
	case MAIL_SORT_SUBJECT:
		if (mail_get_first_header(mail, "Subject", &str) <= 0)
			return;
		str = imap_get_base_subject_cased(pool_datastack_create(),
						  str, NULL);
		str_append(dest, str);
		return;
	case MAIL_SORT_CC:
		str = get_first_mailbox(mail, "Cc");
		break;
	case MAIL_SORT_FROM:
		str = get_first_mailbox(mail, "From");
		break;
	case MAIL_SORT_TO:
		str = get_first_mailbox(mail, "To");
		break;
	default:
		i_unreached();
	}

	(void)uni_utf8_to_decomposed_titlecase(str, (size_t)-1, dest);
}

static uint32_t sort_get_arrival(struct mail *mail)
{
	time_t t;

	if (mail_get_received_date(mail, &t) < 0)
		t = 0;

	i_assert(t != (time_t)-1);
	/* FIXME: truncation isn't good.. */
	return t <= 0 ? 1 :
		((uint64_t)t >= (uint32_t)-1 ? (uint32_t)-1 : (uint32_t)t + 1);
}

static uint32_t sort_get_date(struct mail *mail)
{
	time_t t;

	if (mail_get_date(mail, &t, NULL) < 0)
		t = 0;
	if (t == 0) {
		if (mail_get_received_date(mail, &t) < 0)
			return 1;
	}
	i_assert(t != (time_t)-1);
	/* FIXME: truncation isn't good.. */
	return t <= 0 ? 1 :
		((uint64_t)t >= (uint32_t)-1 ? (uint32_t)-1 : (uint32_t)t + 1);
}

static uint32_t sort_get_size(struct mail *mail)
{
	uoff_t size;

	if (mail_get_virtual_size(mail, &size) < 0)
		return 1;

	/* FIXME: elsewhere we support 64bit message sizes, but here
	   we support only 32bit sizes.. It's a bit too much trouble
	   to support 64bit here currently, so until such messages
	   actually start showing up somewhere, 32bit is enough */
	i_assert(size < (uint32_t)-1);
	return size + 1;
}

static int sort_node_cmp_type(struct sort_cmp_context *ctx,
			      const enum mail_sort_type *sort_program,
			      const struct mail_sort_node *n1,
			      const struct mail_sort_node *n2)
{
	enum mail_sort_type sort_type;
	uint32_t time1, time2, size1, size2;
	int ret = 0;

	sort_type = *sort_program & MAIL_SORT_MASK;
	switch (sort_type) {
	case MAIL_SORT_CC:
	case MAIL_SORT_FROM:
	case MAIL_SORT_TO:
	case MAIL_SORT_SUBJECT:
		T_FRAME_BEGIN {
			string_t *str1, *str2;

			str1 = t_str_new(256);
			str2 = t_str_new(256);
			sort_header_get(str1, sort_type, ctx->mail, n1->seq);
			sort_header_get(str2, sort_type, ctx->mail, n2->seq);

			ret = strcmp(str_c(str1), str_c(str2));
		} T_FRAME_END;
		break;
	case MAIL_SORT_ARRIVAL:
		mail_set_seq(ctx->mail, n1->seq);
		time1 = sort_get_arrival(ctx->mail);

		mail_set_seq(ctx->mail, n2->seq);
		time2 = sort_get_arrival(ctx->mail);

		ret = time1 < time2 ? -1 :
			(time1 > time2 ? 1 : 0);
		break;
	case MAIL_SORT_DATE:
		mail_set_seq(ctx->mail, n1->seq);
		time1 = sort_get_date(ctx->mail);

		mail_set_seq(ctx->mail, n2->seq);
		time2 = sort_get_date(ctx->mail);

		ret = time1 < time2 ? -1 :
			(time1 > time2 ? 1 : 0);
		break;
	case MAIL_SORT_SIZE:
		mail_set_seq(ctx->mail, n1->seq);
		size1 = sort_get_size(ctx->mail);

		mail_set_seq(ctx->mail, n2->seq);
		size2 = sort_get_size(ctx->mail);

		ret = size1 < size2 ? -1 :
			(size1 > size2 ? 1 : 0);
		break;
	case MAIL_SORT_END:
		return n1->seq < n2->seq ? -1 :
			(n1->seq > n2->seq ? 1 : 0);
	case MAIL_SORT_MASK:
	case MAIL_SORT_FLAG_REVERSE:
		i_unreached();
	}

	if (ret == 0)
		return sort_node_cmp_type(ctx, sort_program+1, n1, n2);

	/* primary reversion isn't in sort_program */
	if ((*sort_program & MAIL_SORT_FLAG_REVERSE) != 0)
		ret = ret < 0 ? 1 : -1;
	return ret;
}

static int sort_node_cmp(const void *p1, const void *p2)
{
	struct sort_cmp_context *ctx = &static_node_cmp_context;
	const struct mail_sort_node *n1 = p1, *n2 = p2;

	if (n1->sort_id < n2->sort_id)
		return -1;
	if (n1->sort_id > n2->sort_id)
		return 1;

	return sort_node_cmp_type(ctx, ctx->program->sort_program + 1, n1, n2);
}

static int sort_node_cmp_nozero_sort_id(const void *p1, const void *p2)
{
	struct sort_cmp_context *ctx = &static_node_cmp_context;
	const struct mail_sort_node *n1 = p1, *n2 = p2;
	const enum mail_sort_type *sort_program;

	/* Use sort IDs only if both have them */
	if (n1->sort_id != 0 && n2->sort_id != 0) {
		if (n1->sort_id < n2->sort_id)
			return -1;
		if (n1->sort_id > n2->sort_id)
			return 1;
		sort_program = ctx->program->sort_program + 1;
	} else {
		sort_program = ctx->program->sort_program;
	}

	return sort_node_cmp_type(ctx, sort_program, n1, n2);
}

static void
index_sort_add_ids_range(struct mail_search_sort_program *program,
			 struct mail *mail, unsigned int left_idx,
			 unsigned int right_idx)
{
	struct mail_sort_node *nodes;
	unsigned int i, count, rightmost_idx;
	uint32_t left_sort_id, right_sort_id;
	string_t *right_str, *left_str, *str;
	unsigned int skip;
	bool have_right_sort_id = FALSE;

	nodes = array_get_modifiable(&program->all_nodes, &count);
	rightmost_idx = count - 1;

	/* get the sort IDs from left and right */
	i_assert(left_idx == 0 || nodes[left_idx].sort_id != 0);
	i_assert(right_idx == rightmost_idx || nodes[right_idx].sort_id != 0);
	left_sort_id = nodes[left_idx].sort_id == 0 ? 1 :
		nodes[left_idx].sort_id;
	right_sort_id = nodes[right_idx].sort_id == 0 ? (uint32_t)-1 :
		nodes[right_idx].sort_id;

	while ((right_sort_id - left_sort_id) / (right_idx-left_idx + 2) == 0) {
		/* we most likely don't have enough space. we have to
		   renumber some of the existing sort IDs. do this by
		   widening the area we're giving sort IDs. */
		if (left_idx > 0) {
			left_idx--;
			left_sort_id = nodes[left_idx].sort_id;
			i_assert(left_sort_id != 0);
		}

		while (right_idx < rightmost_idx) {
			if (nodes[++right_idx].sort_id != 0)
				break;
		}
		right_sort_id = right_idx == rightmost_idx ? (uint32_t)-1 :
			nodes[right_idx].sort_id;
		i_assert(left_sort_id < right_sort_id);
	}

	left_str = t_str_new(256);
	right_str = t_str_new(256);
	if (nodes[left_idx].sort_id != 0) {
		sort_header_get(left_str, program->sort_program[0], mail,
				nodes[left_idx].seq);
		left_idx++;
	}
	if (nodes[right_idx].sort_id != 0) {
		have_right_sort_id = TRUE;
		sort_header_get(right_str, program->sort_program[0], mail,
				nodes[right_idx].seq);
		right_idx--;
	}

	/* give (new) sort IDs to all nodes in left_idx..right_idx range.
	   divide the available space so that each messagets an equal sized
	   share. some messages' sort strings may be equivalent, so give them
	   the same sort IDs. */
	str = str_new(default_pool, 256);
	for (i = left_idx; i <= right_idx; i++) {
		T_FRAME(
			sort_header_get(str, program->sort_program[0], mail,
					nodes[i].seq);
		);

		if (left_idx != 0 && str_equals(str, left_str))
			nodes[i].sort_id = left_sort_id;
		else if (have_right_sort_id && str_equals(str, right_str)) {
			/* the rest of the sort IDs should be the same */
			nodes[i].sort_id = right_sort_id;
		} else {
			/* divide the available space equally. leave the same
			   sized space also between the first and the last
			   messages */
			skip = (right_sort_id - left_sort_id) /
				(right_idx - i + 2);
			i_assert(skip > 0);
			left_sort_id += skip;
			nodes[i].sort_id = left_sort_id;

			str_truncate(left_str, 0);
			str_append_str(left_str, str);
		}
	}
	str_free(&str);
}

static void
index_sort_add_ids(struct mail_search_sort_program *program, struct mail *mail)
{
	const struct mail_sort_node *nodes;
	unsigned int i, left_idx = 0, right_idx, count;

	nodes = array_get(&program->all_nodes, &count);
	for (i = 0; i < count; i++) {
		if (nodes[i].sort_id != 0)
			continue;

		/* get the range for all sort_id=0 nodes. include the nodes
		   left and right of the range as well */
		for (right_idx = i + 1; right_idx < count; right_idx++) {
			if (nodes[right_idx].sort_id != 0)
				break;
		}
		if (right_idx == count)
			right_idx--;
		left_idx = i == 0 ? 0 : i - 1;
		T_FRAME(
			index_sort_add_ids_range(program, mail,
						 left_idx, right_idx);
		);
	}
}

static void
index_sort_add_string_sort_ids(struct mail_search_sort_program *program,
			       uint32_t last_seq)
{
	ARRAY_TYPE(mail_sort_node) seq_nodes_arr;
	struct mail_sort_node *nodes, node, *seq_nodes;
	unsigned int i, count, count2;

	/* insert missing nodes */
	memset(&node, 0, sizeof(node));
	node.seq = array_count(&program->all_nodes) + 1;
	for (; node.seq <= last_seq; node.seq++)
		array_append(&program->all_nodes, &node, 1);

	/* sort everything. use sort_ids whenever possible */
	nodes = array_get_modifiable(&program->all_nodes, &count);
	i_assert(count == last_seq);
	qsort(nodes, count, sizeof(struct mail_sort_node),
	      sort_node_cmp_nozero_sort_id);

	/* we can now build the sort_ids */
	index_sort_add_ids(program, static_node_cmp_context.mail);

	/* @UNSAFE: and finally get the range sorted back by sequence */
	i_array_init(&seq_nodes_arr, count);
	(void)array_idx_modifiable(&seq_nodes_arr, count-1);
	seq_nodes = array_get_modifiable(&seq_nodes_arr, &count2);
	i_assert(count2 == count);
	for (i = 0; i < count; i++)
		seq_nodes[nodes[i].seq-1] = nodes[i];

	array_free(&program->all_nodes);
	program->all_nodes = seq_nodes_arr;
}

static void index_sort_build(struct mail_search_sort_program *program)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)program->t;
	struct mail_sort_node node, *all_nodes, *nodes;
	const void *data;
	uint32_t last_seq;
	unsigned int seq, i, count, count2;

	/* add messages that have sort_ids. they're always at the beginning
	   of the mailbox. */
	memset(&node, 0, sizeof(node));
	last_seq = mail_index_view_get_messages_count(t->ibox->view);
	i_array_init(&program->all_nodes, last_seq);
	for (seq = 1; seq <= last_seq; seq++) {
		node.seq = seq;

		mail_index_lookup_ext(t->ibox->view, seq, program->ext_id,
				      &data, NULL);
		node.sort_id = data == NULL ? 0 : *(const uint32_t *)data;
		if (node.sort_id == 0) {
			/* the rest don't have sort_ids either */
			break;
		}
		array_append(&program->all_nodes, &node, 1);
	}
	i_assert(seq <= last_seq);
	index_sort_add_string_sort_ids(program, last_seq);

	/* add the missing sort IDs to index */
	all_nodes = array_get_modifiable(&program->all_nodes, &count);
	for (; seq <= count; seq++) {
		i_assert(all_nodes[seq-1].sort_id != 0);
		mail_index_update_ext(t->trans, seq, program->ext_id,
				      &all_nodes[seq-1].sort_id, NULL);
	}

	/* set missing sort_ids to wanted nodes */
	nodes = array_get_modifiable(&program->nodes, &count2);
	for (i = program->first_missing_sort_id_idx; i < count2; i++)
		nodes[i].sort_id = all_nodes[nodes[i].seq-1].sort_id;
	array_free(&program->all_nodes);
}

void index_sort_list_add(struct mail_search_sort_program *program,
			 struct mail *mail)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)program->t;
	const void *data;
	struct mail_sort_node node;

	i_assert(mail->transaction == program->t);

	node.seq = mail->seq;
	if (program->ext_id == (uint32_t)-1) {
		/* no indexing for this field */
		node.sort_id = program->get_sort_id(mail);
		array_append(&program->nodes, &node, 1);
		return;
	}

	mail_index_lookup_ext(t->trans_view, mail->seq,
			      program->ext_id, &data, NULL);
	node.sort_id = data == NULL ? 0 : *(const uint32_t *)data;
	if (node.sort_id == 0 && !program->missing_sort_ids) {
		program->missing_sort_ids = TRUE;
		program->first_missing_sort_id_idx =
			array_count(&program->nodes);
	}
	array_append(&program->nodes, &node, 1);
}

void index_sort_list_finish(struct mail_search_sort_program *program)
{
	struct mail_sort_node *nodes;

	memset(&static_node_cmp_context, 0, sizeof(static_node_cmp_context));
	static_node_cmp_context.program = program;
	static_node_cmp_context.mail = program->temp_mail;

	if (program->missing_sort_ids) {
		i_assert(program->ext_id != (uint32_t)-1);
		index_sort_build(program);
	}

	nodes = array_get_modifiable(&program->nodes, &program->nodes_count);
	qsort(nodes, program->nodes_count, sizeof(struct mail_sort_node),
	      sort_node_cmp);

	program->nodes_ptr = nodes;
	if (program->reverse)
		program->iter_idx = program->nodes_count;
}

bool index_sort_list_next(struct mail_search_sort_program *program,
			  struct mail *mail)
{
	const struct mail_sort_node *node;

	if (!program->reverse) {
		if (program->iter_idx == program->nodes_count)
			return FALSE;

		node = &program->nodes_ptr[program->iter_idx++];
	} else {
		if (program->iter_idx == 0)
			return FALSE;

		node = &program->nodes_ptr[--program->iter_idx];
	}
	mail_set_seq(mail, node->seq);
	return TRUE;
}
