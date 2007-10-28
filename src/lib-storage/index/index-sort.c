/* Copyright (c) 2006-2007 Dovecot authors, see the included COPYING file */

/* The idea in here is that for each used primary sort condition there's
   a 32bit integer in the index file which specifies the sort order. So when
   sorting we simply look up the sort IDs and sort the messages by them.

   Sort IDs are allocated in two ways:

   1) Time and size fields can be directly used as sort IDs, so we simply
   use them directly as the missing sort IDs.

   2) Strings can't be used as sort IDs directly. The way they're currently
   handled is that the whole 32bit integer space is used for them and whenever
   adding a string, the available space is halved and the new ID is added in
   the middle. For example if we add one mail the first time, it gets ID
   2^31. If we then add two mails which are sorted before the first one, they
   get IDs 2^31/3 and 2^31/3*2. Once we run out of the available space between
   IDs, a large amount of the IDs are renumbered.

   We try to avoid looking at mails' contents as much as possible. For case 1)
   IDs it's simple because we need to get only the new mails' sort fields once
   and use them as sort IDs. For case 2) we'll have to start looking at the
   strings from older mails as well. To minimize this, we first sort the
   existing sort IDs. After that we start inserting the new mails into the
   sorted array by looking the position using binary search. This minimizes
   the number of lookups we have to do for the old mails. Usually only a few
   mails have been added, so this should be faster than other sort methods.
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
	const char *primary_sort_header;
	struct mail *temp_mail;

	ARRAY_TYPE(mail_sort_node) nodes;
	const struct mail_sort_node *nodes_ptr;
	unsigned int nodes_count, iter_idx;

	ARRAY_TYPE(mail_sort_node) all_nodes;

	uint32_t ext_id;
	uint32_t prev_seq, last_sorted_seq;

	unsigned int reverse:1;
	unsigned int skipped_mails:1;
	unsigned int sort_ids_added:1;
};

struct sort_cmp_context {
	struct mail_search_sort_program *program;
	struct mail *mail;

	uint32_t cache_seq;
	enum mail_sort_type cache_type;
	uint32_t cache_value;
	const char *cache_str;
};

static struct sort_cmp_context static_node_cmp_context;

struct mail_search_sort_program *
index_sort_program_init(struct mailbox_transaction_context *t,
			const enum mail_sort_type *sort_program)
{
	struct index_mailbox *ibox = (struct index_mailbox *)t->box;
	struct mail_search_sort_program *program;
	const char *name;
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
		name = "rdate";
		break;
	case MAIL_SORT_CC:
		name = "sort-c";
		program->primary_sort_header = "Cc";
		break;
	case MAIL_SORT_DATE:
		name = "date";
		break;
	case MAIL_SORT_FROM:
		name = "sort-f";
		program->primary_sort_header = "From";
		break;
	case MAIL_SORT_SIZE:
		name = "size";
		break;
	case MAIL_SORT_SUBJECT:
		name = "sort-s";
		program->primary_sort_header = "Subject";
		break;
	case MAIL_SORT_TO:
		name = "sort-t";
		program->primary_sort_header = "To";
		break;
	default:
		i_unreached();
	}
	program->ext_id =
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

static const char *
sort_header_get(enum mail_sort_type sort_type, struct mail *mail, uint32_t seq)
{
	const char *str;
	string_t *buf;

	mail_set_seq(mail, seq);
	switch (sort_type & MAIL_SORT_MASK) {
	case MAIL_SORT_SUBJECT:
		if (mail_get_first_header(mail, "Subject", &str) <= 0)
			return "";
		return imap_get_base_subject_cased(pool_datastack_create(),
						   str, NULL);
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

	buf = t_str_new(128);
	(void)uni_utf8_to_decomposed_titlecase(str, (size_t)-1, buf);
	return str_c(buf);
}

static uint32_t sort_get_arrival(struct mail *mail)
{
	time_t t;

	if (mail_get_received_date(mail, &t) < 0)
		t = 0;

	i_assert(t != (time_t)-1);
	/* FIXME: truncation isn't good.. */
	return t <= 0 ? 1 :
		(t >= (uint32_t)-1 ? (uint32_t)-1 : t + 1);
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
		(t >= (uint32_t)-1 ? (uint32_t)-1 : t + 1);
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
	const char *str1, *str2;
	uint32_t time1, time2, size1, size2;
	int ret = 0;

	sort_type = *sort_program & MAIL_SORT_MASK;
	switch (sort_type) {
	case MAIL_SORT_CC:
	case MAIL_SORT_FROM:
	case MAIL_SORT_TO:
	case MAIL_SORT_SUBJECT:
		t_push();
		str1 = n1->seq == ctx->cache_seq &&
			ctx->cache_type == sort_type ? ctx->cache_str :
			sort_header_get(sort_type, ctx->mail, n1->seq);
		str2 = sort_header_get(sort_type, ctx->mail, n2->seq);

		ret = strcmp(str1, str2);
		t_pop();
		break;
	case MAIL_SORT_ARRIVAL:
		if (n1->seq == ctx->cache_seq && ctx->cache_type == sort_type)
			time1 = ctx->cache_value;
		else {
			mail_set_seq(ctx->mail, n1->seq);
			time1 = sort_get_arrival(ctx->mail);
		}

		mail_set_seq(ctx->mail, n2->seq);
		time2 = sort_get_arrival(ctx->mail);

		ret = time1 < time2 ? -1 :
			(time1 > time2 ? 1 : 0);
		break;
	case MAIL_SORT_DATE:
		if (n1->seq == ctx->cache_seq && ctx->cache_type == sort_type)
			time1 = ctx->cache_value;
		else {
			mail_set_seq(ctx->mail, n1->seq);
			time1 = sort_get_date(ctx->mail);
		}

		mail_set_seq(ctx->mail, n2->seq);
		time2 = sort_get_date(ctx->mail);

		ret = time1 < time2 ? -1 :
			(time1 > time2 ? 1 : 0);
		break;
	case MAIL_SORT_SIZE:
		if (n1->seq == ctx->cache_seq && ctx->cache_type == sort_type)
			size1 = ctx->cache_value;
		else {
			mail_set_seq(ctx->mail, n1->seq);
			size1 = sort_get_size(ctx->mail);
		}

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

static int sort_node_cmp_no_sort_id(const void *p1, const void *p2)
{
	struct sort_cmp_context *ctx = &static_node_cmp_context;

	return sort_node_cmp_type(ctx, ctx->program->sort_program, p1, p2);
}

static void
index_sort_save_ids(struct mail_search_sort_program *program,
		    uint32_t first_seq)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)program->t;
	const struct mail_sort_node *nodes;
	unsigned int i, count;

	nodes = array_get(&program->all_nodes, &count);
	for (i = 0; i < count; i++) {
		if (nodes[i].seq < first_seq)
			continue;

		i_assert(nodes[i].sort_id != 0);
		mail_index_update_ext(t->trans, nodes[i].seq,
				      program->ext_id, &nodes[i].sort_id, NULL);
	}
}

static int
index_sort_add_ids_range(struct mail_search_sort_program *program,
			 struct mail *mail, unsigned int idx1,
			 unsigned int idx2)
{
	struct mail_sort_node *nodes;
	unsigned int i, count;
	const char *last_str = "";
	uint32_t prev_id = 0, last_id = (uint32_t)-1;
	string_t *prev_str;
	const char *str;
	unsigned int skip;
	int ret = 1;

	t_push();
	nodes = array_get_modifiable(&program->all_nodes, &count);
	if (nodes[idx2].sort_id != 0) {
		i_assert(idx1 != idx2);
		last_id = nodes[idx2].sort_id;

		last_str = sort_header_get(program->sort_program[0], mail,
					   nodes[idx2].seq);
		idx2--;
	}

	prev_str = t_str_new(256);
	if (nodes[idx1].sort_id != 0) {
		prev_id = nodes[idx1].sort_id;

		str_append(prev_str,
			   sort_header_get(program->sort_program[0], mail,
					   nodes[idx1].seq));
		idx1++;
	}

	for (i = idx1; i <= idx2; i++) {
		str = sort_header_get(program->sort_program[0], mail,
				      nodes[i].seq);

		if (i == idx2 && strcmp(str, last_str) == 0)
			nodes[i].sort_id = last_id;
		else if (strcmp(str, str_c(prev_str)) == 0 && prev_id != 0)
			nodes[i].sort_id = prev_id;
		else {
			/* divide the available space so that each message gets
			   an equal sized share. leave the same sized space
			   also between the first and the last messages */
			skip = (last_id - prev_id) / (idx2 - i + 2);
			nodes[i].sort_id = prev_id + skip;
			if (nodes[i].sort_id == prev_id && prev_id != last_id)
				nodes[i].sort_id++;
			if (nodes[i].sort_id == last_id) {
				/* we ran out of ID space. have to renumber
				   the IDs. */
				ret = 0;
				break;
			}

			prev_id = nodes[i].sort_id;
			str_truncate(prev_str, 0);
			str_append(prev_str, str);
		}
	}
	t_pop();
	return ret;
}

static void
index_sort_renumber_ids(struct mail_search_sort_program *program,
			unsigned int idx)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)program->t;
	struct mail_sort_node *nodes;
	unsigned int i, count;
	uint32_t sort_id = 0, prev_sort_id, skip;

	nodes = array_get_modifiable(&program->all_nodes, &count);
	prev_sort_id = (uint32_t)-1;
	for (; idx < count; idx++) {
		sort_id = nodes[idx].sort_id;
		if (sort_id == nodes[idx+1].sort_id)
			break;
	}
	i_assert(idx != count);

	if (((uint32_t)-1 - sort_id) / (count - idx + 1) < RENUMBER_SPACE) {
		/* space is running out, lets just renumber everything */
		sort_id = 0;
		skip = (uint32_t)-1 / (count + 1);
		for (i = 0; i < idx; i++) {
			if (sort_id != prev_sort_id)
				sort_id += skip;
			prev_sort_id = nodes[i].sort_id;

			i_assert(sort_id != 0);
			nodes[i].sort_id = sort_id;
			mail_index_update_ext(t->trans, nodes[i].seq,
					      program->ext_id,
					      &nodes[i].sort_id, NULL);
		}
	} else {
		skip = RENUMBER_SPACE;
	}

	for (i = idx; i < count && sort_id >= nodes[i].sort_id; i++) {
		if (sort_id != prev_sort_id) {
			i_assert(sort_id <= (uint32_t)-1 - skip);
			sort_id += skip;
		}
		prev_sort_id = nodes[i].sort_id;

		i_assert(sort_id != 0);
		if (nodes[i].sort_id != 0) {
			nodes[i].sort_id = sort_id;
			mail_index_update_ext(t->trans, nodes[i].seq,
					      program->ext_id,
					      &nodes[i].sort_id, NULL);
		}
	}
}

static void
index_sort_add_ids(struct mail_search_sort_program *program, struct mail *mail)
{
	const struct mail_sort_node *nodes;
	unsigned int i, j, count;

	nodes = array_get(&program->all_nodes, &count);
	for (i = 0; i < count; i++) {
		if (nodes[i].sort_id == 0) {
			for (j = i + 1; j < count; j++) {
				if (nodes[j].sort_id != 0)
					break;
			}
			if (index_sort_add_ids_range(program, mail,
						     i == 0 ? 0 : i-1,
						     I_MIN(j, count-1)) == 0)
				index_sort_renumber_ids(program, i-1);
		}
	}
}

static void index_sort_preset_sort_ids(struct mail_search_sort_program *program,
				       uint32_t last_seq)
{
	struct mail_sort_node node;
	struct mail *mail;
	uint32_t (*get_sort_id)(struct mail *);

	switch (program->sort_program[0] & MAIL_SORT_MASK) {
	case MAIL_SORT_ARRIVAL:
		get_sort_id = sort_get_arrival;
		break;
	case MAIL_SORT_DATE:
		get_sort_id = sort_get_date;
		break;
	case MAIL_SORT_SIZE:
		get_sort_id = sort_get_size;
		break;
	default:
		i_unreached();
	}

	/* add the missing nodes with their sort_ids */
	mail = program->temp_mail;
	node.seq = array_count(&program->all_nodes) + 1;
	for (; node.seq <= last_seq; node.seq++) {
		mail_set_seq(mail, node.seq);
		node.sort_id = get_sort_id(mail);
		i_assert(node.sort_id != 0);
		array_append(&program->all_nodes, &node, 1);
	}

	/* @UNSAFE: and sort them */
	memset(&static_node_cmp_context, 0, sizeof(static_node_cmp_context));
	static_node_cmp_context.program = program;
	static_node_cmp_context.mail = mail;

	qsort(array_idx_modifiable(&program->all_nodes, 0), last_seq,
	      sizeof(struct mail_sort_node), sort_node_cmp);
}

static void index_sort_cache_seq(struct sort_cmp_context *ctx,
				 enum mail_sort_type sort_type, uint32_t seq)
{
	ctx->cache_seq = seq;
	ctx->cache_type = sort_type & MAIL_SORT_MASK;

	mail_set_seq(ctx->mail, seq);
	switch (ctx->cache_type) {
	case MAIL_SORT_ARRIVAL:
		ctx->cache_value = sort_get_arrival(ctx->mail);
		break;
	case MAIL_SORT_DATE:
		ctx->cache_value = sort_get_date(ctx->mail);
		break;
	case MAIL_SORT_SIZE:
		ctx->cache_value = sort_get_size(ctx->mail);
		break;
	default:
		ctx->cache_str = sort_header_get(sort_type, ctx->mail, seq);
		break;
	}
}

static void index_sort_headers(struct mail_search_sort_program *program,
			       uint32_t last_seq)
{
	struct mail_sort_node *nodes, node;
	const struct mail_sort_node *cnodes;
	unsigned int count, idx;

	/* we wish to avoid reading the actual headers as much as possible.
	   first sort the nodes which already have sort_ids, then start
	   inserting the new nodes by finding their insertion position with
	   binary search */
	memset(&static_node_cmp_context, 0, sizeof(static_node_cmp_context));
	static_node_cmp_context.program = program;
	static_node_cmp_context.mail = program->temp_mail;

	/* @UNSAFE */
	nodes = array_get_modifiable(&program->all_nodes, &count);
	if (program->last_sorted_seq != count) {
		qsort(nodes, count, sizeof(struct mail_sort_node),
		      sort_node_cmp);
	}

	node.sort_id = 0;
	for (node.seq = count + 1; node.seq <= last_seq; node.seq++) {
		index_sort_cache_seq(&static_node_cmp_context,
				     program->sort_program[0], node.seq);

		cnodes = array_get_modifiable(&program->nodes, &count);
		bsearch_insert_pos(&node, cnodes, count, sizeof(*cnodes),
				   sort_node_cmp_no_sort_id,
				   &idx);
		array_insert(&program->nodes, idx, &node, 1);
	}

	index_sort_add_ids(program, static_node_cmp_context.mail);
}

static void index_sort_build(struct mail_search_sort_program *program,
			     uint32_t last_seq)
{
	struct index_mailbox *ibox = (struct index_mailbox *)program->t->box;
	struct mail_sort_node node;
	const void *data;
	unsigned int i, first_missing_sort_id_seq;

	i = array_count(&program->all_nodes);
	if (i == 0) {
		/* we're building the array from scratch. add here only the
		   messages that have sort_ids set. */
		program->last_sorted_seq = 0;
		for (; i < last_seq; i++) {
			node.seq = i+1;

			mail_index_lookup_ext(ibox->view, i+1, program->ext_id,
					      &data, NULL);

			node.sort_id = data == NULL ? 0 :
				*(const uint32_t *)data;
			if (node.sort_id == 0) {
				/* the rest don't have sort_ids either */
				break;
			}
			array_append(&program->all_nodes, &node, 1);
		}
	}
	first_missing_sort_id_seq = i + 1;

	switch (program->sort_program[0] & MAIL_SORT_MASK) {
	case MAIL_SORT_ARRIVAL:
	case MAIL_SORT_DATE:
	case MAIL_SORT_SIZE:
		index_sort_preset_sort_ids(program, last_seq);
		break;
	default:
		index_sort_headers(program, last_seq);
		break;
	}
	index_sort_save_ids(program, first_missing_sort_id_seq);
}

static void index_sort_add_node(struct mail_search_sort_program *program,
				const struct mail_sort_node *node)
{
	const struct mail_sort_node *nodes;
	unsigned int count, idx;

	memset(&static_node_cmp_context, 0, sizeof(static_node_cmp_context));
	static_node_cmp_context.program = program;
	static_node_cmp_context.mail = program->temp_mail;

	nodes = array_get(&program->nodes, &count);
	bsearch_insert_pos(node, nodes, count,
			   sizeof(*node), sort_node_cmp,
			   &idx);
	array_insert(&program->nodes, idx, node, 1);

	program->last_sorted_seq = node->seq;
	program->prev_seq = node->seq;
}

void index_sort_list_add(struct mail_search_sort_program *program,
			 struct mail *mail)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)program->t;
	const struct mail_index_header *hdr;
	const void *data;
	struct mail_sort_node node;
	uint32_t last_seq;

	i_assert(mail->transaction == program->t);

	if (program->prev_seq + 1 != mail->seq)
		program->skipped_mails = TRUE;

	node.seq = mail->seq;
	if (program->last_sorted_seq == program->prev_seq) {
		/* we're still on the fast path using sort_ids from the
		   index file */
		mail_index_lookup_ext(t->trans_view, mail->seq,
				      program->ext_id, &data, NULL);
		node.sort_id = data == NULL ? 0 : *(const uint32_t *)data;
		if (node.sort_id != 0) {
			index_sort_add_node(program, &node);
			return;
		}
		i_assert(!program->sort_ids_added);
	} else {
		node.sort_id = 0;
	}

	/* sort_ids are missing, have to generate them */
	if (!program->skipped_mails) {
		/* as long as we think we're returning all the mails sorted,
		   which is the common case, we want to avoid duplicating the
		   node array. so here we just keep counting the sequences
		   until either we skip a sequence or we reach list_finish() */
		program->prev_seq = mail->seq;
		return;
	}

	/* we're not returning all the mails. have to create a temporary array
	   for all the nodes so we can set all the missing sort_ids. */
	hdr = mail_index_get_header(t->ibox->view);
	i_array_init(&program->all_nodes, hdr->messages_count);
	index_sort_build(program, hdr->messages_count);
	array_free(&program->all_nodes);

	/* add the nodes in the middle */
	node.seq = program->last_sorted_seq + 1;
	last_seq = program->prev_seq;
	for (; node.seq <= last_seq; node.seq++) {
		mail_index_lookup_ext(t->trans_view, mail->seq, program->ext_id,
				      &data, NULL);

		node.sort_id = *(const uint32_t *)data;
		i_assert(node.sort_id != 0);

		index_sort_add_node(program, &node);
	}

	/* and add this last node */
	program->sort_ids_added = TRUE;
	index_sort_list_add(program, mail);
}

void index_sort_list_finish(struct mail_search_sort_program *program)
{
	if (program->last_sorted_seq != program->prev_seq) {
		/* nodes array contains a contiguous range of sequences from
		   the beginning, with the last ones missing sort_id. we can
		   just sort the array directly without copying it. */
		i_assert(!program->sort_ids_added);

		program->all_nodes = program->nodes;
		index_sort_build(program, program->prev_seq);
	}

	program->nodes_ptr =
		array_get(&program->nodes, &program->nodes_count);

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
