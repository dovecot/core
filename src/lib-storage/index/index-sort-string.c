/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

/* The idea is that we use 32bit integers for string sort IDs which specifiy
   the sort order for primary sort condition. The whole 32bit integer space is
   used and whenever adding a string, the available space is halved and the new
   ID is added in the middle. For example if we add one mail the first time, it
   gets ID 2^31. If we then add two mails which are sorted before the first
   one, they get IDs 2^31/3 and 2^31/3*2. Once we run out of the available
   space between IDs, more space is made by renumbering some IDs.
*/
#include "lib.h"
#include "array.h"
#include "str.h"
#include "index-storage.h"
#include "index-sort-private.h"

#include <stdlib.h>

struct mail_sort_node {
	uint32_t seq:29;
	uint32_t wanted:1;
	uint32_t no_update:1;
	uint32_t sort_id_changed:1;
	uint32_t sort_id;
};
ARRAY_DEFINE_TYPE(mail_sort_node, struct mail_sort_node);

struct sort_string_context {
	struct mail_search_sort_program *program;
	const char *primary_sort_name;

	ARRAY_TYPE(mail_sort_node) zero_nodes, nonzero_nodes, sorted_nodes;
	const char **sort_strings;
	pool_t sort_string_pool;
	unsigned int first_missing_sort_id_idx;

	uint32_t ext_id, last_seq, highest_reset_id, prev_seq;
	uint32_t lowest_nonexpunged_zero;

	unsigned int regetting:1;
	unsigned int have_all_wanted:1;
	unsigned int no_writing:1;
	unsigned int reverse:1;
	unsigned int seqs_nonsorted:1;
	unsigned int broken:1;
};

static char expunged_msg;
static struct sort_string_context *static_zero_cmp_context;

static void index_sort_list_reset_broken(struct sort_string_context *ctx);
static void index_sort_node_add(struct sort_string_context *ctx,
				struct mail_sort_node *node);

void index_sort_list_init_string(struct mail_search_sort_program *program)
{
	struct sort_string_context *ctx;
	const char *name;

	switch (program->sort_program[0] & MAIL_SORT_MASK) {
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
	case MAIL_SORT_DISPLAYFROM:
		name = "sort-df";
		break;
	case MAIL_SORT_DISPLAYTO:
		name = "sort-dt";
		break;
	default:
		i_unreached();
	}

	program->context = ctx = i_new(struct sort_string_context, 1);
	ctx->reverse = (program->sort_program[0] & MAIL_SORT_FLAG_REVERSE) != 0;
	ctx->program = program;
	ctx->primary_sort_name = name;
	ctx->ext_id = mail_index_ext_register(program->t->box->index, name, 0,
					      sizeof(uint32_t),
					      sizeof(uint32_t));
	i_array_init(&ctx->zero_nodes, 128);
	i_array_init(&ctx->nonzero_nodes, 128);
}

static int sort_node_seq_cmp(const void *p1, const void *p2)
{
	const struct mail_sort_node *n1 = p1, *n2 = p2;

	if (n1->seq < n2->seq)
		return -1;
	if (n1->seq > n2->seq)
		return 1;
	return 0;
}

static void index_sort_generate_seqs(struct sort_string_context *ctx)
{
	struct mail_sort_node *nodes, *nodes2;
	unsigned int i, j, count, count2;
	uint32_t seq;

	nodes = array_get_modifiable(&ctx->nonzero_nodes, &count);
	nodes2 = array_get_modifiable(&ctx->zero_nodes, &count2);

	if (!array_is_created(&ctx->program->seqs))
		i_array_init(&ctx->program->seqs, count + count2);
	else
		array_clear(&ctx->program->seqs);

	for (i = j = 0;;) {
		if (i < count && j < count2) {
			if (nodes[i].seq < nodes2[j].seq)
				seq = nodes[i++].seq;
			else
				seq = nodes2[j++].seq;
		} else if (i < count) {
			seq = nodes[i++].seq;
		} else if (j < count2) {
			seq = nodes2[j++].seq;
		} else {
			break;
		}
		array_append(&ctx->program->seqs, &seq, 1);
	}
}

static void index_sort_reget_sort_ids(struct sort_string_context *ctx)
{
	struct mail_sort_node node;
	const uint32_t *seqs;
	unsigned int i, count;

	i_assert(!ctx->regetting);
	ctx->regetting = TRUE;

	index_sort_generate_seqs(ctx);
	array_clear(&ctx->zero_nodes);
	array_clear(&ctx->nonzero_nodes);

	memset(&node, 0, sizeof(node));
	node.wanted = TRUE;
	seqs = array_get(&ctx->program->seqs, &count);
	for (i = 0; i < count; i++) {
		node.seq = seqs[i];
		index_sort_node_add(ctx, &node);
	}
	ctx->regetting = FALSE;
}

static void index_sort_node_add(struct sort_string_context *ctx,
				struct mail_sort_node *node)
{
	struct mail_index_map *map;
	const void *data;
	uint32_t reset_id;
	bool expunged;

	mail_index_lookup_ext_full(ctx->program->t->view, node->seq,
				   ctx->ext_id, &map, &data, &expunged);
	if (expunged) {
		/* we don't want to update expunged messages' sort IDs */
		node->no_update = TRUE;
		/* we can't trust expunged messages' sort IDs. they might be
		   valid, but it's also possible that sort IDs were updated
		   and the expunged messages' sort IDs became invalid. we could
		   use sort ID if we could know the extension's reset_id at the
		   time of the expunge so we could compare it to
		   highest_reset_id, but this isn't currently possible. */
		node->sort_id = 0;
	} else {
		node->sort_id = ctx->broken || data == NULL ? 0 :
			*(const uint32_t *)data;
		if (node->sort_id == 0) {
			if (ctx->lowest_nonexpunged_zero > node->seq ||
			    ctx->lowest_nonexpunged_zero == 0)
				ctx->lowest_nonexpunged_zero = node->seq;
		} else if (ctx->lowest_nonexpunged_zero != 0 &&
			   ctx->lowest_nonexpunged_zero <= node->seq) {
			index_sort_list_reset_broken(ctx);
			ctx->broken = TRUE;
			node->sort_id = 0;
		}
	}

	if (node->sort_id != 0) {
		/* if reset ID increases, lookup all existing messages' sort
		   IDs again. if it decreases, ignore the sort ID. */
		if (!mail_index_ext_get_reset_id(ctx->program->t->view, map,
						 ctx->ext_id, &reset_id))
			reset_id = 0;
		if (reset_id != ctx->highest_reset_id) {
			if (reset_id < ctx->highest_reset_id) {
				i_assert(expunged);
				node->sort_id = 0;
			} else if (ctx->have_all_wanted) {
				/* a bit late to start changing the reset_id.
				   the node lists aren't ordered by sequence
				   anymore. */
				node->sort_id = 0;
				ctx->no_writing = TRUE;
			} else {
				ctx->highest_reset_id = reset_id;
				index_sort_reget_sort_ids(ctx);
			}
		}
	}

	if (node->sort_id == 0)
		array_append(&ctx->zero_nodes, node, 1);
	else
		array_append(&ctx->nonzero_nodes, node, 1);
	if (ctx->last_seq < node->seq)
		ctx->last_seq = node->seq;
}

void index_sort_list_add_string(struct mail_search_sort_program *program,
				struct mail *mail)
{
	struct sort_string_context *ctx = program->context;
	struct mail_sort_node node;

	memset(&node, 0, sizeof(node));
	node.seq = mail->seq;
	node.wanted = TRUE;

	if (mail->seq < ctx->prev_seq)
		ctx->seqs_nonsorted = TRUE;
	ctx->prev_seq = mail->seq;

	index_sort_node_add(ctx, &node);
}

static int sort_node_zero_string_cmp(const struct mail_sort_node *n1,
				     const struct mail_sort_node *n2)
{
	struct sort_string_context *ctx = static_zero_cmp_context;
	int ret;

	ret = strcmp(ctx->sort_strings[n1->seq], ctx->sort_strings[n2->seq]);
	if (ret != 0)
		return !ctx->reverse ? ret : -ret;

	return index_sort_node_cmp_type(ctx->program->temp_mail,
					ctx->program->sort_program + 1,
					n1->seq, n2->seq);
}

static void index_sort_zeroes(struct sort_string_context *ctx)
{
	struct mail *mail = ctx->program->temp_mail;
	enum mail_sort_type sort_type = ctx->program->sort_program[0];
	string_t *str;
	pool_t pool;
	struct mail_sort_node *nodes;
	unsigned int i, count;

	/* first get all the messages' sort strings. although this takes more
	   memory, it makes error handling easier and probably also helps
	   CPU caching. */
	ctx->sort_strings = i_new(const char *, ctx->last_seq + 1);
	ctx->sort_string_pool = pool =
		pool_alloconly_create("sort strings", 1024*64);
	str = str_new(default_pool, 512);
	nodes = array_get_modifiable(&ctx->zero_nodes, &count);
	for (i = 0; i < count; i++) {
		i_assert(nodes[i].seq <= ctx->last_seq);

		T_BEGIN {
			index_sort_header_get(mail, nodes[i].seq,
					      sort_type, str);
			ctx->sort_strings[nodes[i].seq] =
				str_len(str) == 0 ? "" :
				p_strdup(pool, str_c(str));
		} T_END;
	}
	str_free(&str);

	/* we have all strings, sort nodes based on them */
	static_zero_cmp_context = ctx;
	array_sort(&ctx->zero_nodes, sort_node_zero_string_cmp);
}

static const char *
index_sort_get_expunged_string(struct sort_string_context *ctx, uint32_t idx,
			       string_t *str)
{
	struct mail *mail = ctx->program->temp_mail;
	enum mail_sort_type sort_type = ctx->program->sort_program[0];
	const struct mail_sort_node *nodes;
	const char *result = NULL;
	unsigned int i, count;
	uint32_t sort_id;

	/* Look forwards and backwards to see if there are
	   identical sort_ids. If we do find them, try to get
	   their sort string and use it to update the rest. */
	nodes = array_get(&ctx->nonzero_nodes, &count);
	sort_id = nodes[idx].sort_id;
	/* If previous sort ID is identical and its sort string is set, we can
	   trust it. If it's expunged, we already verified that there are no
	   non-expunged messages. */
	if (idx > 0 && nodes[idx-1].sort_id == sort_id &&
	    ctx->sort_strings[nodes[idx].seq] != NULL)
		return ctx->sort_strings[nodes[idx].seq];

	/* Go forwards as long as there are identical sort IDs. If we find one
	   that's not expunged, update string table for all messages with
	   identical sort IDs. */
	for (i = idx + 1; i < count; i++) {
		if (nodes[i].sort_id != sort_id)
			break;

		if (ctx->sort_strings[nodes[i].seq] != NULL) {
			/* usually we fill all identical sort_ids and this
			   shouldn't happen, but we can get here if we skipped
			   over messages when binary searching */
			result = ctx->sort_strings[nodes[i].seq];
			break;
		}
		if (index_sort_header_get(mail, nodes[i].seq,
					  sort_type, str) >= 0) {
			result = str_len(str) == 0 ? "" :
				p_strdup(ctx->sort_string_pool, str_c(str));
			break;
		}
	}
	if (result == NULL) {
		/* unknown */
		return &expunged_msg;
	}

	/* fill all identical sort_ids with the same value */
	for (i = idx; i > 0 && nodes[i-1].sort_id == sort_id; i--) ;
	for (i = idx; i < count && nodes[i].sort_id == sort_id; i++)
		ctx->sort_strings[nodes[i].seq] = result;
	return result;
}

static const char *
index_sort_get_string(struct sort_string_context *ctx,
		      uint32_t idx, uint32_t seq)
{
	struct mail *mail = ctx->program->temp_mail;
	int ret;

	if (ctx->sort_strings[seq] == NULL) T_BEGIN {
		string_t *str;

		str = t_str_new(256);
		ret = index_sort_header_get(mail, seq,
					    ctx->program->sort_program[0], str);
		if (str_len(str) > 0) {
			ctx->sort_strings[seq] =
				p_strdup(ctx->sort_string_pool, str_c(str));
		} else if (ret >= 0) {
			ctx->sort_strings[seq] = "";
		} else {
			ctx->sort_strings[seq] = 
				index_sort_get_expunged_string(ctx, idx, str);
		}
	} T_END;

	return ctx->sort_strings[seq];
}

static void
index_sort_bsearch(struct sort_string_context *ctx, const char *key,
		   unsigned int start_idx, unsigned int *idx_r,
		   const char **prev_str_r)
{
	const struct mail_sort_node *nodes;
	const char *str, *str2;
	unsigned int idx, left_idx, right_idx, prev;
	int ret;

	nodes = array_get_modifiable(&ctx->nonzero_nodes, &right_idx);
	idx = left_idx = start_idx;
	while (left_idx < right_idx) {
		idx = (left_idx + right_idx) / 2;
		str = index_sort_get_string(ctx, idx, nodes[idx].seq);
		if (str != &expunged_msg)
			ret = strcmp(key, str);
		else {
			/* put expunged messages first */
			ret = 1;
			for (prev = idx; prev > 0; ) {
				prev--;
				str2 = index_sort_get_string(ctx, prev,
							     nodes[prev].seq);
				if (str2 != &expunged_msg) {
					ret = strcmp(key, str2);
					if (ret <= 0) {
						idx = prev;
						str = str2;
					}
					break;
				}
			}
		}
		if (ret > 0)
			left_idx = idx+1;
		else if (ret < 0)
			right_idx = idx;
		else {
			*idx_r = idx + 1;
			*prev_str_r = str;
			return;
		}
	}

	if (left_idx > idx)
		idx++;

	*idx_r = idx;
	if (idx > start_idx) {
		prev = idx;
		do {
			prev--;
			str2 = index_sort_get_string(ctx, prev,
						     nodes[prev].seq);
		} while (str2 == &expunged_msg && prev > 0 &&
			 nodes[prev-1].sort_id == nodes[prev].sort_id);
		*prev_str_r = str2;
	}
}

static void index_sort_merge(struct sort_string_context *ctx)
{
	struct mail_sort_node *znodes, *nznodes;
	const char *zstr, *nzstr, *prev_str;
	unsigned int zpos, nzpos, nz_next_pos, zcount, nzcount;
	int ret;

	/* both zero_nodes and nonzero_nodes are sorted. we'll now just have
	   to merge them together. use sorted_nodes as the result array. */
	i_array_init(&ctx->sorted_nodes, array_count(&ctx->nonzero_nodes) +
		     array_count(&ctx->zero_nodes));

	znodes = array_get_modifiable(&ctx->zero_nodes, &zcount);
	nznodes = array_get_modifiable(&ctx->nonzero_nodes, &nzcount);

	prev_str = NULL;
	for (zpos = nzpos = 0; zpos < zcount && nzpos < nzcount; ) {
		zstr = ctx->sort_strings[znodes[zpos].seq];
		nzstr = index_sort_get_string(ctx, nzpos, nznodes[nzpos].seq);

		if (nzstr != &expunged_msg)
			ret = strcmp(zstr, nzstr);
		else if (prev_str != NULL && strcmp(zstr, prev_str) == 0) {
			/* identical to previous message, must keep them
			   together */
			ret = -1;
		} else {
			/* we can't be yet sure about the order, but future
			   nznodes may reveal that the znode must be added
			   later. if future nznodes don't reveal that, we have
			   no idea about these nodes' order. so just always
			   put the expunged message first. */
			ret = 1;
		}

		if (ret <= 0) {
			array_append(&ctx->sorted_nodes, &znodes[zpos], 1);
			prev_str = zstr;
			zpos++;
		} else {
			array_append(&ctx->sorted_nodes, &nznodes[nzpos], 1);
			prev_str = nzstr;
			nzpos++;

			/* avoid looking up all existing messages' strings by
			   binary searching the next zero-node position. don't
			   bother if it looks like more work than linear
			   scanning. */
			if (zcount - zpos < (nzcount - nzpos)/2) {
				index_sort_bsearch(ctx, zstr, nzpos,
						   &nz_next_pos, &prev_str);
				array_append(&ctx->sorted_nodes,
					     &nznodes[nzpos],
					     nz_next_pos - nzpos);
				nzpos = nz_next_pos;
			}
		}
	}
	/* only one of zero_nodes and nonzero_nodes can be non-empty now */
	for (; zpos < zcount; zpos++)
		array_append(&ctx->sorted_nodes, &znodes[zpos], 1);
	for (; nzpos < nzcount; nzpos++)
		array_append(&ctx->sorted_nodes, &nznodes[nzpos], 1);

	/* future index_sort_get_string() calls use ctx->nonzero_nodes, but we
	   use only ctx->sorted_nodes. make them identical. */
	array_free(&ctx->nonzero_nodes);
	ctx->nonzero_nodes = ctx->sorted_nodes;
}

static int
index_sort_add_ids_range(struct sort_string_context *ctx,
			 unsigned int left_idx, unsigned int right_idx)
{

	struct mail_sort_node *nodes;
	unsigned int i, count, rightmost_idx, skip;
	const char *left_str = NULL, *right_str = NULL, *str = NULL;
	uint32_t left_sort_id, right_sort_id, diff;
	bool no_left_str = FALSE, no_right_str = FALSE;
	int ret;

	nodes = array_get_modifiable(&ctx->sorted_nodes, &count);
	rightmost_idx = count - 1;

	/* get the sort IDs from left and right */
	left_sort_id = nodes[left_idx].sort_id;
	right_sort_id = nodes[right_idx].sort_id;
	/* check if all of them should have the same sort IDs. we don't want
	   to hit the renumbering code in that situation. */
	if (left_sort_id == right_sort_id && left_sort_id != 0) {
		/* they should all have the same sort ID */
		for (i = left_idx + 1; i < right_idx; i++) {
			nodes[i].sort_id = left_sort_id;
			nodes[i].sort_id_changed = TRUE;
		}
		return 0;
	}

	if (left_sort_id == 0) {
		i_assert(left_idx == 0);
		left_sort_id = 1;
	}
	if (right_sort_id == 0) {
		i_assert(right_idx == rightmost_idx);
		right_sort_id = (uint32_t)-1;
	}
	i_assert(left_sort_id <= right_sort_id);

	diff = right_sort_id - left_sort_id;
	while (diff / (right_idx-left_idx + 2) == 0) {
		/* we most likely don't have enough space. we have to
		   renumber some of the existing sort IDs. do this by
		   widening the area we're giving sort IDs. */
		while (left_idx > 0) {
			if (nodes[--left_idx].sort_id != left_sort_id) {
				left_sort_id = nodes[left_idx].sort_id;
				if (left_sort_id == 0) {
					i_assert(left_idx == 0);
					left_sort_id = 1;
				}
				break;
			}
		}

		while (right_idx < rightmost_idx) {
			right_idx++;
			if (nodes[right_idx].sort_id > right_sort_id)
				break;
		}
		right_sort_id = nodes[right_idx].sort_id;
		if (right_sort_id == 0) {
			i_assert(right_idx == rightmost_idx);
			right_sort_id = (uint32_t)-1;
		}
		i_assert(left_sort_id <= right_sort_id);

		if (diff == right_sort_id - left_sort_id) {
			/* we did nothing, but there's still not enough space.
			   have to renumber the leftmost/rightmost node(s) */
			i_assert(left_idx == 0 && right_idx == rightmost_idx);
			if (left_sort_id > 1) {
				left_sort_id = 1;
				no_left_str = TRUE;
			} else {
				i_assert(right_sort_id != (uint32_t)-1);
				right_sort_id = (uint32_t)-1;
				no_right_str = TRUE;
			}
		}
		diff = right_sort_id - left_sort_id;
	}

	if (nodes[left_idx].sort_id != 0 && !no_left_str) {
		left_str = index_sort_get_string(ctx, left_idx,
						 nodes[left_idx].seq);
		if (left_str == &expunged_msg) {
			/* not equivalent with any message */
			left_str = NULL;
		}
		left_idx++;
	}
	if (nodes[right_idx].sort_id != 0 && !no_right_str) {
		right_str = index_sort_get_string(ctx, right_idx,
						  nodes[right_idx].seq);
		if (right_str == &expunged_msg) {
			/* not equivalent with any message */
			right_str = NULL;
		}
		right_idx--;
	}
	i_assert(left_idx <= right_idx);

	/* give (new) sort IDs to all nodes in left_idx..right_idx range.
	   divide the available space so that each message gets an equal sized
	   share. some messages' sort strings may be equivalent, so give them
	   the same sort IDs. */
	for (i = left_idx; i <= right_idx; i++) {
		str = index_sort_get_string(ctx, i, nodes[i].seq);
		if (str == &expunged_msg) {
			/* it doesn't really matter what we give to this
			   message, since it's only temporary and we don't
			   know its correct position anyway. so let's assume
			   it's equivalent to previous message. */
			nodes[i].sort_id = left_sort_id;
			continue;
		}

		ret = left_str == NULL ? 1 : strcmp(str, left_str);
		if (ret <= 0) {
			if (ret < 0) {
				/* broken sort_ids */
				return -1;
			}
			nodes[i].sort_id = left_sort_id;
		} else if (right_str != NULL && strcmp(str, right_str) == 0) {
			/* the rest of the sort IDs should be the same */
			nodes[i].sort_id = right_sort_id;
			left_sort_id = right_sort_id;
		} else {
			/* divide the available space equally. leave the same
			   sized space also between the first and the last
			   messages */
			skip = (right_sort_id - left_sort_id) /
				(right_idx - i + 2);
			if (skip == 0) {
				/* broken sort IDs (we previously assigned
				   left_sort_id=right_sort_id) */
				return -1;
			}
			left_sort_id += skip;
			i_assert(left_sort_id < right_sort_id);

			nodes[i].sort_id = left_sort_id;
			left_str = str;
		}
		nodes[i].sort_id_changed = TRUE;
	}
	i_assert(str != NULL);

	return right_str == NULL || strcmp(str, right_str) < 0 ||
		(strcmp(str, right_str) == 0 &&
		 nodes[i-1].sort_id == right_sort_id) ? 0 : -1;
}

static int
index_sort_add_sort_ids(struct sort_string_context *ctx)
{
	const struct mail_sort_node *nodes;
	unsigned int i, left_idx, right_idx, count;

	nodes = array_get(&ctx->sorted_nodes, &count);
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
		if (index_sort_add_ids_range(ctx, left_idx, right_idx) < 0)
			return -1;
	}
	return 0;
}

static void index_sort_write_changed_sort_ids(struct sort_string_context *ctx)
{
	struct mail_index_transaction *itrans = ctx->program->t->itrans;
	uint32_t ext_id = ctx->ext_id;
	const struct mail_sort_node *nodes;
	unsigned int i, count;

	if (ctx->no_writing) {
		/* our reset_id is already stale - don't even bother
		   trying to write */
		return;
	}

	mail_index_ext_reset_inc(itrans, ext_id,
				 ctx->highest_reset_id, FALSE);

	/* add the missing sort IDs to index */
	nodes = array_get_modifiable(&ctx->sorted_nodes, &count);
	for (i = 0; i < count; i++) {
		i_assert(nodes[i].sort_id != 0);
		if (!nodes[i].sort_id_changed || nodes[i].no_update)
			continue;

		mail_index_update_ext(itrans, nodes[i].seq, ext_id,
				      &nodes[i].sort_id, NULL);
	}
}

static int sort_node_cmp(const struct mail_sort_node *n1,
			 const struct mail_sort_node *n2)
{
	struct sort_string_context *ctx = static_zero_cmp_context;

	if (n1->sort_id < n2->sort_id)
		return !ctx->reverse ? -1 : 1;
	if (n1->sort_id > n2->sort_id)
		return !ctx->reverse ? 1 : -1;

	return index_sort_node_cmp_type(ctx->program->temp_mail,
					ctx->program->sort_program + 1,
					n1->seq, n2->seq);
}

static void index_sort_add_missing(struct sort_string_context *ctx)
{
	struct mail_sort_node node;
	const uint32_t *seqs;
	unsigned int i, count;
	uint32_t seq, next_seq;

	ctx->have_all_wanted = TRUE;

	seqs = array_get(&ctx->program->seqs, &count);
	for (i = 0, next_seq = 1; i < count; i++) {
		if (seqs[i] == next_seq)
			next_seq++;
		else {
			i_assert(next_seq < seqs[i]);
			for (seq = next_seq; seq < seqs[i]; seq++) {
				memset(&node, 0, sizeof(node));
				node.seq = seq;
				index_sort_node_add(ctx, &node);
			}
			next_seq = seqs[i] + 1;
		}
	}

	if (ctx->lowest_nonexpunged_zero == 0) {
		/* we're handling only expunged zeros. if it causes us to
		   renumber some existing sort IDs, don't save them. */
		ctx->no_writing = TRUE;
	}
}

static void index_sort_list_reset_broken(struct sort_string_context *ctx)
{
	struct mailbox *box = ctx->program->t->box;
	struct mail_sort_node *node;

	mail_storage_set_critical(box->storage,
				  "%s: Broken %s indexes, resetting",
				  box->name, ctx->primary_sort_name);

	array_clear(&ctx->zero_nodes);
	array_append_array(&ctx->zero_nodes,
			   &ctx->nonzero_nodes);
	array_clear(&ctx->nonzero_nodes);

	array_foreach_modifiable(&ctx->zero_nodes, node)
		node->sort_id = 0;
}

void index_sort_list_finish_string(struct mail_search_sort_program *program)
{
	struct sort_string_context *ctx = program->context;
	const struct mail_sort_node *nodes;
	unsigned int i, count;
	uint32_t seq;

	static_zero_cmp_context = ctx;
	if (array_count(&ctx->zero_nodes) == 0) {
		/* fast path: we have all sort IDs */
		array_sort(&ctx->nonzero_nodes, sort_node_cmp);

		nodes = array_get(&ctx->nonzero_nodes, &count);
		if (!array_is_created(&program->seqs))
			i_array_init(&program->seqs, count);
		else
			array_clear(&program->seqs);

		for (i = 0; i < count; i++) {
			seq = nodes[i].seq;
			array_append(&program->seqs, &seq, 1);
		}
		array_free(&ctx->nonzero_nodes);
	} else {
		if (ctx->seqs_nonsorted) {
			/* the nodes need to be sorted by sequence initially */
			array_sort(&ctx->zero_nodes, sort_node_seq_cmp);
			array_sort(&ctx->nonzero_nodes, sort_node_seq_cmp);
		}

		/* we have to add some sort IDs. we'll do this for all
		   messages, so first remember what messages we wanted
		   to know about. */
		index_sort_generate_seqs(ctx);
		/* add messages not in seqs list */
		index_sort_add_missing(ctx);
		/* sort all messages with sort IDs */
		array_sort(&ctx->nonzero_nodes, sort_node_cmp);
		for (;;) {
			/* sort all messages without sort IDs */
			index_sort_zeroes(ctx);

			if (ctx->reverse) {
				/* sort lists are descending currently, but
				   merging and sort ID assigning works only
				   with ascending lists. reverse the lists
				   temporarily. we can't do this while earlier
				   because secondary sort conditions must not
				   be reversed in results (but while assigning
				   sort IDs it doesn't matter). */
				array_reverse(&ctx->nonzero_nodes);
				array_reverse(&ctx->zero_nodes);
			}

			/* merge zero and non-zero arrays into sorted_nodes */
			index_sort_merge(ctx);
			/* give sort IDs to messages missing them */
			if (index_sort_add_sort_ids(ctx) == 0)
				break;

			/* broken, try again with sort IDs reset */
			index_sort_list_reset_broken(ctx);
		}
		index_sort_write_changed_sort_ids(ctx);

		if (ctx->reverse) {
			/* restore the correct sort order */
			array_reverse(&ctx->sorted_nodes);
		}

		nodes = array_get(&ctx->sorted_nodes, &count);
		array_clear(&program->seqs);
		for (i = 0; i < count; i++) {
			if (nodes[i].wanted) {
				seq = nodes[i].seq;
				array_append(&program->seqs, &seq, 1);
			}
		}
		pool_unref(&ctx->sort_string_pool);
		i_free(ctx->sort_strings);
		array_free(&ctx->sorted_nodes);
		/* NOTE: we already freed nonzero_nodes and made it point to
		   sorted_nodes. */
	}

	array_free(&ctx->zero_nodes);
	i_free(ctx);
	program->context = NULL;
}
