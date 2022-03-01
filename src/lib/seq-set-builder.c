/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "seq-set-builder.h"

struct seqset_builder {
	string_t *str;
	uint32_t last_seq;
	size_t last_seq_pos;
	size_t prefix_length;
};

struct seqset_builder *seqset_builder_init(string_t *str)
{
	struct seqset_builder *builder;
	builder = i_new(struct seqset_builder, 1);
	builder->str = str;
	builder->last_seq = 0;
	builder->prefix_length = str_len(str);
	builder->last_seq_pos = 0;
	return builder;
}

static void
seqset_builder_append_one(struct seqset_builder *builder, uint32_t seq)
{
	builder->last_seq_pos = str_len(builder->str)+1;
	str_printfa(builder->str, "%u,", seq);
}

static void
seqset_builder_create_or_merge_range(struct seqset_builder *builder,
				     uint32_t seq)
{
	char delimiter = '\0';

	i_assert(builder->last_seq_pos > builder->prefix_length);

	str_truncate(builder->str, builder->last_seq_pos-1);

	/* Get the delimiter from the builder string */
	if (str_len(builder->str) > 0 &&
	    str_len(builder->str) - 1 > builder->prefix_length)
		delimiter = str_data(builder->str)[str_len(builder->str) - 1];

	if (delimiter == ':') {
		seqset_builder_append_one(builder, seq);
	} else if (delimiter == ',' || delimiter == '\0') {
		str_printfa(builder->str, "%u:", builder->last_seq);
		builder->last_seq_pos = str_len(builder->str) + 1;
		str_printfa(builder->str, "%u,", seq);
	} else
		i_unreached();
	return;
}

void seqset_builder_add(struct seqset_builder *builder, uint32_t seq)
{
	if (builder->last_seq == 0) {
		/* No seq was yet appened so just append this one */
		seqset_builder_append_one(builder, seq);
	} else if (builder->last_seq + 1 == seq) {
		/* This seq is following directly on the previous one
		   try to create a range of seqs */
		seqset_builder_create_or_merge_range(builder, seq);
	} else {
		/* Append this seq without creating a range */
		seqset_builder_append_one(builder, seq);
	}
	builder->last_seq = seq;
}

bool seqset_builder_try_add(struct seqset_builder *builder, size_t max_len,
			    uint32_t seq)
{
	/* Length of this sequence to be appended */
	unsigned int seq_len = 0;
	/* Buffer to use when calculating seq length as string */
	char seq_str[MAX_INT_STRLEN];
	/* Current length of the seq string */
	unsigned int builder_str_len = str_len(builder->str);

	if (builder->last_seq + 1 == seq && builder_str_len + 1 <= max_len) {
		/* Following sequence: This seq can't grow the overall length
		   by more than one. */
		seqset_builder_add(builder, seq);
		return TRUE;
	}

	if (builder_str_len + MAX_INT_STRLEN + 1 <= max_len) {
		/* Appending the maximum length of a sequence number and ','
		   still fits into max_len. There is no need to check the
		   actual length. */
		seqset_builder_add(builder, seq);
		return TRUE;
	}

	seq_len = strlen(dec2str_buf(seq_str, seq)) + 1;
	if (seq_len + builder_str_len > max_len)
		return FALSE;

	seqset_builder_add(builder, seq);
	return TRUE;
}

void seqset_builder_deinit(struct seqset_builder **builder)
{
	/* If anything was appened to the string remove the trailing ',' */
	if ((*builder)->last_seq != 0)
		str_truncate((*builder)->str, str_len((*builder)->str) - 1);
	i_free(*builder);
}
