/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "mail-index-private.h"
#include "mail-transaction-log.h"
#include "mail-transaction-util.h"

struct mail_transaction_expunge_traverse_ctx {
	const struct mail_transaction_expunge *expunges;
	size_t expunges_count, cur_idx, old_idx;
	uint32_t cur_seq, expunges_before;
	uint32_t old_seq, old_expunges_before;
};

const struct mail_transaction_type_map mail_transaction_type_map[] = {
	{ MAIL_TRANSACTION_APPEND, MAIL_INDEX_SYNC_TYPE_APPEND,
	  sizeof(struct mail_index_record) },
	{ MAIL_TRANSACTION_EXPUNGE, MAIL_INDEX_SYNC_TYPE_EXPUNGE,
	  sizeof(struct mail_transaction_expunge) },
	{ MAIL_TRANSACTION_FLAG_UPDATE, MAIL_INDEX_SYNC_TYPE_FLAGS,
	  sizeof(struct mail_transaction_flag_update) },
	{ MAIL_TRANSACTION_CACHE_UPDATE, 0,
	  sizeof(struct mail_transaction_cache_update) },
	{ 0, 0, 0 }
};

const struct mail_transaction_type_map *
mail_transaction_type_lookup(enum mail_transaction_type type)
{
	int i;

	for (i = 0; mail_transaction_type_map[i].type != 0; i++) {
		if ((mail_transaction_type_map[i].type & type) != 0)
			return &mail_transaction_type_map[i];
	}
	return NULL;
}

enum mail_transaction_type
mail_transaction_type_mask_get(enum mail_index_sync_type sync_type)
{
        enum mail_transaction_type type = 0;
	int i;

	for (i = 0; mail_transaction_type_map[i].type != 0; i++) {
		if ((mail_transaction_type_map[i].sync_type & sync_type) != 0)
			type |= mail_transaction_type_map[i].type;
	}
	return type;
}

int mail_transaction_map(const struct mail_transaction_header *hdr,
			 const void *data,
			 struct mail_transaction_map_functions *map,
			 void *context)
{
	int ret = 0;

	switch (hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_APPEND: {
		const struct mail_index_record *rec, *end;

		if (map->append == NULL)
			break;

		end = CONST_PTR_OFFSET(data, hdr->size);
		for (rec = data; rec != end; rec++) {
			ret = map->append(rec, context);
			if (ret <= 0)
				break;
		}
		break;
	}
	case MAIL_TRANSACTION_EXPUNGE:
	case MAIL_TRANSACTION_EXPUNGE|MAIL_TRANSACTION_EXPUNGE_PROT: {
		const struct mail_transaction_expunge *rec, *end;

		if (map->expunge == NULL)
			break;

		end = CONST_PTR_OFFSET(data, hdr->size);
		for (rec = data; rec != end; rec++) {
			ret = map->expunge(rec, context);
			if (ret <= 0)
				break;
		}
		break;
	}
	case MAIL_TRANSACTION_FLAG_UPDATE: {
		const struct mail_transaction_flag_update *rec, *end;

		if (map->flag_update == NULL)
			break;

		end = CONST_PTR_OFFSET(data, hdr->size);
		for (rec = data; rec != end; rec++) {
			ret = map->flag_update(rec, context);
			if (ret <= 0)
				break;
		}
		break;
	}
	case MAIL_TRANSACTION_CACHE_UPDATE: {
		const struct mail_transaction_cache_update *rec, *end;

		if (map->cache_update == NULL)
			break;

		end = CONST_PTR_OFFSET(data, hdr->size);
		for (rec = data; rec != end; rec++) {
			ret = map->cache_update(rec, context);
			if (ret <= 0)
				break;
		}
		break;
	}
	default:
		i_unreached();
	}

	return ret;
}

void
mail_transaction_log_sort_expunges(buffer_t *expunges_buf,
				   const struct mail_transaction_expunge *src,
				   size_t src_buf_size)
{
	const struct mail_transaction_expunge *src_end;
	struct mail_transaction_expunge *dest;
	struct mail_transaction_expunge new_exp;
	uint32_t expunges_before, count;
	size_t first, i, dest_count;

	i_assert(src_buf_size % sizeof(*src) == 0);
	src_end = CONST_PTR_OFFSET(src, src_buf_size);

	/* @UNSAFE */
	dest = buffer_get_modifyable_data(expunges_buf, &dest_count);
	dest_count /= sizeof(*dest);

	expunges_before = 0;
	for (i = 0; src != src_end; src++) {
		/* src[] must be sorted. */
		i_assert(src+1 == src_end || src->seq1 < src[1].seq1);

		for (; i < dest_count; i++) {
			if (src->seq1 + expunges_before < dest[i].seq1)
				break;

			i_assert(src->uid2 > dest[i].uid1);
			expunges_before += dest[i].seq2 - dest[i].seq1 + 1;
		}

		new_exp = *src;
		new_exp.seq1 += expunges_before;
		new_exp.seq2 += expunges_before;

		/* if src[] is in format {1,2}{1,2} rather than {1,2}{3,4}:
		   expunges_before += new_exp.seq2 - new_exp.seq1 + 1;*/

		first = i;
		while (i < dest_count && new_exp.seq2 >= dest[i].seq1-1) {
			/* we can/must merge with next record */
			count = dest[i].seq2 - dest[i].seq1 + 1;
			expunges_before += count;

			new_exp.seq2 += count;
			if (new_exp.seq2 == dest[i].seq2)
				new_exp.uid2 = dest[i].uid2;
			i_assert(new_exp.uid2 >= dest[i].uid2);
			i++;
		}

		if (first > 0 && new_exp.seq1 == dest[first-1].seq2+1) {
			/* continue previous record */
			dest[first-1].seq2 = new_exp.seq2;
			dest[first-1].uid2 = new_exp.uid2;
		} else if (i == first) {
			buffer_insert(expunges_buf, i * sizeof(new_exp),
				      &new_exp, sizeof(new_exp));
			i++; first++;

			dest = buffer_get_modifyable_data(expunges_buf, NULL);
			dest_count++;
		} else {
			/* use next record */
			dest[first] = new_exp;
			first++;
		}

		if (i > first) {
			buffer_delete(expunges_buf, first * sizeof(new_exp),
				      (i - first) * sizeof(new_exp));

			dest = buffer_get_modifyable_data(expunges_buf, NULL);
			dest_count -= i - first;
			i = first;
		}
	}
}

struct mail_transaction_expunge_traverse_ctx *
mail_transaction_expunge_traverse_init(const buffer_t *expunges_buf)
{
	struct mail_transaction_expunge_traverse_ctx *ctx;

	ctx = i_new(struct mail_transaction_expunge_traverse_ctx, 1);
	ctx->cur_seq = 1;
	ctx->old_seq = 1;

	if (expunges_buf != NULL) {
		ctx->expunges =
			buffer_get_data(expunges_buf, &ctx->expunges_count);
		ctx->expunges_count /= sizeof(*ctx->expunges);
	}
	return ctx;
}

void mail_transaction_expunge_traverse_deinit(
	struct mail_transaction_expunge_traverse_ctx *ctx)
{
	i_free(ctx);
}

uint32_t mail_transaction_expunge_traverse_to(
	struct mail_transaction_expunge_traverse_ctx *ctx, uint32_t seq)
{
	uint32_t idx, count, last_seq;

	if (seq < ctx->cur_seq) {
		/* allow seeking one back */
		ctx->cur_idx = ctx->old_idx;
		ctx->cur_seq = ctx->old_seq;
		ctx->expunges_before = ctx->old_expunges_before;
	} else {
		ctx->old_idx = ctx->cur_idx;
		ctx->old_seq = ctx->cur_seq;
		ctx->old_expunges_before = ctx->expunges_before;
	}
	i_assert(seq >= ctx->cur_seq);

	idx = ctx->cur_idx;
	last_seq = idx == 0 ? 1 : ctx->expunges[idx-1].seq2 + 1;
	for (; idx < ctx->expunges_count; idx++) {
		count = ctx->expunges[idx].seq1 - last_seq;
		if (ctx->cur_seq + count > seq)
			break;
		ctx->cur_seq += count;

		ctx->expunges_before += ctx->expunges[idx].seq2 -
			ctx->expunges[idx].seq1 + 1;
		last_seq = ctx->expunges[idx].seq2+1;
	}

	ctx->cur_idx = idx;
	return ctx->expunges_before;
}
