/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "mail-index-private.h"
#include "mail-transaction-log.h"
#include "mail-transaction-util.h"

struct mail_transaction_expunge_iter_ctx {
	const struct mail_transaction_expunge *expunges;
	size_t expunges_count;
	uint32_t cur_seq, cur_idx, expunges_before;
	uint32_t iter_seq, iter_count, iter_idx;
};

const struct mail_transaction_type_map mail_transaction_type_map[] = {
	{ MAIL_TRANSACTION_APPEND, MAIL_INDEX_SYNC_TYPE_APPEND,
	  1 }, /* index-specific size, use 1 */
	{ MAIL_TRANSACTION_EXPUNGE, MAIL_INDEX_SYNC_TYPE_EXPUNGE,
	  sizeof(struct mail_transaction_expunge) },
	{ MAIL_TRANSACTION_FLAG_UPDATE, MAIL_INDEX_SYNC_TYPE_FLAGS,
	  sizeof(struct mail_transaction_flag_update) },
	{ MAIL_TRANSACTION_CACHE_RESET, 0,
	  sizeof(struct mail_transaction_cache_reset) },
	{ MAIL_TRANSACTION_CACHE_UPDATE, 0,
	  sizeof(struct mail_transaction_cache_update) },
	{ MAIL_TRANSACTION_HEADER_UPDATE, 0, 1 }, /* variable size, use 1 */
	{ MAIL_TRANSACTION_EXT_INTRO, 0, 1 },
	{ MAIL_TRANSACTION_EXT_RESET, 0,
	  sizeof(struct mail_transaction_ext_rec_header) },
	{ MAIL_TRANSACTION_EXT_HDR_UPDATE, 0, 1 },
	{ MAIL_TRANSACTION_EXT_REC_UPDATE, 0, 1 },
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

int mail_transaction_map(struct mail_index_map *map,
			 const struct mail_transaction_header *hdr,
			 const void *data,
			 struct mail_transaction_map_functions *func_map,
			 void *context)
{
	int ret = 0;

	switch (hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_APPEND: {
		const struct mail_index_record *rec, *end;

		if (func_map->append == NULL)
			break;

		end = CONST_PTR_OFFSET(data, hdr->size);
		for (rec = data; rec != end; rec++) {
			ret = func_map->append(rec, context);
			if (ret <= 0)
				break;
		}
		break;
	}
	case MAIL_TRANSACTION_EXPUNGE:
	case MAIL_TRANSACTION_EXPUNGE|MAIL_TRANSACTION_EXPUNGE_PROT: {
		const struct mail_transaction_expunge *rec, *end;

		if (func_map->expunge == NULL)
			break;

		end = CONST_PTR_OFFSET(data, hdr->size);
		for (rec = data; rec != end; rec++) {
			ret = func_map->expunge(rec, context);
			if (ret <= 0)
				break;
		}
		break;
	}
	case MAIL_TRANSACTION_FLAG_UPDATE: {
		const struct mail_transaction_flag_update *rec, *end;

		if (func_map->flag_update == NULL)
			break;

		end = CONST_PTR_OFFSET(data, hdr->size);
		for (rec = data; rec != end; rec++) {
			ret = func_map->flag_update(rec, context);
			if (ret <= 0)
				break;
		}
		break;
	}
	case MAIL_TRANSACTION_CACHE_RESET: {
		const struct mail_transaction_cache_reset *rec = data;

		if (func_map->cache_reset != NULL)
			ret = func_map->cache_reset(rec, context);
		break;
	}
	case MAIL_TRANSACTION_CACHE_UPDATE: {
		const struct mail_transaction_cache_update *rec, *end;

		if (func_map->cache_update == NULL)
			break;

		end = CONST_PTR_OFFSET(data, hdr->size);
		for (rec = data; rec != end; rec++) {
			ret = func_map->cache_update(rec, context);
			if (ret <= 0)
				break;
		}
		break;
	}
	case MAIL_TRANSACTION_HEADER_UPDATE: {
		const struct mail_transaction_header_update *rec;
		unsigned int i;

		if (func_map->header_update == NULL)
			break;

		for (i = 0; i < hdr->size; ) {
			rec = CONST_PTR_OFFSET(data, i);
			ret = func_map->header_update(rec, context);
			if (ret <= 0)
				break;

			i += sizeof(*rec) + rec->size;
		}
		break;
	}
	case MAIL_TRANSACTION_EXT_INTRO: {
		const struct mail_transaction_ext_intro *rec = data;
		unsigned int i;

		if (func_map->ext_intro == NULL)
			break;

		for (i = 0; i < hdr->size; ) {
			if (i + sizeof(*rec) > hdr->size) {
				/* should be just extra padding */
				break;
			}

			rec = CONST_PTR_OFFSET(data, i);
			ret = func_map->ext_intro(rec, context);
			if (ret <= 0)
				break;

			i += sizeof(*rec) + rec->name_size;
		}
		break;
	}
	case MAIL_TRANSACTION_EXT_RESET: {
		const struct mail_transaction_ext_rec_header *rec = data;
		unsigned int i, size;

		if (func_map->ext_reset == NULL)
			break;

		size = hdr->size / sizeof(*rec);
		for (i = 0; i < size; i++) {
			ret = func_map->ext_reset(&rec[i], context);
			if (ret <= 0)
				break;
		}
		break;
	}
	case MAIL_TRANSACTION_EXT_HDR_UPDATE: {
		const struct mail_transaction_ext_hdr_update *rec = data;
		unsigned int i;

		if (func_map->ext_hdr_update == NULL)
			break;

		for (i = 0; i < hdr->size; ) {
			rec = CONST_PTR_OFFSET(data, i);
			ret = func_map->ext_hdr_update(rec, context);
			if (ret <= 0)
				break;

			i += sizeof(*rec) + rec->size;
		}
		break;
	}
	case MAIL_TRANSACTION_EXT_REC_UPDATE: {
		const struct mail_transaction_ext_rec_header *ehdr = data;
		const struct mail_transaction_ext_rec_update *rec, *end;
		const struct mail_index_ext *ext;
		unsigned int record_size;

		if (func_map->ext_rec_update == NULL)
			break;

		rec = CONST_PTR_OFFSET(data, sizeof(*ehdr));

		if (map->extensions == NULL ||
		    ehdr->ext_id >= map->extensions->used / sizeof(*ext)) {
			/* broken. let the ext_rec_update handler do the
			   error handling. */
			ret = func_map->ext_rec_update(ehdr, rec, context);
			if (ret >= 0)
				i_unreached();
			break;
		}

		ext = map->extensions->data;
		ext += ehdr->ext_id;
		record_size = sizeof(*ehdr) + ext->record_size;

		end = CONST_PTR_OFFSET(data, hdr->size);
		while (rec != end) {
			ret = func_map->ext_rec_update(ehdr, rec, context);
			if (ret <= 0)
				break;

			rec = CONST_PTR_OFFSET(rec, record_size);
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
	size_t first, i, dest_count;

	i_assert(src_buf_size % sizeof(*src) == 0);

	/* @UNSAFE */
	dest = buffer_get_modifyable_data(expunges_buf, &dest_count);
	dest_count /= sizeof(*dest);

	if (dest_count == 0) {
		buffer_append(expunges_buf, src, src_buf_size);
		return;
	}

	src_end = CONST_PTR_OFFSET(src, src_buf_size);
	for (i = 0; src != src_end; src++) {
		/* src[] must be sorted. */
		i_assert(src+1 == src_end || src->uid1 < src[1].uid1);

		for (; i < dest_count; i++) {
			if (src->uid1 < dest[i].uid1)
				break;
		}

		new_exp = *src;

		first = i;
		while (i < dest_count && src->uid2 >= dest[i].uid1-1) {
			/* we can/must merge with next record */
			if (new_exp.uid2 < dest[i].uid2)
				new_exp.uid2 = dest[i].uid2;
			i++;
		}

		if (first > 0 && new_exp.uid1 <= dest[first-1].uid2+1) {
			/* continue previous record */
			if (dest[first-1].uid2 < new_exp.uid2)
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
