/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "mail-index-private.h"
#include "mail-transaction-log.h"
#include "mail-transaction-util.h"

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
	{ MAIL_TRANSACTION_EXT_RESET, 0, 0 },
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
