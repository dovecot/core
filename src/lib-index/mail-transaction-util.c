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
	{ MAIL_TRANSACTION_HEADER_UPDATE, 0, 1 }, /* variable size, use 1 */
	{ MAIL_TRANSACTION_EXT_INTRO, 0, 1 },
	{ MAIL_TRANSACTION_EXT_RESET, 0,
	  sizeof(struct mail_transaction_ext_reset) },
	{ MAIL_TRANSACTION_EXT_HDR_UPDATE, 0, 1 },
	{ MAIL_TRANSACTION_EXT_REC_UPDATE, 0, 1 },
	{ MAIL_TRANSACTION_KEYWORD_UPDATE,
	  MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD |
	  MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE, 1 },
	{ MAIL_TRANSACTION_KEYWORD_RESET,
	  MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET, 1 },
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
