/* Copyright (c) 2005-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash.h"
#include "mail-storage.h"
#include "mailbox-list-private.h"
#include "mailbox-guid-cache.h"

struct mailbox_guid_cache_rec {
	guid_128_t guid;
	const char *vname;
};

int mailbox_guid_cache_find(struct mailbox_list *list,
			    const guid_128_t guid, const char **vname_r)
{
	const struct mailbox_guid_cache_rec *rec;
	const uint8_t *guid_p = guid;

	if (!hash_table_is_created(list->guid_cache)) {
		mailbox_guid_cache_refresh(list);
		rec = hash_table_lookup(list->guid_cache, guid_p);
	} else {
		rec = hash_table_lookup(list->guid_cache, guid_p);
		if (rec == NULL) {
			mailbox_guid_cache_refresh(list);
			rec = hash_table_lookup(list->guid_cache, guid_p);
		}
	}
	if (rec == NULL) {
		*vname_r = NULL;
		return list->guid_cache_errors ? -1 : 0;
	}
	*vname_r = rec->vname;
	return 0;
}

void mailbox_guid_cache_refresh(struct mailbox_list *list)
{
	struct mailbox_list_iterate_context *ctx;
	const struct mailbox_info *info;
	struct mailbox *box;
	struct mailbox_metadata metadata;
	struct mailbox_guid_cache_rec *rec;
	uint8_t *guid_p;

	if (!hash_table_is_created(list->guid_cache)) {
		list->guid_cache_pool =
			pool_alloconly_create("guid cache", 1024*16);
		hash_table_create(&list->guid_cache, list->guid_cache_pool, 0,
				  guid_128_hash, guid_128_cmp);
	} else {
		hash_table_clear(list->guid_cache, TRUE);
		p_clear(list->guid_cache_pool);
	}
	list->guid_cache_errors = FALSE;

	ctx = mailbox_list_iter_init(list, "*",
				     MAILBOX_LIST_ITER_SKIP_ALIASES |
				     MAILBOX_LIST_ITER_NO_AUTO_BOXES);
	while ((info = mailbox_list_iter_next(ctx)) != NULL) {
		if ((info->flags &
		     (MAILBOX_NOSELECT | MAILBOX_NONEXISTENT)) != 0)
			continue;

		box = mailbox_alloc(list, info->vname, 0);
		if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID,
					 &metadata) < 0) {
			i_error("Couldn't get mailbox %s GUID: %s",
				info->vname, mailbox_get_last_error(box, NULL));
			list->guid_cache_errors = TRUE;
		} else {
			rec = p_new(list->guid_cache_pool,
				    struct mailbox_guid_cache_rec, 1);
			memcpy(rec->guid, metadata.guid, sizeof(rec->guid));
			rec->vname = p_strdup(list->guid_cache_pool, info->vname);
			guid_p = rec->guid;
			hash_table_insert(list->guid_cache, guid_p, rec);
		}
		mailbox_free(&box);
	}
	if (mailbox_list_iter_deinit(&ctx) < 0)
		list->guid_cache_errors = TRUE;
}
