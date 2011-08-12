/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash.h"
#include "mail-storage.h"
#include "mailbox-list-private.h"
#include "mailbox-guid-cache.h"

struct mailbox_guid_cache_rec {
	uint8_t guid[MAIL_GUID_128_SIZE];
	const char *vname;
};

static unsigned int guid_cache_rec_hash(const void *_rec)
{
	const struct mailbox_guid_cache_rec *rec = _rec;

	return mem_hash(rec->guid, sizeof(rec->guid));
}

static int guid_cache_rec_cmp(const void *_r1, const void *_r2)
{
	const struct mailbox_guid_cache_rec *r1 = _r1, *r2 = _r2;

	return memcmp(r1->guid, r2->guid, sizeof(r1->guid));
}

int mailbox_guid_cache_find(struct mailbox_list *list,
			    uint8_t guid[MAIL_GUID_128_SIZE],
			    const char **vname_r)
{
	const struct mailbox_guid_cache_rec *rec;
	struct mailbox_guid_cache_rec lookup_rec;

	memcpy(lookup_rec.guid, guid, sizeof(lookup_rec.guid));
	if (list->guid_cache == NULL) {
		mailbox_guid_cache_refresh(list);
		rec = hash_table_lookup(list->guid_cache, &lookup_rec);
	} else {
		rec = hash_table_lookup(list->guid_cache, &lookup_rec);
		if (rec == NULL) {
			mailbox_guid_cache_refresh(list);
			rec = hash_table_lookup(list->guid_cache, &lookup_rec);
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

	if (list->guid_cache == NULL) {
		list->guid_cache_pool =
			pool_alloconly_create("guid cache", 1024*16);
		list->guid_cache = hash_table_create(default_pool,
						     list->guid_cache_pool, 0,
						     guid_cache_rec_hash,
						     guid_cache_rec_cmp);
	} else {
		hash_table_clear(list->guid_cache, TRUE);
		p_clear(list->guid_cache_pool);
	}
	list->guid_cache_errors = FALSE;

	ctx = mailbox_list_iter_init(list, "*",
				     MAILBOX_LIST_ITER_NO_AUTO_BOXES);
	while ((info = mailbox_list_iter_next(ctx)) != NULL) {
		if ((info->flags &
		     (MAILBOX_NOSELECT | MAILBOX_NONEXISTENT)) != 0)
			continue;

		box = mailbox_alloc(list, info->name, MAILBOX_FLAG_KEEP_RECENT);
		if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID,
					 &metadata) < 0) {
			i_error("Couldn't get mailbox %s GUID: %s",
				info->name, mailbox_get_last_error(box, NULL));
			list->guid_cache_errors = TRUE;
		} else {
			rec = p_new(list->guid_cache_pool,
				    struct mailbox_guid_cache_rec, 1);
			memcpy(rec->guid, metadata.guid, sizeof(rec->guid));
			rec->vname = p_strdup(list->guid_cache_pool, info->name);
			hash_table_insert(list->guid_cache, rec, rec);
		}
		mailbox_free(&box);
	}
	if (mailbox_list_iter_deinit(&ctx) < 0)
		list->guid_cache_errors = TRUE;
}
