/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "write-full.h"
#include "mail-cache-private.h"

#include <stddef.h>

static void
mail_cache_set_decision_type(struct mail_cache *cache, uint32_t idx,
			     enum mail_cache_decision_type type)
{
	uint8_t value = type;

	/* update the header without locking, we'll just write one byte and
	   it's very unlikely someone else tries to write different value for
	   it at the same time. even then it's just a wrong decision which
	   will be corrected sometimes later, not too bad.. */
	if (pwrite_full(cache->fd, &value, 1,
			offsetof(struct mail_cache_header,
				 field_usage_decision_type) + idx) < 0) {
		mail_cache_set_syscall_error(cache, "pwrite_full()");
	}
}

void mail_cache_handle_decisions(struct mail_cache_view *view, uint32_t seq,
				 enum mail_cache_field field)
{
	const struct mail_index_header *hdr;
	unsigned int idx;
	uint32_t uid;

	idx = mail_cache_field_index(field);
	if (view->cache->hdr->field_usage_decision_type[idx] !=
	    MAIL_CACHE_DECISION_TEMP) {
		/* a) forced decision
		   b) not cached, mail_cache_mark_missing() will handle this
		   c) permanently cached already, okay. */
		return;
	}

	/* see if we want to change decision from TEMP to YES */
	if (mail_index_lookup_uid(view->view, seq, &uid) < 0 ||
	    mail_index_get_header(view->view, &hdr) < 0)
		return;

	if (uid < view->cache->field_usage_uid_highwater[idx] ||
	    uid < hdr->day_first_uid[7]) {
		/* a) nonordered access within this session. if client doesn't
		      request messages in growing order, we assume it doesn't
		      have a permanent local cache.
		   b) accessing message older than one week. assume it's a
		      client with no local cache. if it was just a new client
		      generating the local cache for the first time, we'll
		      drop back to TEMP within few months. */
		mail_cache_set_decision_type(view->cache, idx,
					     MAIL_CACHE_DECISION_YES);
	} else {
		view->cache->field_usage_uid_highwater[idx] = uid;
	}
}

void mail_cache_mark_missing(struct mail_cache_view *view, uint32_t seq,
			     enum mail_cache_field field)
{
	unsigned int idx;
	uint32_t uid;

	idx = mail_cache_field_index(field);
	if (view->cache->hdr->field_usage_decision_type[idx] !=
	    MAIL_CACHE_DECISION_NO) {
		/* a) forced decision
		   b) we're already caching it, so it just wasn't in cache */
		return;
	}

	/* field used the first time */
	mail_cache_set_decision_type(view->cache, idx,
				     MAIL_CACHE_DECISION_TEMP);

	if (mail_index_lookup_uid(view->view, seq, &uid) == 0)
		view->cache->field_usage_uid_highwater[idx] = uid;
}
