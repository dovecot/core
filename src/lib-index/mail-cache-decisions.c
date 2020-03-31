/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

/*
   Users can be divided to three groups:

   1. Most users will use only a single IMAP client which caches everything
      locally. For these users it's quite pointless to do any kind of caching
      as it only wastes disk space. That might also mean more disk I/O.

   2. Some users use multiple IMAP clients which cache everything locally.
      These could benefit from caching until all clients have fetched the
      data. After that it's useless.

   3. Some clients don't do permanent local caching at all. For example
      Pine and webmails. These clients would benefit from caching everything.
      Some locally caching clients might also access some data from server
      again, such as when searching messages. They could benefit from caching
      only these fields.

   After thinking about these a while, I figured out that people who care
   about performance most will be using Dovecot optimized LDA anyway
   which updates the indexes/cache immediately. In that case even the first
   user group would benefit from caching the same way as second group. LDA
   reads the mail anyway, so it might as well extract some information
   about it and store them into cache.

   So, group 1. and 2. could be optimally implemented by keeping things
   cached only for a while. I thought a week would be good. When cache file
   is purged, everything older than week will be dropped.

   But how to figure out if user is in group 3? One quite easy rule would
   be to see if client is accessing messages older than a week. But with
   only that rule we might have already dropped useful cached data. It's
   not very nice if we have to read and cache it twice.

   Most locally caching clients always fetch new messages (all but body)
   when they see them. They fetch them in ascending order. Noncaching
   clients might fetch messages in pretty much any order, as they usually
   don't fetch everything they can, only what's visible in screen. Some
   will use server side sorting/threading which also makes messages to be
   fetched in random order. Second rule would then be that if a session
   doesn't fetch messages in ascending order, the fetched field type will
   be permanently cached.

   So, we have three caching decisions:

   1. Don't cache: Clients have never wanted the field
   2. Cache temporarily: Clients want this only once
   3. Cache permanently: Clients want this more than once

   Different mailboxes have different decisions. Different fields have
   different decisions.

   There are some problems, such as if a client accesses message older than
   a week, we can't know if user just started using a new client which is
   just filling its local cache for the first time. Or it might be a
   client user hasn't just used for over a week. In these cases we
   shouldn't have marked the field to be permanently cached. User might
   also switch clients from non-caching to caching.

   So we should re-evaluate our caching decisions from time to time. This
   is done by checking the above rules constantly and marking when was the
   last time the decision was right. If decision hasn't matched for two
   months, it's changed. I picked two months because people go to at least
   one month vacations where they might still be reading mails, but with
   different clients.
*/

#include "lib.h"
#include "ioloop.h"
#include "mail-cache-private.h"

void mail_cache_decision_state_update(struct mail_cache_view *view,
				      uint32_t seq, unsigned int field)
{
	struct mail_cache *cache = view->cache;
	enum mail_cache_decision_type dec;
	const struct mail_index_header *hdr;
	uint32_t uid;

	i_assert(field < cache->fields_count);

	if (view->no_decision_updates)
		return;

	dec = cache->fields[field].field.decision;
	if (dec == (MAIL_CACHE_DECISION_NO | MAIL_CACHE_DECISION_FORCED)) {
		/* don't update last_used */
		return;
	}

	if (ioloop_time - cache->fields[field].field.last_used > 3600*24) {
		/* update last_used about once a day */
		cache->fields[field].field.last_used = (uint32_t)ioloop_time;
		if (cache->field_file_map[field] != (uint32_t)-1)
			cache->field_header_write_pending = TRUE;
	}

	if (dec != MAIL_CACHE_DECISION_TEMP) {
		/* a) forced decision
		   b) not cached, mail_cache_decision_add() will handle this
		   c) permanently cached already, okay. */
		return;
	}

	mail_index_lookup_uid(view->view, seq, &uid);
	hdr = mail_index_get_header(view->view);

	/* see if we want to change decision from TEMP to YES */
	if (uid < cache->fields[field].uid_highwater ||
	    uid < hdr->day_first_uid[7]) {
		/* a) nonordered access within this session. if client doesn't
		      request messages in growing order, we assume it doesn't
		      have a permanent local cache.
		   b) accessing message older than one week. assume it's a
		      client with no local cache. if it was just a new client
		      generating the local cache for the first time, we'll
		      drop back to TEMP within few months. */
		cache->fields[field].field.decision = MAIL_CACHE_DECISION_YES;
		cache->fields[field].decision_dirty = TRUE;
		cache->field_header_write_pending = TRUE;
	} else {
		cache->fields[field].uid_highwater = uid;
	}
}

void mail_cache_decision_add(struct mail_cache_view *view, uint32_t seq,
			     unsigned int field)
{
	struct mail_cache *cache = view->cache;
	uint32_t uid;

	i_assert(field < cache->fields_count);

	if (view->no_decision_updates)
		return;

	if (cache->fields[field].field.decision != MAIL_CACHE_DECISION_NO) {
		/* a) forced decision
		   b) we're already caching it, so it just wasn't in cache */
		return;
	}

	/* field used the first time */
	cache->fields[field].field.decision = MAIL_CACHE_DECISION_TEMP;
	cache->fields[field].field.last_used = ioloop_time;
	cache->fields[field].decision_dirty = TRUE;
	cache->field_header_write_pending = TRUE;

	mail_index_lookup_uid(view->view, seq, &uid);
	cache->fields[field].uid_highwater = uid;
}

int mail_cache_decisions_copy(struct mail_cache *src, struct mail_cache *dst)
{
	if (mail_cache_open_and_verify(src) < 0)
		return -1;
	if (MAIL_CACHE_IS_UNUSABLE(src))
		return 0; /* no caching decisions */

	unsigned int count = 0;
	struct mail_cache_field *fields =
		mail_cache_register_get_list(src, pool_datastack_create(), &count);
	i_assert(fields != NULL || count == 0);
	if (count > 0)
		mail_cache_register_fields(dst, fields, count);

	/* Destination cache isn't expected to exist yet, so use purging
	   to create it. Setting field_header_write_pending also guarantees
	   that the fields are updated even if the cache was already created
	   and no purging was done. */
	dst->field_header_write_pending = TRUE;
	return mail_cache_purge(dst, 0);
}
