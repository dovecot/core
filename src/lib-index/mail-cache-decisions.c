/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

/*
   IMAP clients can work in many different ways. There are basically 2
   types:

   1. Online clients that ask for the same information multiple times (e.g.
      webmails, Pine)

   2. Offline clients that usually download first some of the interesting
      message headers and only after that the message bodies (possibly
      automatically, or possibly only when the user opens the mail). Most
      non-webmail IMAP clients behave like this.

   Cache file is extremely helpful with the type 1 clients. The first time
   that client requests message headers or some other metadata they're
   stored into the cache file. The second time they ask for the same
   information Dovecot can now get it quickly from the cache file instead
   of opening the message and parsing the headers.

   For type 2 clients the cache file is also somewhat helpful if client
   fetches any initial metadata. Some of the information is helpful in any
   case, for example it's required to know the message's virtual size when
   downloading the message with IMAP. Without the virtual size being in cache
   Dovecot first has to read the whole message first to calculate it, which
   increases CPU usage.

   Only the specified fields that client(s) have asked for earlier are
   stored into cache file. This allows Dovecot to be adaptive to different
   clients' needs and still not waste disk space (and cause extra disk
   I/O!) for fields that client never needs.

   Dovecot can cache fields either permanently or temporarily. Temporarily
   cached fields are dropped from the cache file after about a week.
   Dovecot uses two rules to determine when data should be cached
   permanently instead of temporarily:

   1. Client accessed messages in non-sequential order within this session.
      This most likely means it doesn't have a local cache.

   2. Client accessed a message older than one week.

   These rules might not always work optimally, so Dovecot also re-evaluates
   the caching decisions once in a while:

   - When caching decision is YES (permanently cache the field), the field's
     last_used is updated only when the caching decision has been verified to
     be correct.

   - When caching decision is TEMP, the last_used is updated whenever the field
     is accessed.

   - When last_used becomes 30 days old (or unaccessed_field_drop_secs) a
     YES caching decision is changed to TEMP.

   - When last_used becomes 60 days old (or 2*unaccessed_field_drop_secs) a
     TEMP caching decision is changed to NO.
*/

#include "lib.h"
#include "ioloop.h"
#include "mail-cache-private.h"

const char *mail_cache_decision_to_string(enum mail_cache_decision_type dec)
{
	switch (dec & ENUM_NEGATE(MAIL_CACHE_DECISION_FORCED)) {
	case MAIL_CACHE_DECISION_NO:
		return "no";
	case MAIL_CACHE_DECISION_TEMP:
		return "temp";
	case MAIL_CACHE_DECISION_YES:
		return "yes";
	}
	i_unreached();
}

struct event_passthrough *
mail_cache_decision_changed_event(struct mail_cache *cache, struct event *event,
				  unsigned int field)
{
	return event_create_passthrough(event)->
		set_name("mail_cache_decision_changed")->
		add_str("field", cache->fields[field].field.name)->
		add_int("last_used", cache->fields[field].field.last_used);
}

static void
mail_cache_update_last_used(struct mail_cache *cache, unsigned int field)
{
	cache->fields[field].field.last_used = ioloop_time32;
	if (cache->field_file_map[field] != (uint32_t)-1)
		cache->field_header_write_pending = TRUE;
}

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

	/* update last_used about once a day */
	bool last_used_need_update =
		ioloop_time - cache->fields[field].field.last_used > 3600*24;

	if (dec == MAIL_CACHE_DECISION_NO ||
	    (dec & MAIL_CACHE_DECISION_FORCED) != 0) {
		/* a) forced decision
		   b) not cached, mail_cache_decision_add() will handle this */
		if (last_used_need_update)
			mail_cache_update_last_used(cache, field);
		return;
	}
	if (dec == MAIL_CACHE_DECISION_YES) {
		if (!last_used_need_update)
			return;
		/* update last_used only when we can confirm that the YES
		   decision is still correct. */
	} else {
		/* see if we want to change decision from TEMP to YES */
		i_assert(dec == MAIL_CACHE_DECISION_TEMP);
		if (last_used_need_update)
			mail_cache_update_last_used(cache, field);
	}

	mail_index_lookup_uid(view->view, seq, &uid);
	hdr = mail_index_get_header(view->view);

	if (uid >= cache->fields[field].uid_highwater &&
	    uid >= hdr->day_first_uid[7]) {
		cache->fields[field].uid_highwater = uid;
	} else if (dec == MAIL_CACHE_DECISION_YES) {
		/* Confirmed that we still want to preserve YES as cache
		   decision. We can update last_used now. */
		i_assert(last_used_need_update);
		mail_cache_update_last_used(cache, field);
	} else {
		/* a) nonordered access within this session. if client doesn't
		      request messages in growing order, we assume it doesn't
		      have a permanent local cache.
		   b) accessing message older than one week. assume it's a
		      client with no local cache. if it was just a new client
		      generating the local cache for the first time, we'll
		      drop back to TEMP within few months. */
		i_assert(dec == MAIL_CACHE_DECISION_TEMP);
		cache->fields[field].field.decision = MAIL_CACHE_DECISION_YES;
		cache->fields[field].decision_dirty = TRUE;
		cache->field_header_write_pending = TRUE;

		const char *reason = uid < hdr->day_first_uid[7] ?
			"old_mail" : "unordered_access";
		struct event_passthrough *e =
			mail_cache_decision_changed_event(
				view->cache, view->cache->event, field)->
			add_str("reason", reason)->
			add_int("uid", uid)->
			add_str("old_decision", "temp")->
			add_str("new_decision", "yes");
		e_debug(e->event(), "Changing field %s decision temp -> yes (uid=%u)",
			cache->fields[field].field.name, uid);
	}
}

void mail_cache_decision_add(struct mail_cache_view *view, uint32_t seq,
			     unsigned int field)
{
	struct mail_cache *cache = view->cache;
	struct mail_cache_field_private *priv;
	uint32_t uid;

	i_assert(field < cache->fields_count);

	if (view->no_decision_updates)
		return;

	priv = &cache->fields[field];
	if (priv->field.decision != MAIL_CACHE_DECISION_NO &&
	    priv->field.last_used != 0) {
		/* a) forced decision
		   b) we're already caching it, so it just wasn't in cache */
		return;
	}

	/* field used the first time */
	if (priv->field.decision == MAIL_CACHE_DECISION_NO)
		priv->field.decision = MAIL_CACHE_DECISION_TEMP;
	priv->field.last_used = ioloop_time;
	priv->decision_dirty = TRUE;
	cache->field_header_write_pending = TRUE;

	mail_index_lookup_uid(view->view, seq, &uid);
	priv->uid_highwater = uid;

	const char *new_decision =
		mail_cache_decision_to_string(priv->field.decision);
	struct event_passthrough *e =
		mail_cache_decision_changed_event(cache, cache->event, field)->
		add_str("reason", "add")->
		add_int("uid", uid)->
		add_str("old_decision", "no")->
		add_str("new_decision", new_decision);
	e_debug(e->event(), "Adding field %s to cache for the first time (uid=%u)",
		priv->field.name, uid);
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
	return mail_cache_purge(dst, 0, "copy cache decisions");
}
