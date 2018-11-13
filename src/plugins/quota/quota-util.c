/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "quota-private.h"

bool quota_warning_match(const struct quota_root_settings *w,
			 uint64_t bytes_before, uint64_t bytes_current,
			 uint64_t count_before, uint64_t count_current,
			 const char **reason_r)
{
#define QUOTA_EXCEEDED(before, current, limit) \
	((before) < (uint64_t)(limit) && (current) >= (uint64_t)(limit))
	uint64_t bytes_limit = (uint64_t)w->quota_storage_size *
		(uint64_t)w->quota_storage_percentage / 100ULL;
	uint64_t count_limit = (uint64_t)w->quota_message_count *
		(uint64_t)w->quota_message_percentage / 100ULL;
	if (strcmp(w->quota_warning_threshold, QUOTA_WARNING_THRESHOLD_OVER) == 0) {
		/* over quota (default) */
		if (strcmp(w->quota_warning_resource, QUOTA_WARNING_RESOURCE_STORAGE) == 0 &&
		    QUOTA_EXCEEDED(bytes_before, bytes_current, bytes_limit)) {
			*reason_r = t_strdup_printf("bytes=%"PRIu64" -> %"PRIu64" over limit %"PRId64,
				bytes_before, bytes_current, bytes_limit);
			return TRUE;
		}
		if (strcmp(w->quota_warning_resource, QUOTA_WARNING_RESOURCE_MESSAGE) == 0 &&
		    QUOTA_EXCEEDED(count_before, count_current, count_limit)) {
			*reason_r = t_strdup_printf("count=%"PRIu64" -> %"PRIu64" over limit %"PRId64,
				count_before, count_current, count_limit);
			return TRUE;
		}
	} else {
		if (strcmp(w->quota_warning_resource, QUOTA_WARNING_RESOURCE_STORAGE) == 0 &&
		    QUOTA_EXCEEDED(bytes_current, bytes_before, bytes_limit)) {
			*reason_r = t_strdup_printf("bytes=%"PRIu64" -> %"PRIu64" below limit %"PRId64,
				bytes_before, bytes_current, bytes_limit);
			return TRUE;
		}
		if (strcmp(w->quota_warning_resource, QUOTA_WARNING_RESOURCE_MESSAGE) == 0 &&
		    QUOTA_EXCEEDED(count_current, count_before, count_limit)) {
			*reason_r = t_strdup_printf("count=%"PRIu64" -> %"PRIu64" below limit %"PRId64,
				count_before, count_current, count_limit);
			return TRUE;
		}
	}
	return FALSE;
}

int quota_get_mail_size(struct quota_transaction_context *ctx,
			struct mail *mail, uoff_t *size_r)
{
	if (ctx->quota->vsizes)
		return mail_get_virtual_size(mail, size_r);
	else
		return mail_get_physical_size(mail, size_r);
}

static inline bool
quota_is_over(uoff_t alloc, int64_t used, uint64_t ceil, uint64_t over)
{
	if (used < 0) {
		const uint64_t deleted = (uint64_t)-used;

		/* we've deleted some messages. */
		if (over > 0) {
			if (over > deleted) {
				/* even after deletions we're over quota */
				return TRUE;
			}
			if (alloc > (deleted - over))
				return TRUE;
		} else {
			if (alloc > deleted && (alloc - deleted) < ceil)
				return TRUE;
		}
	} else if (alloc == 0) {
		/* we need to explicitly test this case, since the generic
		   check would fail if user is already over quota */
		if (over > 0)
			return TRUE;
	} else {
		if (ceil < alloc || (ceil - alloc) < (uint64_t)used) {
			/* limit reached */
			return TRUE;
		}
	}

	return FALSE;
}

bool quota_transaction_is_over(struct quota_transaction_context *ctx,
			       uoff_t size)
{
	if (quota_is_over(1, ctx->count_used, ctx->count_ceil,
			  ctx->count_over))
		return TRUE;
	if (quota_is_over(size, ctx->bytes_used, ctx->bytes_ceil,
			  ctx->bytes_over))
		return TRUE;
	return FALSE;
}
