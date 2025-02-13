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

bool quota_transaction_is_over(struct quota_transaction_context *ctx,
			       uoff_t size)
{
	if (ctx->count_used < 0) {
		/* we've deleted some messages. we should be ok, unless we
		   were already over quota and still are after these
		   deletions. */
		const uint64_t count_deleted = (uint64_t)-ctx->count_used;

		if (ctx->count_over > 0) {
			if (count_deleted - 1 < ctx->count_over)
				return TRUE;
		}
	} else {
		if (ctx->count_ceil < 1 ||
		    ctx->count_ceil - 1 < (uint64_t)ctx->count_used) {
			/* count limit reached */
			return TRUE;
		}
	}

	if (ctx->bytes_used < 0) {
		const uint64_t bytes_deleted = (uint64_t)-ctx->bytes_used;

		/* we've deleted some messages. same logic as above. */
		if (ctx->bytes_over > 0) {
			if (ctx->bytes_over > bytes_deleted) {
				/* even after deletions we're over quota */
				return TRUE;
			}
			if (size > bytes_deleted - ctx->bytes_over)
				return TRUE;
		} else {
			if (size > bytes_deleted &&
			    size - bytes_deleted < ctx->bytes_ceil)
				return TRUE;
		}
	} else if (size == 0) {
		/* we need to explicitly test this case, since the generic
		   check would fail if user is already over quota */
		if (ctx->bytes_over > 0)
			return TRUE;
	} else {
		if (ctx->bytes_ceil < size ||
		    ctx->bytes_ceil - size < (uint64_t)ctx->bytes_used) {
			/* bytes limit reached */
			return TRUE;
		}
	}
	return FALSE;
}
